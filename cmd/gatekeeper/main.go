package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -Wno-missing-declarations" -target bpf xdp ./../../bpf/xdp_knock.c -- -I./../../bpf

// Config represents the YAML configuration structure.
type Config struct {
	Interface         string   `yaml:"interface"`
	ProtectedPort     uint16   `yaml:"protected_port"`
	BackendAddr       string   `yaml:"backend_addr"`
	KnockSequence     []uint16 `yaml:"knock_sequence"`
	KnockTimeoutSec   uint32   `yaml:"knock_timeout_sec"`
	AccessDurationSec uint32   `yaml:"access_duration_sec"`
}

// eBPF config struct (must match the C struct config).
type bpfConfig struct {
	KnockTimeoutNS   uint64
	AccessDurationNS uint64
	ProtectedPort    uint16
	_                [6]byte // padding for alignment
}

type debugEvent struct {
	SrcIP        uint32
	SrcPort      uint16
	EventType    uint8
	Step         uint8
	ExpectedPort uint16
	Timestamp    uint64
}

const (
	configFile      = "../../config.yaml"
	cleanupInterval = 10 * time.Second
)

func getMonotonicNs() uint64 {
	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Nano())
}

func htons(val uint16) uint16 {
	return (val<<8)&0xFF00 | (val>>8)&0x00FF
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func applyConfig(objs *xdpObjects, cfg *Config) error {
	// Convert seconds to nanoseconds for eBPF
	knockTimeoutNS := uint64(cfg.KnockTimeoutSec) * 1_000_000_000
	accessDurationNS := uint64(cfg.AccessDurationSec) * 1_000_000_000
	protectedPortNet := htons(cfg.ProtectedPort)

	bpfCfg := bpfConfig{
		KnockTimeoutNS:   knockTimeoutNS,
		AccessDurationNS: accessDurationNS,
		ProtectedPort:    protectedPortNet,
	}
	key := uint32(0)
	if err := objs.ConfigMap.Put(&key, &bpfCfg); err != nil {
		return fmt.Errorf("failed to update config_map: %w", err)
	}

	// Populate knock sequence
	for i, port := range cfg.KnockSequence {
		k := uint32(i)
		v := port // host byte order, the eBPF program uses bpf_ntohs
		if err := objs.KnockSequenceMap.Put(&k, &v); err != nil {
			return fmt.Errorf("failed to update knock_sequence_map: %w", err)
		}
	}
	return nil
}

func cleanupMaps(knockMap, allowedMap *ebpf.Map, knockTimeoutSec uint32) {
	now := getMonotonicNs()
	knockTimeoutNS := uint64(knockTimeoutSec) * 1_000_000_000

	var srcIP uint32
	var state struct {
		Step       uint32
		LastSeenNs uint64
	}
	iter := knockMap.Iterate()
	for iter.Next(&srcIP, &state) {
		if now-state.LastSeenNs > knockTimeoutNS {
			knockMap.Delete(&srcIP)
		}
	}

	var expiry uint64
	iter2 := allowedMap.Iterate()
	for iter2.Next(&srcIP, &expiry) {
		if now > expiry {
			allowedMap.Delete(&srcIP)
		}
	}
}

func startTCPProxy(listenAddr, targetAddr string) {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("Failed to start TCP proxy on %s: %v", listenAddr, err)
	}
	defer listener.Close()
	log.Printf("TCP proxy listening on %s, forwarding to %s", listenAddr, targetAddr)

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			log.Printf("Proxy accept error: %v", err)
			continue
		}
		go func() {
			defer clientConn.Close()
			backendConn, err := net.Dial("tcp", targetAddr)
			if err != nil {
				log.Printf("Failed to connect to backend %s: %v", targetAddr, err)
				return
			}
			defer backendConn.Close()

			clientAddr := clientConn.RemoteAddr().String()
			log.Printf("Proxying connection from %s to %s", clientAddr, targetAddr)

			go func() {
				_, _ = io.Copy(backendConn, clientConn)
			}()
			_, _ = io.Copy(clientConn, backendConn)
		}()
	}
}

func displayDebugEvent(evt debugEvent) {
	ip := net.IPv4(byte(evt.SrcIP), byte(evt.SrcIP>>8), byte(evt.SrcIP>>16), byte(evt.SrcIP>>24))
	switch evt.EventType {
	case 0:
		fmt.Printf("🔔 NEW KNOCK: IP=%s, Port=%d\n", ip, evt.SrcPort)
	case 1:
		fmt.Printf("❌ WRONG KNOCK: IP=%s, Got=%d, Expected=%d\n", ip, evt.SrcPort, evt.ExpectedPort)
	case 2:
		fmt.Printf("✅ STEP OK: IP=%s, Step=%d, Port=%d\n", ip, evt.Step, evt.SrcPort)
	case 3:
		fmt.Printf("🎉 SEQUENCE COMPLETE: IP=%s added to allowlist\n", ip)
	case 4:
		fmt.Printf("🚪 TCP ACCESS: IP=%s, Allowed\n", ip)
	default:
		fmt.Printf("❓ UNKNOWN EVENT: IP=%s, Type=%d\n", ip, evt.EventType)
	}
}

func main() {
	// Load initial configuration
	cfg, err := loadConfig(configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Load eBPF objects
	objs := xdpObjects{}
	if err := loadXdpObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// Apply configuration to BPF maps
	if err := applyConfig(&objs, cfg); err != nil {
		log.Fatalf("Failed to apply config: %v", err)
	}

	// Attach XDP to interface
	ifaceName := cfg.Interface
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Interface '%s' not found: %v", ifaceName, err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpKnock,
		Interface: iface.Index,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		log.Printf("XDP driver mode failed, falling back to generic mode: %v", err)
		xdpLink, err = link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpKnock,
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			log.Fatalf("Failed to attach XDP: %v", err)
		}
		log.Println("XDP program attached in generic mode.")
	} else {
		log.Println("XDP program attached in driver mode.")
	}
	defer xdpLink.Close()

	// Periodic map cleanup
	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()
		for range ticker.C {
			cleanupMaps(objs.KnockStateMap, objs.AllowedIps, cfg.KnockTimeoutSec)
		}
	}()

	// Start TCP proxy
	proxyListen := fmt.Sprintf(":%d", cfg.ProtectedPort)
	go startTCPProxy(proxyListen, cfg.BackendAddr)

	// Start perf event reader for debug events
	rdr, err := perf.NewReader(objs.DebugEvents, os.Getpagesize())
	if err != nil {
		log.Fatalf("Failed to create perf reader: %v", err)
	}
	defer rdr.Close()

	go func() {
		var evt debugEvent
		for {
			record, err := rdr.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				log.Printf("Error reading perf event: %v", err)
				continue
			}
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
				log.Printf("Error parsing event: %v", err)
				continue
			}
			displayDebugEvent(evt)
		}
	}()

	log.Printf("Gatekeeper running on interface %s. Press Ctrl+C to exit.", ifaceName)

	// Set up signal handling for SIGHUP (config reload)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// Main event loop
	for {
		s := <-sig
		switch s {
		case syscall.SIGINT, syscall.SIGTERM:
			log.Println("Shutdown signal received, cleaning up...")
			return
		case syscall.SIGHUP:
			log.Println("SIGHUP received, reloading configuration...")
			newCfg, err := loadConfig(configFile)
			if err != nil {
				log.Printf("Failed to reload config: %v", err)
				continue
			}
			if err := applyConfig(&objs, newCfg); err != nil {
				log.Printf("Failed to apply new config: %v", err)
				continue
			}
			// Update cleanup timer with new timeout
			cfg = newCfg
			log.Println("Configuration reloaded successfully.")
		}
	}
}
