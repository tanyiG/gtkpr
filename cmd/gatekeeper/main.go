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
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -Wno-missing-declarations" -target bpf xdp ./../../bpf/xdp_knock.c -- -I./../../bpf

const (
	protectedPort   = 22
	backendAddr     = "127.0.0.1:2222"
	cleanupInterval = 10 * time.Second
	knockTimeout    = 30 * time.Second
)

// debugEvent matches the C debug_event struct exactly.
type debugEvent struct {
	SrcIP        uint32
	SrcPort      uint16
	EventType    uint8
	Step         uint8
	ExpectedPort uint16
	Timestamp    uint64
}

func getMonotonicNs() uint64 {
	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Nano())
}

func loadKnockSequence(knockSeqMap *ebpf.Map) error {
	ports := []uint16{1111, 2222, 3333}
	for i, port := range ports {
		key := uint32(i)
		if err := knockSeqMap.Put(&key, &port); err != nil {
			return err
		}
	}
	return nil
}

func cleanupMaps(knockMap, allowedMap *ebpf.Map) {
	now := getMonotonicNs()

	var srcIP uint32
	var state struct {
		Step       uint32
		LastSeenNs uint64
	}
	iter := knockMap.Iterate()
	for iter.Next(&srcIP, &state) {
		if now-state.LastSeenNs > uint64(knockTimeout.Nanoseconds()) {
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

// displayDebugEvent formats and prints the received debug event.
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
	// Load eBPF objects
	objs := xdpObjects{}
	if err := loadXdpObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// Populate knock sequence
	if err := loadKnockSequence(objs.KnockSequenceMap); err != nil {
		log.Fatalf("Failed to populate knock sequence: %v", err)
	}

	// Attach to veth0
	ifaceName := "veth0"
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
			cleanupMaps(objs.KnockStateMap, objs.AllowedIps)
		}
	}()

	// Start TCP proxy
	go startTCPProxy(":22", backendAddr)

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

	// Wait for shutdown signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutdown signal received, cleaning up...")
}
