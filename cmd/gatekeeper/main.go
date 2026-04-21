package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	_ "github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -Wno-missing-declarations" -target bpf xdp ./../../bpf/xdp_knock.c -- -I./../../bpf

func main() {
	// Load eBPF objects
	objs := xdpObjects{}
	if err := loadXdpObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// Choose network interface (loopback for testing)
	ifaceName := "lo"
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Interface '%s' not found: %v", ifaceName, err)
	}

	// Attach XDP program
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.xdpPrograms.XdpDrop,
		Interface: iface.Index,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		log.Printf("XDP driver mode failed, falling back to generic mode: %v", err)
		xdpLink, err = link.AttachXDP(link.XDPOptions{
			Program:   objs.xdpPrograms.XdpDrop,
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

	log.Printf("XDP program successfully attached to %s. Press Ctrl+C to exit.", ifaceName)

	// Wait for shutdown signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutdown signal received, detaching XDP program...")
}