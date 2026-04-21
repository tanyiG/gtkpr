# Port Knocking with eBPF/XDP and Go – Implementation Plan

A high-performance, stealthy gatekeeper that hides services until a valid UDP knock sequence is received.

**Project Repository:** [tanyiG/gtkpr · GitHub](https://github.com/tanyiG/gtkpr)  
**License:** 

- eBPF kernel parts (`bpf/*.c`): GPL-2.0 OR Apache-2.0 (dual license) 
- Userspace (Go code): Apache License 2.0

**Last updated:** April 2026

---

## Table of Contents

1. [Project Vision & Core Requirements](#1-project-vision--core-requirements)
2. [High-Level System Architecture](#2-high-level-system-architecture)
3. [Technology Stack](#3-technology-stack)
4. [Detailed Implementation Phases](#4-detailed-implementation-phases)
5. [Key Decisions & Open Questions](#5-key-decisions--open-questions)
6. [References](#6-references)
7. [Future Work & Extensibility](#7-future-work--extensibility)

---

## 1. Project Vision & Core Requirements

Build a **stealth network gatekeeper** that makes protected services (e.g. SSH) completely invisible to port scanners. Only clients that send the correct sequence of UDP packets (“knock”) gain temporary access.

**Core requirements:**

- **Default stealth:** All incoming traffic is dropped (`XDP_DROP`) except for the configured knock sequence and whitelisted IPs.
- **Stateful knock tracking:** Per-source-IP state machine with configurable timeouts.
- **DoS resilience:** Use `BPF_MAP_TYPE_LRU_HASH` for all per-IP maps (automatic eviction of least recently used entries).
- **Precise timing:** Monotonic clock only – `bpf_ktime_get_ns()` in kernel and `CLOCK_MONOTONIC` in userspace.
- **Modular architecture:** eBPF/XDP fast data plane + Go control plane + lightweight TCP proxy.
- **Clean shutdown:** Automatic XDP detachment and resource cleanup on exit.

---

## 2. High-Level System Architecture

                  ┌──────────────────────────────────────┐
                  │         Userspace (Go)               │
                  │  ┌─────────────────────────────────┐ │
                  │  │   TCP Proxy :22 → 127.0.0.1:2222│ │
                  │  └─────────────────────────────────┘ │
                  │    ┌─────────────────────────────┐   │
                  │    │  Control Plane              │   │
                  │    │  - Load eBPF                │   │
                  │    │  - Periodic map cleanup     │   │
                  │    │  - Signal handler           │   │
                  │    └─────────────────────────────┘   │
                  └──────────────────┬───────────────────┘
                                     │ bpf(2) syscalls
                                     ▼
                  ┌─────────────────────────────────────┐
                  │         Kernel                      │
                  │  ┌─────────────────────────────┐    │
                  │  │  eBPF/XDP program           │    │
                  │  │  - Packet parsing           │    │
                  │  │  - Knock state machine      │    │
                  │  │  - Allowed IP check         │    │
                  │  │  - Rate limiting            │    │
                  │  │  - Return XDP_PASS / DROP   │    │
                  │  └─────────────────────────────┘    │
                  │  ┌───────────┐     ┌───────────┐    │
                  │  │LRU_HASH   │     │LRU_HASH   │    │
                  │  │knock_state│     │allowed_ips│    │
                  │  └───────────┘     └───────────┘    │
                  └─────────────────┬───────────────────┘
                                    │
                                    ▼
                  ┌─────────────────────────────────────┐
                  │         Physical Network            │
                  └─────────────────────────────────────┘

---

## 3. Technology Stack

| Component    | Technology                                                    |
| ------------ | ------------------------------------------------------------- |
| Kernel-space | C (compiled to BPF with clang) – `BPF_PROG_TYPE_XDP`          |
| Userspace    | Go 1.26+                                                      |
| eBPF library | `github.com/cilium/ebpf` (with `bpf2go`) – no CGO required    |
| BPF maps     | `BPF_MAP_TYPE_LRU_HASH` for automatic eviction                |
| Timing       | `bpf_ktime_get_ns()` (kernel) + `CLOCK_MONOTONIC` (userspace) |
| Build system | `go generate` + Makefile                                      |
| Testing      | Network namespaces, `nmap`, custom knock client               |

---

## 4. Detailed Implementation Phases

### Phase 1: Environment Setup

- Create reproducible build environment (`clang`, `llvm`, `bpftool`, Go).
- Define clean project layout.

### Phase 2: “Hello XDP” – Default Drop

- Minimal XDP program that drops everything.
- Go loader with driver-mode attachment + generic fallback.
- Verify with ping (100 % packet loss).

### Phase 3: Packet Parsing

- Safe parsing of Ethernet → IPv4 → UDP headers with proper bounds checking.
- Early drop for non-relevant protocols/ports.

### Phase 4: Stateful Knock Sequence (Kernel)

- Implement per-IP state machine using `knock_state_map` (LRU_HASH).
- Configurable knock sequence stored in `knock_sequence_map` (ARRAY).
- Timeout handling and automatic reset on wrong port.

### Phase 5: Access Granting & Go Control Plane

- `allowed_ips` map for granted IPs with expiry timestamps.
- XDP logic for protected TCP port: pass only valid, non-expired IPs.
- Go control plane: load eBPF, attach XDP, periodic map cleanup goroutine, graceful signal handling.

### Phase 6: Configuration Management

- YAML-based configuration (interface, protected port, knock sequence, timeouts, rate limits).
- Load configuration into BPF maps at startup.
- Optional SIGHUP hot-reload support.

### Phase 7: Standard TCP Proxy (Userspace)

- Simple Go TCP proxy forwarding traffic from public port to backend service.
- Chosen over AF_XDP for simplicity and sufficient performance for typical use cases (SSH, etc.).

### Phase 8: Stabilisation & Testing

- Integration tests in network namespaces.
- DoS simulation (LRU + rate limiting validation).
- Performance comparison (with/without XDP).

---

## 5. Key Decisions & Open Questions

- Use of monotonic clock everywhere to avoid time jumps.
- `BPF_MAP_TYPE_LRU_HASH` for built-in DoS protection.
- Standard TCP proxy instead of AF_XDP (simplicity vs. performance trade-off).
- Scope of rate limiting implementation.

---

## 6. References

### Core Technologies

- [Cilium eBPF Library](https://github.com/cilium/ebpf)
- [XDP Documentation](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_XDP/)
- [bpf_ktime_get_ns()](https://docs.ebpf.io/linux/helper-function/bpf_ktime_get_ns/)
- [BPF_MAP_TYPE_LRU_HASH](https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_LRU_HASH/)

### Similar Projects

- **[tinyknock](https://github.com/theobori/tinyknock)** – XDP-based port knocking implementation compatible with standard knock clients.
- **[xSpa](https://github.com/kilkamesh/xSpa)** – Minimalist Single Packet Authorization (SPA) using eBPF/XDP.
- **[XDP-Firewall](https://github.com/gamemann/XDP-Firewall)** – High-performance stateless firewall built with XDP and eBPF.
- **[go-tcp-proxy](https://github.com/jpillora/go-tcp-proxy)** – Lightweight TCP proxy in Go, used as reference for the userspace forwarding component.

---

## 7. Future Work & Extensibility

- IPv6 support
- Multiple protected ports with different knock sequences
- Encrypted knock payloads
- Dynamic blacklisting
- Prometheus metrics export
- Hot configuration reload

---

*This document is the living implementation plan. The actual source code will be in the repository files (`bpf/xdp_knock.c`, `cmd/gatekeeper/main.go`, etc.).*

**License** 

- eBPF kernel parts (`bpf/*.c`): **GPL-2.0 OR Apache-2.0** (dual license) 
- Userspace (Go code): **Apache License 2.0**
