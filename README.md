# gtkpr – eBPF/XDP Port Knocking Gatekeeper

A high-performance, stealthy network gatekeeper built with **eBPF/XDP** and **Go**.
Hides your sensitive services (e.g., SSH) from port scanners and unauthorized access.
Only clients sending the correct sequence of UDP knocks receive temporary access.

![License](https://img.shields.io/badge/license-GPL--2.0%20OR%20Apache--2.0-blue)
![Status](https://img.shields.io/badge/status-Phase%207%20(TCP%20Proxy)%20Complete-brightgreen)

---

## Project Status

**Current phase:** Phase 7 – Standard TCP Proxy (*complete*), Phase 8 – Stabilisation & Testing (*in progress*).

All core components are implemented and verified in an isolated test environment:
- ✅ XDP packet parsing and filtering
- ✅ Stateful multi-step UDP knock sequence (per-IP, with monotonic clock)
- ✅ Per-IP allowlist with configurable expiry
- ✅ Go control plane: eBPF loader, periodic map cleanup, graceful shutdown
- ✅ YAML-based configuration with SIGHUP hot-reload
- ✅ Real-time debug events via `BPF_MAP_TYPE_PERF_EVENT_ARRAY`
- ✅ Lightweight TCP proxy (userspace, forwarding to real backend)
- ✅ Network namespace test scripts for zero-risk development

---

## How It Works

1. **Selective Protection** – All TCP traffic destined to the protected port (e.g., 22)
   is silently dropped (`XDP_DROP`) at the earliest point of the network stack, unless
   the source IP is authorized. Other ports and protocols pass through unchanged.
2. **Knock Sequence** – The client sends a pre-configured sequence of UDP packets to
   specific ports (e.g., 1111 → 2222 → 3333). A per‑IP state machine in the kernel
   tracks progress using the monotonic clock.
3. **Access Granted** – After the correct sequence, the client's IP is added to an
   allowlist with a configurable expiry (default: 5 minutes).
4. **Transparent Proxy** – Authorized TCP connections are forwarded by a lightweight Go
   proxy to the real backend service (e.g., `127.0.0.1:2222`).

---

## Key Features

- **Port-specific stealth** – only the configured TCP port is hidden; everything else
  operates normally, avoiding unnecessary disruption.
- **Stateful per‑IP knock tracking** – `BPF_MAP_TYPE_LRU_HASH` automatically evicts
  least‑recently‑used entries, providing built‑in DoS resilience.
- **Monotonic clock only** – `bpf_ktime_get_ns()` in the kernel, `CLOCK_MONOTONIC` in
  userspace – immune to NTP time jumps.
- **YAML‑based configuration** – change ports, timeouts, interface and backend without
  recompilation. `SIGHUP` reloads the config on the fly.
- **Real‑time debug events** – the kernel pushes structured events via
  `BPF_MAP_TYPE_PERF_EVENT_ARRAY`; the Go control plane prints human‑readable emoji logs.
- **Periodic map cleanup** – stale knock states and expired allowlist entries are
  removed automatically, keeping memory usage predictable.
- **Graceful shutdown** – on exit, the XDP program is detached and all resources are
  released.
- **Network namespace testing** – helper scripts create an isolated `testns` environment
  with a `veth` pair, allowing risk‑free development and verification.

---

## Technology Stack

| Component    | Technology |
| ------------ | ---------- |
| Kernel-space | C compiled to BPF with clang – `BPF_PROG_TYPE_XDP` |
| Userspace    | Go 1.21+ |
| eBPF library | `github.com/cilium/ebpf` (with `bpf2go`) – no CGO required |
| BPF maps     | `BPF_MAP_TYPE_LRU_HASH`, `BPF_MAP_TYPE_ARRAY`, `BPF_MAP_TYPE_PERF_EVENT_ARRAY` |
| Timing       | `bpf_ktime_get_ns()` (kernel) + `CLOCK_MONOTONIC` (userspace) |
| Build system | `go generate` + `go build` |
| Testing      | Network namespaces, `nc`, `ssh`, `bpftool`, custom shell scripts |

---

## Prerequisites

- **Linux kernel 5.8+** with BPF support
- **clang** and **llvm**
- **libbpf** and **bpftool**
- **linux-headers** matching your kernel
- **Go 1.21+**

On Arch/EndeavourOS:
```bash
sudo pacman -S clang llvm libbpf bpftool linux-headers go make git
```

Generate `vmlinux.h`:
```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
```

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/tanyiG/gtkpr.git
cd gtkpr

# Build the eBPF program and the Go control plane
cd cmd/gatekeeper
go generate
go build -o gatekeeper .

# Edit config.yaml to match your setup (interface, ports, timeouts, backend)

# Run (requires root for XDP attachment)
sudo ./gatekeeper
```

---

## Configuration

Edit `config.yaml` in the project root:

```yaml
interface: "veth0"              # Network interface to attach XDP
protected_port: 22              # TCP port to protect
backend_addr: "127.0.0.1:2222"  # Real service backend
knock_sequence:
  - 1111
  - 2222
  - 3333
knock_timeout_sec: 30           # Max time between knocks
access_duration_sec: 300        # How long access is granted
```

**Hot reload:** Send `SIGHUP` to reload configuration without restarting:
```bash
sudo kill -SIGHUP $(pgrep gatekeeper)
```

---

## Testing with Network Namespaces

The `scripts` directory contains shell scripts for completely isolated, risk‑free
testing using Linux network namespaces and virtual Ethernet (veth) pairs.

| Script | Purpose |
| ------ | ------- |
| `setup_test_env.sh`      | Create namespace `testns` and `veth0`/`veth1` pair |
| `teardown_test_env.sh`   | Remove the test namespace and associated interfaces |
| `test_knocking.sh`       | Send the correct UDP knock sequence (1111 → 2222 → 3333) |
| `test_wrong_knocking.sh` | Send an incorrect sequence to verify rejection |
| `test_connect.sh`        | Attempt TCP connection to the protected port |
| `ssh_from_testns.sh`     | Open an SSH session through the proxy |

**Step-by-step example:**

```bash
# 1. Create the isolated test environment
sudo ./scripts/setup_test_env.sh

# 2. Start the gatekeeper (attaches XDP to veth0)
cd cmd/gatekeeper
sudo ./gatekeeper

# 3. (Another terminal) Verify that the service is INVISIBLE without knocking
sudo ./scripts/test_connect.sh
# Expected: Connection refused or timeout

# 4. Send a WRONG knock sequence – still no access
sudo ./scripts/test_wrong_knocking.sh
sudo ./scripts/test_connect.sh
# Expected: Still no connection

# 5. Send the CORRECT knock sequence
sudo ./scripts/test_knocking.sh

# 6. Now the connection should succeed
sudo ./scripts/test_connect.sh
# Expected: Connection to 10.0.0.1 22 port [tcp/ssh] succeeded!

# 7. (Optional) Open a real SSH session
sudo ./scripts/ssh_from_testns.sh

# 8. Clean up
sudo ./scripts/teardown_test_env.sh
```

> **Note:** The knocking and connect scripts use `ip netns exec testns` and can be
> run with `sudo` if your user lacks the required permissions.

---

## Repository Structure

```
.
├── config.yaml                  # Runtime configuration
├── bpf/
│   ├── xdp_knock.c              # eBPF/XDP program (kernel-space)
│   ├── vmlinux.h                # Kernel type definitions (generated)
│   └── headers/
│       └── common.h
├── cmd/
│   └── gatekeeper/
│       └── main.go              # Go control plane + TCP proxy
├── scripts/
│   ├── setup_test_env.sh        # Create test network namespace + veth pair
│   ├── teardown_test_env.sh     # Remove test environment
│   ├── test_knocking.sh         # Send correct UDP knock sequence
│   ├── test_wrong_knocking.sh   # Send incorrect UDP knock sequence
│   ├── test_connect.sh          # Test TCP connectivity to protected port
│   └── ssh_from_testns.sh       # SSH into the protected service
├── XDP and Go – Implementation Plan.md
└── XDP and Go – Research & Implementation Plan (generated).md
```

---

## Debug Output

The gatekeeper prints real‑time debug events received from the kernel via
`BPF_MAP_TYPE_PERF_EVENT_ARRAY`:

```
✅ STEP OK: IP=10.0.0.2, Step=0, Port=1111
✅ STEP OK: IP=10.0.0.2, Step=1, Port=2222
🎉 SEQUENCE COMPLETE: IP=10.0.0.2 added to allowlist
🚪 TCP ACCESS: IP=10.0.0.2, Allowed
```

To inspect the BPF maps directly, use `bpftool`:
```bash
sudo bpftool map dump name knock_state_map
sudo bpftool map dump name allowed_ips
sudo bpftool map dump name knock_sequence_map
sudo bpftool map dump name config_map
```

---

## License

- **eBPF kernel parts** (`bpf/*.c`): **GPL-2.0 OR Apache-2.0** (dual license)
- **Userspace (Go code)**: **Apache License 2.0**

---

## Acknowledgments

Inspired by:

- [Sándor Laki, PhD](https://lakis.web.elte.hu/)
- [tinyknock](https://github.com/theobori/tinyknock)
- [xSpa](https://github.com/kilkamesh/xSpa)
- [XDP-Firewall](https://github.com/gamemann/XDP-Firewall)
- [go-tcp-proxy](https://github.com/jpillora/go-tcp-proxy)

---

*This is a living document. Contributions and feedback are welcome.*
