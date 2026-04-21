# gtkpr – eBPF/XDP Port Knocking Gatekeeper

A high-performance, stealthy network gatekeeper built with **eBPF/XDP** and **Go**.

Hides your services (e.g. SSH) from port scanners and unauthorized access. Only clients sending the correct sequence of UDP knocks receive temporary access.

![License](https://img.shields.io/badge/license-GPL--2.0%20OR%20Apache--2.0-blue)
![Status](https://img.shields.io/badge/status-Planning%20%26%20Design-yellow)

---

## Project Status

**Current phase:** Phase 2: “Hello XDP” – Default Drop finished and verified  
**Code:** 
- `vmlinux.h`: generated
- `xdp_knock.c`: drops every packages
- `main.go`: initial version of Go loader 
- `go.mod`: project requirements included

This repository currently contains the detailed **implementation plan** for the project.

---

## ✨ Project Goals

- Create a true stealth port knocking solution using XDP (eXpress Data Path)
- Default-deny all traffic (`XDP_DROP`)
- Stateful, multi-step UDP knock sequence with per-IP tracking
- Strong DoS resistance using `BPF_MAP_TYPE_LRU_HASH`
- Clean, modular architecture (eBPF data plane + Go control plane)
- Reliable monotonic timing (no time jumps from NTP)
- Simple and maintainable userspace TCP proxy

---

## 📄 Current Content

- **[XDP and Go – Implementation Plan.md](XDP%20and%20Go%20–%20Implementation%20Plan.md)** – Complete technical design, architecture, phases, key decisions and references

---

## Roadmap

- Phase 1: Environment setup & "Hello XDP"
- Phase 2–4: Packet parsing and stateful knock logic
- Phase 5–6: Control plane and configuration
- Phase 7: Userspace TCP proxy
- Phase 8: Testing & stabilization

See the full [Implementation Plan](XDP%20and%20Go%20–%20Implementation%20Plan.md) for detailed steps.

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

---

*This is a living document. Contributions and feedback are welcome.*
