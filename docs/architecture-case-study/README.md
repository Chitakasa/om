# 🏛️ Architecture Case Study & Engineering Portfolio

This directory contains the in-depth architectural case study, threat modeling specifications, and career portfolio assets for the **Containers Infrastructure** project.

---

## 📑 Category Index

1. **[Engineering Case Study: Solving the Rootless Container Ingress Flaw](ENGINEERING_CASE_STUDY.md)**  
   *The complete technical paper covering the rootless SNAT vulnerability, kernel socket-level interface isolation, zero-knowledge frontend privacy, dynamic Podman discovery, and live penetration testing.*

2. **[System Architect & Security Lead: Project Role & Portfolio Guide](SYSTEM_ARCHITECT_ROLE.md)**  
   *Detailed documentation of Cyber's role as System Architect & Security Lead, including resume bullet points, interview defense talking points, LinkedIn portfolio descriptions, and Reddit / Hacker News publication blueprints.*

---

## 🔑 Key Architectural Achievements

- **Single-Entry, Fail-Closed Perimeter**: Only Caddy (80/443) is reachable; LAN Host Header Spoofing is blocked by Layer 3/Layer 4 interface port isolation (`192.168.1.5:80 → 8080`, `127.0.0.1:80 → 80`), the private tier answers only an explicit host list (no DNS rebinding), and workspaces reach services only through a token-gated internal router (no container pivoting).
- **Zero-Knowledge Privacy**: Server-side scope filtering ensures LAN visitors receive zero metadata, code, or API evidence of private services.
- **100% Dynamic Discovery**: Real-time Podman UNIX socket inspection (`/var/run/docker.sock`) eliminates hardcoded service lists.
- **Minimal Host Footprint**: Self-contained in `~/.om`; the only host-level piece is an optional, self-contained nftables table (`core/firewall/om.nft`).
