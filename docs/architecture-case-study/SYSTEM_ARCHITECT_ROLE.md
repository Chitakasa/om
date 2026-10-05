# System Architect & Security Lead: Project Role & Portfolio Specification

This document details the **System Architect & Security Lead role** executed by **Cyber** in the design, engineering, and security hardening of the **Containers Stack Infrastructure**.

It provides ready-to-use resume bullet points, interview defense talking points, LinkedIn portfolio summaries, and community publication blueprints.

---

## 1. Executive Role Summary

As **System Architect & Security Lead**, Cyber drove the architectural strategy, threat modeling, security boundary definitions, and quality assurance for an enterprise-grade, rootless container infrastructure on Linux. 

Rather than adopting standard, vulnerable tutorials, Cyber specifically identified critical network-layer attack vectors, rejected brittle Layer 7 mitigations, and enforced kernel socket-level isolation, zero-knowledge privacy, and portable system design.

### Key Architectural Decisions Driven by Cyber:

1. **Threat Model Identification (The Rootless SNAT Flaw)**:
   - *The Insight*: Identified that standard rootless container networks apply SNAT, causing all forwarded traffic to appear from `10.89.0.x`.
   - *The Impact*: Recognized that standard reverse proxies listening on `0.0.0.0:80` are completely vulnerable to Host Header Spoofing from untrusted LAN/Wi-Fi devices.

2. **Rejection of Layer 7 Hacks in Favor of Layer 3/Layer 4 Socket Isolation**:
   - *The Insight*: Rejected relying on HTTP request header filters or basic path regexes, which can be bypassed or misconfigured.
   - *The Solution*: Enforced physical interface binding (`192.168.1.5:80 → 8080`, `127.0.0.1:80 → 80`) so that private routes physically do not exist on the LAN server instance.

3. **Zero-Knowledge Frontend Privacy Enforcement**:
   - *The Insight*: Insisted that unauthenticated LAN visitors must not learn what private services run on the machine by inspecting HTML, DevTools, or JavaScript.
   - *The Solution*: Designed server-side scope filtering where private containers are stripped from memory before generating JSON responses.

4. **100% Dynamic Discovery over Static Hardcoding**:
   - *The Insight*: Pushed back against hardcoding service names, paths, or URLs in HTML and Caddyfiles.
   - *The Solution*: Architected a dual-file route generation system (`conf.d/*.caddy` + `conf.d/*.[public|private]_subpath`) driven by live Podman UNIX socket label discovery.

5. **Architectural Trade-Off: Portability over Host OS Pollution**:
   - *The Insight*: Overruled suggestions to install host-level DNS daemons (`dnsmasq` / `systemd-resolved` host stubs) that would couple the stack to a single Linux distribution.
   - *The Solution*: Preserved 100% self-containment inside the `Containers/` directory, ensuring the entire stack can be transferred to any Linux OS and boot seamlessly with zero host pollution.

---

## 2. Resume & Portfolio Bullet Points

Use these tailored bullet points on your resume, CV, and portfolio:

### For DevOps / SRE Roles:
* **Engineered a zero-trust rootless container infrastructure** on Linux using Podman, Caddy, and Tailscale (WireGuard), isolating untrusted LAN traffic from private management endpoints at the Linux socket layer.
* **Eliminated Host Header Spoofing and lateral network privilege escalation** by architecting interface-level port isolation, ensuring private route handlers are physically absent from LAN-facing proxy instances.
* **Developed an automated reverse-proxy lifecycle controller (`om`)** supporting zero-downtime hot-reloads, automated mDNS broadcasts via Avahi, and live container inspection over Podman UNIX sockets.
* **Enforced strict zero-host-pollution architecture**, eliminating host-level configuration coupling to enable 100% portable drop-in deployment across any Linux distribution.

### For Security Engineer / Cloud Security Roles:
* **Conducted threat modeling on rootless container networking**, identifying that Source Network Address Translation (SNAT) bypasses Layer 7 reverse proxy access controls.
* **Architected a Layer 3/Layer 4 physical socket isolation model** that mathematically prevents unauthenticated LAN attackers from reaching container management interfaces (Portainer, SearXNG).
* **Implemented zero-knowledge frontend data isolation**, applying server-side scope inspection to strip private container metadata from HTTP responses and eliminate information disclosure via DOM/DevTools.
* **Designed and executed automated penetration testing suites** validating perimeter boundaries against forged host headers, direct socket probes, and unauthorized API calls.
* **Ran a second-round audit that found and closed three perimeter bypasses** (published container ports, lateral movement through the reverse proxy, DNS rebinding) with a default-drop host firewall and an edge/router split in which the internal router only accepts requests signed with an edge-held secret — portable across Podman, Docker and every OS.

---

## 3. LinkedIn / Portfolio Project Description

> **Project: Zero-Trust Rootless Container Infrastructure & Dynamic Ingress Controller**  
> **Role**: System Architect & Security Lead  
> **Technologies**: Linux (Arch), Rootless Podman, Caddy, Tailscale (WireGuard), Avahi (mDNS), Python, Shell  
>
> **Overview**:  
> Most self-hosted container setups expose services on a single shared port (`0.0.0.0:80`), leaving private administrative interfaces vulnerable to Host Header Spoofing over home Wi-Fi due to container network SNAT.
> 
> As System Architect, I designed an impenetrable, multi-zone container infrastructure that solves this vulnerability at the Linux kernel socket level. By mapping host interfaces to separate internal proxy servers, private routes physically do not exist on the LAN ingress port. 
> 
> The architecture features zero-knowledge frontend privacy, live container auto-discovery via Podman UNIX sockets, dynamic Avahi mDNS broadcasts, and an automated route lifecycle manager (`om`), while remaining 100% self-contained and portable across any Linux distribution.

---

## 4. Technical Interview Defense Guide

When interviewers ask about this project, use these structured responses:

### Q1: "Tell me about a challenging security or networking problem you solved."
> **Answer**:  
> *"When building my self-hosted container stack with rootless Podman and Caddy, I was threat-modeling the network perimeter and realized that rootless container networking applies SNAT. Every incoming packet from my Wi-Fi was translated to appear from the bridge gateway `10.89.0.x`.
> 
> Because Caddy was listening on `0.0.0.0:80` for all services, an attacker on my Wi-Fi could forge a `Host: portainer.private` header and Caddy couldn't distinguish it from legitimate traffic, bypassing perimeter access controls.
> 
> Instead of trying to write brittle HTTP header regexes, I solved it at Layer 3/Layer 4: I bound my host LAN IP to container port 8080, and my Localhost/Tailscale IPs to port 80. Inside Caddy, port 8080 runs an isolated server where `.private` routes simply do not exist in memory. Any spoofed packet arriving on LAN physically falls into the read-only public portal catchall. It turned a complex L7 filtering problem into a deterministic, kernel-enforced socket guarantee."*

---

### Q2: "Did you use AI to build this?"
> **Answer**:  
> *"Yes, I actively used modern AI pair-programming to write boilerplate code, shell scripts, and configuration syntax. My role was System Architect and Security Lead: I defined the threat models, spotted the SNAT Host Header Spoofing vulnerability, designed the socket isolation strategy, enforced zero-knowledge data privacy, and rejected suggestions that would pollute the host OS or break portability.
> 
> In modern engineering, AI is a powerful accelerator, but it has no security judgment or systems taste. Being able to critically supervise, audit, and steer AI to produce hardened, production-grade architecture is a core competency I bring to any team."*

---

### Q3: "Why not just use Docker with root privileges and firewall rules?"
> **Answer**:  
> *"Rootless Podman provides true defense-in-depth: if an application container is ever compromised via a remote code execution vulnerability, the attacker is trapped as an unprivileged UID on the host with zero root capabilities.
>
> I use both, as separate layers. The proxy-level isolation decides *what* each network tier can reach; a small default-drop nftables table decides *which ports* exist at all, so a container that accidentally publishes a port is still unreachable. A follow-up audit showed why one layer isn't enough: a published port, a container pivoting through the proxy, and DNS rebinding all went around the socket isolation rather than through it. Each layer now fails closed on its own."*

---

## 5. Community Publication Blueprints

### Blueprint A: Reddit (`r/selfhosted`, `r/homelab`, `r/linux`)

**Title**:  
`Why your reverse proxy might be vulnerable to LAN Host Header Spoofing — and how I solved it with interface socket isolation in rootless Podman`

**Post Outline**:
1. **The Hook**: The common assumption that `example.private` on `0.0.0.0:80` is safe from home Wi-Fi devices.
2. **The Flaw**: Explaining how rootless Netavark/SNAT translates packets, making LAN IPs look like bridge gateways.
3. **The Proof**: The `curl -H "Host: containers.portainer.localhost" http://192.168.1.5/` exploit.
4. **The Solution**: Interface port isolation (`192.168.1.5:80 → 8080`, `127.0.0.1:80 → 80`) with dual Caddy servers.
5. **The Extra Mile**: Zero-knowledge frontend privacy (no leaked service names in HTML/JSON) and dynamic Podman UNIX socket discovery.
6. **Open Source Link**: Link to GitHub repository with diagrams.

---

### Blueprint B: Hacker News (`Show HN`)

**Title**:  
`Show HN: A zero-trust rootless Podman architecture with physical interface isolation`

**Text**:  
> Hi HN,  
> Most self-hosted homelabs run a single reverse proxy on `0.0.0.0:80` serving both public services (media, landing page) and private administrative tools (portainer, search). In rootless container setups, SNAT masks the client IP, making L7 perimeter filtering vulnerable to Host Header Spoofing over LAN.  
> 
> I built a self-contained, multi-zone container architecture that solves this at L3/L4 by binding interfaces to distinct internal proxy instances (`8080` for public LAN, `80` for loopback & Tailscale WireGuard). Private routes physically do not exist on the LAN server instance.  
> 
> It also features zero-knowledge frontend data isolation (private container metadata is filtered server-side) and 100% dynamic discovery over Podman UNIX sockets.  
> 
> Architecture doc & case study: [Link to GitHub]  
> Feedback and critiques welcome!
