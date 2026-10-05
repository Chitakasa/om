# Engineering Case Study: Solving the Rootless Container Ingress Flaw

**Author & System Architect**: Cyber ([GitHub](https://github.com))  
**Category**: Systems Engineering, Network Security, Container Infrastructure  
**Stack**: Linux (Arch), Rootless Podman, Caddy, Tailscale (WireGuard), Avahi (mDNS), Python  
**Status**: Production / Live  

---

## 1. Executive Summary

Standard self-hosted container environments suffer from a critical, widely overlooked architectural flaw: **when running behind a standard reverse proxy in rootless container networks, private administrative services are inherently vulnerable to Host Header Spoofing over the local area network (LAN).**

Because rootless container packet engines (such as Netavark / rootlessport) apply Source Network Address Translation (SNAT), all incoming packets appear to originate from the internal bridge gateway (`10.89.0.x`). When a reverse proxy listens on a shared port (`0.0.0.0:80`), it cannot cryptographically or physically differentiate between a packet from a home Wi-Fi guest and an administrator on localhost.

This case study documents the design, threat modeling, and implementation of a **multi-zone, defense-in-depth, fail-closed architecture** that:
1. **Eliminates LAN Host Header Spoofing** through kernel socket-level interface port isolation.
2. **Guarantees zero-knowledge frontend privacy**, ensuring unauthenticated LAN visitors receive zero metadata, code, or API trace of private containers.
3. **Achieves 100% dynamic service discovery** via live Podman UNIX socket polling without static configuration files.
4. **Closes the three bypasses socket isolation alone does not cover** — published container ports, lateral movement through the proxy, and DNS rebinding — found in a second-round audit (§7).

```
                           ══════════════════════════════════════════════════════════
                                             EXTERNAL TRAFFIC SOURCES
                           ══════════════════════════════════════════════════════════
                                     │                                  │
                       [ Tailscale Mesh VPN / PC ]             [ Home Wi-Fi / LAN Devices ]
                       - 100.117.253.5 (Tailscale)             - 192.168.1.5 (Host LAN IP)
                       - archlinux (MagicDNS)                  - archlinux.local (mDNS)
                       - 127.0.0.1 / localhost                 - jellyfin.local / media.local
                                     │                                  │
                                     │ (Zone 1 & 2)                     │ (Zone 3)
                                     ▼                                  ▼
                    ┌────────────────────────────────────────────────────────────────────────┐
                    │                      HOST PERIMETER (Linux Kernel)                     │
                    │         Interface-Specific Socket Port Forwarding:                     │
                    │         • 127.0.0.1:80/443         ──► Caddy Container Port 80/443     │
                    │         • 100.117.253.5:80/443     ──► Caddy Container Port 80/443     │
                    │         • 192.168.1.5:80/443       ──► Caddy Container Port 8080/8443  │
                    └────────────────────────────────────────────────────────────────────────┘
                                                         │
                                                         ▼
                    ┌────────────────────────────────────────────────────────────────────────┐
                    │                 CADDY REVERSE PROXY CONTAINER (caddy)                  │
                    │                                                                        │
                    │   [SERVER A: Port 80 & 443]           [SERVER B: Port 8080 & 8443]     │
                    │   • Private Ingress Server            • Public Ingress Server          │
                    │   • <ws>.<svc>.localhost              • Public Dashboard (:8080)       │
                    │   • Import *.private_subpath          • Import *.public_subpath        │
                    │   • Full Administrative Dashboard     • NO private handlers exist!     │
                    └────────────────────────────────────────────────────────────────────────┘
                                                         │
                           ──────────────────────────────┴──────────────────────────────
                             om_core_net             containers_net             perso_net
                           ─────────────────────────────────────────────────────────────
                                 │                 │                 │                 │
                                 ▼                 ▼                 ▼                 ▼
                          ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
                          │ dashboard + │   │   searxng   │   │  jellyfin   │   │     pep     │
                          │  portainer  │   │  Port 8080  │   │  Port 8096  │   │  Port 8080  │
                          └─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘
```

---

## 2. The Threat Model: The Rootless SNAT Flaw

### The Traditional Setup
In a typical homelab:
1. Docker or Podman runs containers on a user bridge network (`10.89.0.0/24`).
2. An NGINX, Traefik, or Caddy reverse proxy binds `0.0.0.0:80` and `0.0.0.0:443`.
3. Virtual hosts are defined:
   - `http://jellyfin.local` ➔ Public media server
   - `http://portainer.private` ➔ Private container management

### The Attack Vector: Host Header Spoofing
Because rootless containers run without root privileges, Podman uses user-space port forwarding (`rootlessport`). Incoming packets from the physical Wi-Fi interface (`192.168.1.5`) are translated:
$$\text{Source IP: } 192.168.1.105 \xrightarrow{\text{SNAT}} 10.89.0.1$$

When the reverse proxy inspects the TCP connection, **all connections appear to come from `10.89.0.1`**.

If an attacker on the home Wi-Fi sends a forged packet:
```bash
curl -H "Host: containers.portainer.localhost" http://192.168.1.5/
```
The reverse proxy sees a request for `portainer.private` coming from internal IP `10.89.0.1`. It matches the virtual host and proxies the untrusted attacker directly to the root container management UI. **Access control is completely broken.**

---

## 3. The Architectural Solution: Kernel-Level Socket Isolation

Rather than relying on brittle Layer 7 HTTP request inspection, this architecture enforces separation at **Layer 3 / Layer 4 socket binding**.

### 1. Dual-Port Container Ingress
Instead of binding `0.0.0.0`, Podman binds individual network interfaces to separate internal container ports:

```yaml
# infrastructure/caddy/docker-compose.yml
ports:
  # PRIVATE INGRESS (Localhost & Tailscale Mesh): Mapped to Container Port 80 & 443
  - "127.0.0.1:80:80"
  - "127.0.0.1:443:443"
  - "${TAILSCALE_IP:-100.117.253.5}:80:80"
  - "${TAILSCALE_IP:-100.117.253.5}:443:443"
  - "${TAILSCALE_IP:-100.117.253.5}:443:443/udp"

  # PUBLIC INGRESS (Home Wi-Fi / LAN): Mapped to Container Port 8080 & 8443
  - "${LAN_IP:-192.168.1.5}:80:8080"
  - "${LAN_IP:-192.168.1.5}:443:8443"
  - "${LAN_IP:-192.168.1.5}:443:8443/udp"
```

### 2. Physical Route Absence in Caddy
Inside Caddy, two isolated HTTP server instances execute:
- **Server Instance A (Container Ports 80 & 443)**: Bound strictly to loopback and Tailscale WireGuard. Contains virtual hosts for `.private` services and subpath handlers for remote management.
- **Server Instance B (Container Ports 8080 & 8443)**: Bound strictly to incoming LAN packets. Contains **ONLY** public services (`jellyfin.local:8080`) and the Public Portal catchall (`:8080`).

### Why Attackers Fail
When an attacker on LAN sends `Host: containers.portainer.localhost` to `192.168.1.5:80`:
1. The host kernel forwards the packet to container port **`8080`**.
2. Caddy evaluates the request against its Port 8080 route table.
3. `containers.portainer.localhost` **does not exist** in Port 8080's memory table.
4. Caddy routes the packet to `:8080` (the Public Portal catchall) with header `X-Access-Scope: public`.
5. Portainer is **unreachable from the LAN tier**: no route to it exists there.

---

## 4. Zero-Knowledge Frontend Privacy

A core security requirement: **Can an attacker discover private service names by inspecting the dashboard web code, HTML, or DevTools on `archlinux.local`?**

The architecture enforces zero-knowledge frontend privacy:

### 1. Server-Side Scope Filtering (`server.py`)
When the dashboard loads, it queries `/api/services`. The Python backend inspects the request:
```python
def _is_public_scope(self):
    scope_hdr = self.headers.get('X-Access-Scope', '').strip().lower()
    if scope_hdr == 'public':
        return True
    host = self.headers.get('Host', '').split(':')[0].strip().lower()
    if host.endswith('.local') or host.endswith('.home'):
        return True
    import ipaddress
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private and not str(ip).startswith('127.') and not str(ip).startswith('100.'):
            return True
    except ValueError:
        pass
    return False
```
When `_is_public_scope()` is True:
```python
services = [s for s in services if s.get('is_public')]
```
All private services (Portainer, SearXNG, Backup Host) are filtered out **in memory before generating the JSON response**.

### 2. Zero Hardcoding in Web Assets (`index.html`)
The HTML contains zero static references to private services. The search bar dynamically looks for `is_search: true` in the returned JSON; if absent, the search engine UI is not initialized. An attacker running `view-source:` or DevTools finds **zero evidence** that SearXNG or Portainer exist on the machine.

---

## 5. 100% Dynamic Discovery & Route Lifecycle

To ensure maintainability as new containers are added, the stack operates without manual configuration edits:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        CONTAINER DISCOVERY PIPELINE                    │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
     1. Live Podman UNIX Socket Inspection (/var/run/docker.sock)
        - Reads container state, labels, and ports live
        - Detects: dashboard.scope, dashboard.domain, dashboard.path
                                    │
                                    ▼
     2. Dual-File Automated Route Generation (om add)
        - conf.d/${NAME}.caddy   ──► Virtual Host (.private or .local:8080)
        - conf.d/${NAME}.subpath ──► Tailscale subpath (/service/*)
                                    │
                                    ▼
     3. Dynamic Avahi mDNS Broadcaster (mdns-publisher.sh)
        - Scans conf.d/*.caddy dynamically for *.local aliases
        - Broadcasts new aliases across Wi-Fi without service restarts
```

---

## 6. Penetration Testing & Verification

The architecture was subjected to rigorous penetration testing on the live network:

```bash
# 1. Verify Host Header Spoofing Resistance on LAN IP:
$ curl -s -I -H "Host: containers.portainer.localhost" http://192.168.1.5/
HTTP/1.1 200 OK
Server: BaseHTTP/0.6 Python/3.14.7
# RESULT: Serves Public Dashboard, Portainer is UNREACHABLE.

# 2. Verify Port 8080 is NOT exposed on LAN IP:
$ curl -m 2 http://192.168.1.5:8080/
curl: (7) Failed to connect to 192.168.1.5 port 8080: Connection refused
# RESULT: Port 8080 exists only inside the container network.

# 3. Verify Zero-Knowledge Code Privacy on LAN:
$ curl -s http://192.168.1.5/ | grep -icE 'searxng|portainer'
0
# RESULT: Zero private artifacts leak over the wire.

# 4. Verify Localhost Administrative Access:
$ curl -s -o /dev/null -w "%{http_code}\n" http://containers.portainer.localhost/
200
# RESULT: Localhost retains full administrative capabilities.
```

---

## 7. Second-Round Audit: What Socket Isolation Did Not Cover

Socket isolation answers one question — *can a LAN packet reach a private route?* — and answers it well. A follow-up audit asked the broader question — *can anyone reach anything private by any path?* — and found three paths, all verified against the live system and all now closed.

### Finding 1 — Published container ports bypass the proxy entirely
`om add` scaffolded services with `ports: - "8080"`. Podman publishes that on **every host interface** (`0.0.0.0:35183`), so the private `pep` service was reachable from the LAN directly, never touching Caddy. With no host firewall, nothing stopped it.

**Fix**: services use `expose:` (container network only); `om start` warns about any published port; and a **default-drop host firewall** (`nftables`, only 80/443 and a few system ports open) makes any future slip unreachable anyway.

### Finding 2 — Lateral movement through the proxy itself
`om_caddy` joins every workspace network so it can reach services. But that means every container can connect to `om_caddy:80` — the *private* tier. From inside the LAN-public Jellyfin container, `http://om_caddy/portainer/` returned **200**: a compromised public service could reach Portainer, which holds the Podman socket.

**First fix (interim)**: a Caddy gate exploiting a rootless-Podman detail — its port forwarder connects from inside Caddy's own network namespace, so legitimate connections satisfy `remote address == local address`. It worked, but only on rootless Podman: under Docker, Docker Desktop or Podman machine, forwarded traffic arrives differently and the gate would have locked everyone out.

**Final fix (1.0)**: split the proxy. The **edge** keeps the host ports and all access logic but joins only the core network, so no workspace container can reach it. An internal **router** joins every workspace network and forwards a request only if it carries a 256-bit secret known only to the edge (and only to a `<workspace>_<service>:<port>` target, never a core container). Containers can reach the router but cannot use it. This relies only on HTTP and container networking, so it behaves the same on every engine and OS — and it also isolates workspaces from each other.

### Finding 3 — DNS rebinding against the private tier
The private tier was declared with a catch-all `:80`, so it answered *any* `Host`. A malicious website can resolve its own domain to `127.0.0.1` and then read responses with JavaScript in the victim's browser: `Host: attacker.example` returned the workspace list and Portainer with **200**.

**Fix**: the private tier answers only an explicit host list and ends with `:80 { abort }`; the dashboard also enforces a host allowlist and rejects cross-origin `POST`s (CSRF).

### Further hardening from the same audit
- `trusted_proxies` removed — LAN clients can no longer spoof `X-Forwarded-For` to upstreams.
- Dashboard: workspace ids validated (a public `GET` could previously create directories via `../`), public scope pinned to core data (no workspace enumeration), uploads validated before replacing anything, SVG never served from the dashboard origin.
- Route generator: names validated before being written into Caddy config; each generated file records its owner so one workspace can't delete another's (or core's) routes; stale public routes are pruned when a service is removed.
- Containers: Jellyfin no longer mounts all of `/home` (which included `~/.ssh` and the local CA's private key); the backup container — which mounts `/` — has no network at all; core containers run with read-only root filesystems and only `CAP_NET_BIND_SERVICE`.
- The local CA's private key and runtime state were removed from version control.

### Verification
```bash
$ curl -s -m4 -o /dev/null -w '%{http_code}\n' -H 'Host: attacker.example' http://127.0.0.1/api/workspaces
000   # rebinding: connection aborted
$ podman exec containers_jellyfin curl -s -m4 -o /dev/null -w '%{http_code}\n' http://om_caddy/portainer/
000   # pivot: the edge is not on the container's network
$ podman exec containers_jellyfin curl -s -m4 -o /dev/null -w '%{http_code}\n' -H 'X-Om-Upstream: perso_pep:8080' http://om_router:8000/
000   # router without the edge token: aborted
$ curl -s -m4 -o /dev/null -w '%{http_code}\n' http://192.168.1.5:35183/
000   # formerly-published port: gone
$ curl -s -o /dev/null -w '%{http_code}\n' http://localhost/portainer/
200   # legitimate admin access unchanged
```

The full list of layers and the verification suite live in [Network Architecture §3 and §9](../NETWORK_ARCHITECTURE.md).

---

## 8. Architectural Impact & Conclusion

Socket isolation was the right foundation, but the audit shows why a single control is never enough: each of the three bypasses went *around* it rather than through it. The final design is layered so that each layer fails closed independently:

**firewall (only 80/443) → socket separation → route absence → explicit hosts → token-gated router → dashboard checks → container isolation.**

The resulting system is:
- **Single-entry**: one front door (Caddy on 80/443); everything else on the host is dropped.
- **Fail-closed**: every check aborts on mismatch rather than falling through.
- **Private**: zero-knowledge frontend and API isolation for the LAN tier.
- **Dynamic**: automated service discovery and a self-pruning routing lifecycle.

No system is impenetrable — the remaining trust boundaries (the Podman socket held by the dashboard and Portainer, the services' own authentication, the Tailscale account) are documented rather than assumed away.
