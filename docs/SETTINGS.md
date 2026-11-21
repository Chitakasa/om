<!-- Generated from the code by tests/gen_reference.py: do not edit. Run `python3 tests/gen_reference.py` after a change. -->
# Settings

Machine settings live in `~/.config/om/om.env` (`$OM_CONFIG_DIR/om.env`), one `KEY=value` per line, written readable by you only. Read and change them with `om config show`, `om config set KEY=value` and `om config unset KEY`: every value is checked, and `OM_NOTIFY_URL` is shown as `***` unless you ask. `auto` means "detect it"; `off` means "switch it off". Most changes take effect after the command named under *Then run*.

## `OM_FIREWALL_EXTRA_TCP`

Extra inbound TCP ports the host firewall lets through, for example `1714-1764`.

- **Default:** (empty)
- **Accepts:** a comma list of ports or ranges
- **Change it with:** `om config set OM_FIREWALL_EXTRA_TCP=<value>`
- **Then run:** `om firewall apply`

## `OM_FIREWALL_EXTRA_UDP`

Extra inbound UDP ports the host firewall lets through.

- **Default:** (empty)
- **Accepts:** a comma list of ports or ranges
- **Change it with:** `om config set OM_FIREWALL_EXTRA_UDP=<value>`
- **Then run:** `om firewall apply`

## `OM_HTTPS_PORT`

The host port of the front door (HTTPS).

- **Default:** `443`
- **Accepts:** 1-65535
- **Change it with:** `om config set OM_HTTPS_PORT=<value>`
- **Then run:** `om core restart, then om firewall apply`

## `OM_HTTP_PORT`

The host port of the front door (HTTP). Change it to run a second om, for another OS user, on the same machine.

- **Default:** `80`
- **Accepts:** 1-65535
- **Change it with:** `om config set OM_HTTP_PORT=<value>`
- **Then run:** `om core restart, then om firewall apply`

## `OM_LAN_IP`

The address om treats as this machine's LAN address, where the public tier is served. `auto` detects it; `off` turns the LAN tier off.

- **Default:** `auto`
- **Accepts:** `auto`, `off`, or an IPv4 address
- **Change it with:** `om config set OM_LAN_IP=<value>`
- **Then run:** `om core restart`

## `OM_NOTIFY`

Where om sends messages about updates and failures. `auto` is desktop toasts only, so nothing leaves the machine; `webhook` posts to `OM_NOTIFY_URL` and is never automatic. Every message is also written to `notify.log`.

- **Default:** `auto`
- **Accepts:** `auto`, `off`, or a comma list of `desktop`, `webhook`
- **Change it with:** `om config set OM_NOTIFY=<value>`

## `OM_NOTIFY_URL`

Where the webhook channel posts, for example an ntfy topic. It acts like a password: the file is kept 0600 and `om config` shows it as `***`.

- **Default:** (empty)
- **Accepts:** an `https://` URL (`http://` only to this machine or a private address)
- **Change it with:** `om config set OM_NOTIFY_URL=<value>`

## `OM_POLICY`

The deploy policy gate: privileged containers, host namespaces, `ports:`, engine sockets and sensitive mounts. `enforce` refuses the compose file and names the fix; `warn` only reports. See `om policy check`.

- **Default:** `enforce`
- **Accepts:** `enforce` or `warn`
- **Change it with:** `om config set OM_POLICY=<value>`

## `OM_SIGNED`

Signed deploys: a clean commit must be signed by a key in the workspace's `.om/allowed_signers`. `auto` enforces as soon as git is set up to sign with an SSH key, and warns otherwise. A dirty tree always runs as an unsigned dev generation.

- **Default:** `auto`
- **Accepts:** `auto`, `warn` or `enforce`
- **Change it with:** `om config set OM_SIGNED=<value>`

## `OM_TRUSTED_USERS`

Other accounts on this machine that are yours. `om doctor` does not count them as people who could use the private tier without a login.

- **Default:** (empty)
- **Accepts:** a comma list of account names
- **Change it with:** `om config set OM_TRUSTED_USERS=<value>`

## `OM_VPN`

The VPNs trusted to reach the private tier: only VPNs whose members are all your own devices. None by default. Set it with `om vpn trust <interface>`.

- **Default:** (empty)
- **Accepts:** `auto`, or interfaces / addresses such as `wg0,10.8.0.1`
- **Change it with:** `om vpn trust|untrust <interface>` (it also updates the firewall)

## `OM_VPN_ALLOW`

Only these VPN devices reach the private tier; other devices on a trusted VPN get the public tier. Empty means every device on a trusted VPN. Set it with `om vpn allow <device>`; the host firewall enforces it (`om firewall apply`), and until it does the VPN's private tier stays closed.

- **Default:** (empty)
- **Accepts:** empty, or addresses and ranges
- **Change it with:** `om vpn allow|disallow <device>` (it also updates the firewall)

## `OM_WALLPAPERS_DIR`

The folder the dashboard takes wallpapers from. `auto` uses `~/Pictures/Wallpapers` when it exists, else a folder in om's data.

- **Default:** `auto`
- **Accepts:** `auto` or a folder
- **Change it with:** `om config set OM_WALLPAPERS_DIR=<value>`
- **Then run:** `om core restart`
