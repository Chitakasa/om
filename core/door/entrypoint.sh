#!/bin/sh
# Bring up wg0 from the config om renders (peers come only from the signed access file).
# Kernel WireGuard when the host has it; wireguard-go (userspace) otherwise.
set -eu
CONF=/etc/om-door/wg0.conf
if ! ip link add wg0 type wireguard 2>/dev/null; then
    echo "om-door: kernel WireGuard unavailable, using wireguard-go"
    wireguard-go wg0
fi
wg setconf wg0 "$CONF"
ip address add "${DOOR_CIDR:?}" dev wg0
ip link set wg0 up
echo "om-door: wg0 up on ${DOOR_CIDR}, $(wg show wg0 peers | wc -l) peer(s)"
# om reloads peers with `wg syncconf wg0 /etc/om-door/wg0.conf` (no restart, no dropped tunnels).
# Device DNS, on the door address only: om's names → the door; everything else → upstream.
# A DNS failure must never take the door (and the edge in its namespace) down: background it.
dnsmasq --keep-in-foreground --user=root --group=root --listen-address="${DOOR_IP:?}" --bind-interfaces \
    --no-hosts --cache-size=500 --log-facility=- \
    --address="/${OM_DOMAIN:?}/${DOOR_IP}" --address="/${OM_DOMAIN_P:?}/${DOOR_IP}" &
trap 'exit 0' TERM INT
while :; do sleep 3600 & wait $!; done
