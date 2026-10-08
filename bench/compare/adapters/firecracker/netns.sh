#!/usr/bin/env bash
# One network namespace per Firecracker slot. Every guest restored from
# the snapshot has the same IP (172.16.0.2) and MAC, so each lives in a
# namespace of its own with its own tap0, and the host reaches it through
# a veth pair and a DNAT rule. Runs as root on the KVM host.
#
#   netns.sh up <slot>      make fc-<slot>, print the address the host dials
#   netns.sh down <slot>    remove it
#
# Slot n gets the /30 at 10.200.(n/64).((n%64)*4): host .1, namespace .2.
# Inside the namespace, traffic to .2:port is DNATed to the guest, and
# the guest's replies are masqueraded to tap0's address so no route is
# needed in the guest.
set -euo pipefail
cmd=${1:?up|down} slot=${2:?slot}
ns="fc-$slot"
third=$((slot / 64)); fourth=$(((slot % 64) * 4))
host="10.200.$third.$((fourth + 1))"; peer="10.200.$third.$((fourth + 2))"
veth="fcv$slot"
case "$cmd" in
  up)
    ip netns add "$ns"
    ip netns exec "$ns" ip link set lo up
    ip netns exec "$ns" ip tuntap add tap0 mode tap
    ip netns exec "$ns" ip addr add 172.16.0.1/30 dev tap0
    ip netns exec "$ns" ip link set tap0 up
    ip link add "$veth" type veth peer name veth0 netns "$ns"
    ip addr add "$host/30" dev "$veth"
    ip link set "$veth" up
    ip netns exec "$ns" ip addr add "$peer/30" dev veth0
    ip netns exec "$ns" ip link set veth0 up
    ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
    ip netns exec "$ns" iptables -t nat -A PREROUTING -d "$peer" -j DNAT --to-destination 172.16.0.2
    ip netns exec "$ns" iptables -t nat -A POSTROUTING -o tap0 -j MASQUERADE
    echo "$peer"
    ;;
  down)
    ip link del "$veth" 2>/dev/null || true
    ip netns del "$ns" 2>/dev/null || true
    ;;
  *) echo "usage: $0 up|down <slot>" >&2; exit 2 ;;
esac
