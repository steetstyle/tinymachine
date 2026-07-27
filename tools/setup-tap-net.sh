#!/bin/bash
# One-time host-side NAT setup for tinymachine guest networking.
# Run once after boot: sudo bash tools/setup-tap-net.sh
#
# The TAP interface (tap-tiny) is created and configured automatically by
# the tinymachine binary (requires CAP_NET_ADMIN, set via setcap).
# This script only sets up iptables NAT so the guest can reach the internet.

TAP_NET="10.0.2.0/24"
# Change WAN_IF to your internet-facing interface (ip route show default)
WAN_IF="wlo1"

set -e

# Enable IP forwarding (if not already)
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# NAT: masquerade TAP traffic out the WAN interface
iptables -t nat -C POSTROUTING -s "$TAP_NET" -o "$WAN_IF" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s "$TAP_NET" -o "$WAN_IF" -j MASQUERADE

echo "Host NAT ready: $TAP_NET -> $WAN_IF"
echo "Run once per boot. Persist with: iptables-save > /etc/iptables/rules.v4"
