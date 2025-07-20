#!/bin/bash
# Enable and persist TCP BBR when the running kernel provides it (Linux 4.9+).
# Safe to run multiple times. Skips quietly if BBR is unavailable.

if [ ! -r /proc/sys/net/ipv4/tcp_available_congestion_control ]; then
	exit 0
fi
if ! grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
	exit 0
fi

sudo sysctl -w net.ipv4.tcp_congestion_control=bbr 2>/dev/null || true
echo 'net.ipv4.tcp_congestion_control=bbr' | sudo tee /etc/sysctl.d/99-amnezia-tcp-bbr.conf >/dev/null
