#!/usr/bin/env bash
set -euo pipefail

# This script starts as root so the network backstop can be installed, then
# drops privileges before starting uvicorn. If the runtime disallows NET_ADMIN,
# the application-layer DNS/request guard remains active.
if [ "${SANDBOX_APPLY_IPTABLES:-1}" = "1" ] && command -v iptables >/dev/null 2>&1; then
  for net in \
    10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 127.0.0.0/8 \
    169.254.0.0/16 100.64.0.0/10 224.0.0.0/4 240.0.0.0/4; do
    iptables -A OUTPUT -d "$net" -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || true
done
fi

exec su -s /bin/bash sandbox -c 'exec uvicorn src.main:app --host 0.0.0.0 --port 8080 --workers 1'
