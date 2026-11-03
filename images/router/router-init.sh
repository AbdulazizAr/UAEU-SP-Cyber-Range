#!/bin/bash
# No default route (containment: nothing leaves the range), forwarding on, policy loaded.
set -uo pipefail
ip route del default 2>/dev/null || true
sysctl -qw net.ipv4.ip_forward=1 2>/dev/null || true
if nft -f /etc/iris/router.nft; then
  echo "router-init: policy ok ($(nft list chain inet iris forward | grep -c 'accept\|drop') rules)"
else
  echo "router-init: policy FAIL"
fi
echo "router-init: ready"
trap 'exit 0' TERM INT
sleep infinity &
wait $!
