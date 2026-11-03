#!/bin/bash
set -uo pipefail
if [ -n "${IRIS_GATEWAY:-}" ]; then
  ip route replace default via "$IRIS_GATEWAY" && echo "external-init: route ok" || echo "external-init: route FAIL"
fi
echo "external-init: ready (${IRIS_EXTERNAL_KIND:-client})"
trap 'exit 0' TERM INT
sleep infinity &
wait $!
