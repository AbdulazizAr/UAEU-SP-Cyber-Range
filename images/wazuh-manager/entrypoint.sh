#!/bin/bash
# Starts the Wazuh manager. Virtual time: when FAKETIME is set in the container
# environment, LD_PRELOAD (also set in the environment) makes every daemon and every
# `docker exec` process see the shifted clock. Monotonic time is never faked.
set -euo pipefail

if [ -n "${FAKETIME:-}" ]; then
  echo "virtual time: FAKETIME=${FAKETIME} -> $(date -u +%Y-%m-%dT%H:%M:%SZ)"
fi

mkdir -p /var/ossec/logs/alerts /var/ossec/logs/archives
# Do not let one optional daemon (e.g. the API) kill the container: report and keep going.
/var/ossec/bin/wazuh-control start || echo "wazuh-control start exited $? (see wazuh-control status)"
touch /var/ossec/logs/alerts/alerts.json /var/ossec/logs/archives/archives.json
exec tail -F /var/ossec/logs/ossec.log
