#!/bin/bash
# Enrols once (keys persist in the /var/ossec volume across episodes), then starts the agent.
set -euo pipefail

: "${WAZUH_MANAGER:?WAZUH_MANAGER must be set}"
: "${AGENT_NAME:?AGENT_NAME must be set}"

sed -i "s#<address>.*</address>#<address>${WAZUH_MANAGER}</address>#" /var/ossec/etc/ossec.conf

if [ ! -s /var/ossec/etc/client.keys ]; then
  for _ in $(seq 1 90); do
    if /var/ossec/bin/agent-auth -m "${WAZUH_MANAGER}" -A "${AGENT_NAME}" >/dev/null 2>&1; then
      echo "enrolled as ${AGENT_NAME}"
      break
    fi
    sleep 2
  done
fi
[ -s /var/ossec/etc/client.keys ] || { echo "enrolment failed" >&2; exit 1; }

/var/ossec/bin/wazuh-control start
exec tail -F /var/ossec/logs/ossec.log
