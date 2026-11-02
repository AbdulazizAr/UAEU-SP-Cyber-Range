#!/bin/bash
# Starts the Wazuh manager on the real clock (records are shifted into virtual time at export).
set -euo pipefail

mkdir -p /var/ossec/logs/alerts /var/ossec/logs/archives
# Do not let one optional daemon (e.g. the API) kill the container: report and keep going.
/var/ossec/bin/wazuh-control start || echo "wazuh-control start exited $? (see wazuh-control status)"
touch /var/ossec/logs/alerts/alerts.json /var/ossec/logs/archives/archives.json
exec tail -F /var/ossec/logs/ossec.log
