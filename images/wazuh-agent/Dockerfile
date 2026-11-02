# Wazuh agent base layer (Layer 3 of the image model), Debian 12, libfaketime available.
FROM debian:12-slim

ARG WAZUH_VERSION=4.14.9-1

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gnupg procps libfaketime \
 && curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
      > /etc/apt/sources.list.d/wazuh.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends wazuh-agent=${WAZUH_VERSION} \
 && rm -rf /var/lib/apt/lists/* \
 && ln -s "$(ls /usr/lib/*/faketime/libfaketime.so.1 | head -1)" /usr/local/lib/libfaketime.so.1

# Keep FIM small and compressed (INPUT Part 3, 6.4): /etc only, every 5 minutes.
RUN perl -0pi -e 's#<frequency>43200</frequency>#<frequency>300</frequency>#' /var/ossec/etc/ossec.conf \
 && perl -0pi -e 's#<directories>/etc,/usr/bin,/usr/sbin</directories>#<directories>/etc</directories>#' /var/ossec/etc/ossec.conf \
 && perl -0pi -e 's#\s*<directories>/bin,/sbin,/boot</directories>##' /var/ossec/etc/ossec.conf \
 && mkdir -p /var/log/iris && touch /var/log/iris/canary.log \
 && printf '\n<ossec_config>\n  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/iris/canary.log</location>\n  </localfile>\n</ossec_config>\n' \
      >> /var/ossec/etc/ossec.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
