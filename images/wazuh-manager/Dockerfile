# Wazuh manager for generation mode: manager only (no indexer/dashboard), Debian 12,
# libfaketime available for virtual time. Pinned to one Wazuh version per release.
FROM debian:12-slim

ARG WAZUH_VERSION=4.14.9-1

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gnupg procps libfaketime \
 && curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
      > /etc/apt/sources.list.d/wazuh.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends wazuh-manager=${WAZUH_VERSION} \
 && rm -rf /var/lib/apt/lists/* \
 && ln -s "$(ls /usr/lib/*/faketime/libfaketime.so.1 | head -1)" /usr/local/lib/libfaketime.so.1

# Generation-mode settings: JSON archives on, no indexer, no vulnerability detector
# (posture comes from Trivy). perl-base is part of every Debian image.
RUN perl -0pi -e 's#<logall_json>no</logall_json>#<logall_json>yes</logall_json>#' /var/ossec/etc/ossec.conf \
 && perl -0pi -e 's#(<vulnerability-detection>\s*<enabled>)yes#${1}no#' /var/ossec/etc/ossec.conf \
 && perl -0pi -e 's#(<indexer>\s*<enabled>)yes#${1}no#' /var/ossec/etc/ossec.conf \
 && grep -q "<logall_json>yes" /var/ossec/etc/ossec.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 1514 1515
ENTRYPOINT ["/entrypoint.sh"]
