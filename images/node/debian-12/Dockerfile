# Range node, Debian 12: base tools + Wazuh agent + the services named in RECIPES.
# One Dockerfile for every role; the compiler passes RECIPES per image tag. Layers before
# `ARG RECIPES` are shared by every node built on a machine (including the vendor deploy
# key, so `auth.shared_ssh_key` really is the same key on every host).
FROM debian:12-slim

ARG WAZUH_VERSION=4.14.9-1
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gnupg procps iproute2 iputils-ping \
      netcat-openbsd dnsutils rsyslog sudo openssh-client openssl less python3 \
 && curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
      > /etc/apt/sources.list.d/wazuh.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends wazuh-agent=${WAZUH_VERSION} \
 && rm -rf /var/lib/apt/lists/* \
 && sed -i '/imklog/s/^/#/' /etc/rsyslog.conf \
 && mkdir -p /opt/vendor \
 && ssh-keygen -q -t ed25519 -N '' -C deploy@vendor -f /opt/vendor/deploy_key

# FIM on /etc only (INPUT Part 3, 6.4): the default set (/usr/bin, /usr/sbin, /bin, /boot)
# costs minutes of CPU at every start and adds nothing to the scenarios.
RUN perl -0pi -e 's#<directories>/etc,/usr/bin,/usr/sbin</directories>#<directories>/etc</directories>#' /var/ossec/etc/ossec.conf \
 && perl -0pi -e 's#\s*<directories>/bin,/sbin,/boot</directories>##' /var/ossec/etc/ossec.conf

ARG RECIPES=""
RUN pkgs="" \
 && for r in $(echo "${RECIPES}" | tr ',' ' '); do \
      case "$r" in \
        nginx)       pkgs="$pkgs nginx" ;; \
        openssh)     pkgs="$pkgs openssh-server" ;; \
        postgresql)  pkgs="$pkgs postgresql postgresql-client" ;; \
        unbound)     pkgs="$pkgs unbound" ;; \
        flask_shop)  pkgs="$pkgs python3-flask python3-psycopg2 gunicorn" ;; \
        *) echo "unknown recipe: $r" >&2; exit 1 ;; \
      esac; \
    done \
 && if [ -n "$pkgs" ]; then apt-get update && apt-get install -y --no-install-recommends $pkgs \
      && rm -rf /var/lib/apt/lists/*; fi \
 && dpkg-query -W -f '${Package}\t${Version}\n' > /opt/vendor/packages.tsv

COPY shop /opt/shop
COPY node-init.sh /usr/local/sbin/node-init
RUN chmod 0755 /usr/local/sbin/node-init

STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/sbin/node-init"]
