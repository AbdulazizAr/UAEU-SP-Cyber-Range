#!/bin/bash
# Node start-up for the live range. Configuration comes only from environment variables
# written by the compiler (iris.generator.compiler.node_env):
#   IRIS_GATEWAY      router address in this zone (becomes the default route)
#   IRIS_DNS          enterprise resolver; IRIS_DOMAIN internal domain
#   IRIS_SERVICES     recipe:version:port/proto[:tls],...
#   IRIS_WEAKNESSES   planted weakness modules on this host (comma-separated)
#   IRIS_USERS        user:password:privilege;...   IRIS_ROOT_PASSWORD
#   IRIS_UPSTREAM     nginx -> app (ip:port,...)    IRIS_DB  app -> db (ip:port:db:user:password)
#   IRIS_DB_CLIENTS   db: allowed client IPs        IRIS_DB_APP  db:user:password   IRIS_PG_PASSWORD
#   IRIS_DNS_RECORDS  dns: host=ip;...              IRIS_DNS_CLIENTS  subnets allowed to query
#   WAZUH_MANAGER / AGENT_NAME   set only on monitored hosts
# Every step reports "node-init: <step> ok|FAIL ..." on stdout (docker logs); the health
# gate verifies services from outside, so a failed step never stops the container.
set -uo pipefail

log() { echo "node-init: $*"; }
has_weak() { [[ ",${IRIS_WEAKNESSES:-}," == *",$1,"* ]]; }
svc_field() { # svc_field <recipe> <field: port|proto|tls>
  local entry
  IFS=',' read -ra entries <<< "${IRIS_SERVICES:-}"
  for entry in "${entries[@]}"; do
    IFS=':' read -r recipe _version portproto tls <<< "$entry"
    if [ "$recipe" = "$1" ]; then
      case "$2" in
        port) echo "${portproto%%/*}" ;;
        proto) echo "${portproto##*/}" ;;
        tls) [ "${tls:-}" = "tls" ] && echo yes || echo no ;;
      esac
      return 0
    fi
  done
  return 1
}
has_recipe() { svc_field "$1" port >/dev/null; }

# ---------------------------------------------------------------- network
if [ -n "${IRIS_GATEWAY:-}" ]; then
  ip route replace default via "$IRIS_GATEWAY" && log "route ok via $IRIS_GATEWAY" || log "route FAIL"
fi
if has_recipe unbound; then
  printf 'nameserver 127.0.0.1\nsearch %s\n' "${IRIS_DOMAIN:-lan}" > /etc/resolv.conf
elif [ -n "${IRIS_DNS:-}" ]; then
  printf 'nameserver %s\nsearch %s\n' "$IRIS_DNS" "${IRIS_DOMAIN:-lan}" > /etc/resolv.conf
fi

# ---------------------------------------------------------------- logging
mkdir -p /var/log
rsyslogd && log "rsyslog ok" || log "rsyslog FAIL"

# ---------------------------------------------------------------- accounts
if [ -n "${IRIS_ROOT_PASSWORD:-}" ]; then
  echo "root:${IRIS_ROOT_PASSWORD}" | chpasswd
fi
IFS=';' read -ra users <<< "${IRIS_USERS:-}"
for u in "${users[@]}"; do
  [ -z "$u" ] && continue
  IFS=':' read -r name pass priv <<< "$u"
  id "$name" >/dev/null 2>&1 || useradd -m -s /bin/bash "$name"
  echo "${name}:${pass}" | chpasswd
  [ "$priv" = "admin" ] && usermod -aG sudo "$name"
done
log "accounts ok (${#users[@]})"
if has_weak host.sudo_nopasswd; then
  echo '%sudo ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/90-ops
  chmod 0440 /etc/sudoers.d/90-ops
fi

# ---------------------------------------------------------------- openssh
start_sshd() {
  local port; port=$(svc_field openssh port)
  ssh-keygen -A >/dev/null
  mkdir -p /run/sshd /root/.ssh
  chmod 700 /root/.ssh
  {
    echo "Port ${port}"
    has_weak auth.ssh_password && echo "PasswordAuthentication yes" || echo "PasswordAuthentication no"
    has_weak auth.ssh_root_login && echo "PermitRootLogin yes" || echo "PermitRootLogin prohibit-password"
    echo "UseDNS no"
  } > /etc/ssh/sshd_config.d/10-site.conf
  if has_weak auth.shared_ssh_key; then
    cat /opt/vendor/deploy_key.pub >> /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
  fi
  /usr/sbin/sshd && log "openssh ok :${port}" || log "openssh FAIL"
}

# ---------------------------------------------------------------- nginx
start_nginx() {
  local port tls upstream fqdn
  port=$(svc_field nginx port); tls=$(svc_field nginx tls)
  upstream="${IRIS_UPSTREAM:-}"; fqdn="$(hostname).${IRIS_DOMAIN:-lan}"
  rm -f /etc/nginx/sites-enabled/default
  {
    if [ -n "$upstream" ]; then
      echo "upstream shop_app {"
      IFS=',' read -ra ups <<< "$upstream"
      for u in "${ups[@]}"; do echo "  server ${u};"; done
      echo "}"
    fi
    echo "server {"
    if [ "$tls" = "yes" ]; then
      mkdir -p /etc/nginx/tls
      openssl req -x509 -nodes -newkey rsa:2048 -days 825 -subj "/CN=${fqdn}" \
        -keyout /etc/nginx/tls/site.key -out /etc/nginx/tls/site.crt >/dev/null 2>&1
      echo "  listen ${port} ssl;"
      echo "  ssl_certificate /etc/nginx/tls/site.crt;"
      echo "  ssl_certificate_key /etc/nginx/tls/site.key;"
      if has_weak tls.weak_config; then
        echo "  ssl_protocols TLSv1 TLSv1.1 TLSv1.2;"
        echo "  ssl_ciphers DEFAULT:@SECLEVEL=0;"
      else
        echo "  ssl_protocols TLSv1.2 TLSv1.3;"
        echo "  ssl_ciphers HIGH:!aNULL:!MD5;"
      fi
    else
      echo "  listen ${port};"
    fi
    echo "  server_name ${fqdn};"
    echo "  access_log /var/log/nginx/access.log;"
    echo "  error_log /var/log/nginx/error.log;"
    if [ -n "$upstream" ]; then
      echo "  location / {"
      echo "    proxy_pass http://shop_app;"
      echo "    proxy_set_header Host \$host;"
      echo "    proxy_set_header X-Forwarded-For \$remote_addr;"
      echo "  }"
      echo "  location /admin {"
      if has_weak web.admin_exposed; then
        echo "    proxy_pass http://shop_app;"
        echo "    proxy_set_header X-Forwarded-For \$remote_addr;"
      else
        echo "    return 403;"
      fi
      echo "  }"
    else
      echo "  location / { root /var/www/html; }"
    fi
    echo "}"
  } > /etc/nginx/conf.d/site.conf
  nginx -t >/dev/null 2>&1 && nginx && log "nginx ok :${port} tls=${tls}" || log "nginx FAIL $(nginx -t 2>&1 | tail -1)"
}

# ---------------------------------------------------------------- postgresql
start_postgres() {
  local port ver conf db user pass
  port=$(svc_field postgresql port)
  ver=$(ls /etc/postgresql | sort -V | tail -1)
  conf="/etc/postgresql/${ver}/main"
  IFS=':' read -r db user pass <<< "${IRIS_DB_APP:-shop:app:app}"
  sed -i "s/^#\?listen_addresses.*/listen_addresses = '*'/" "$conf/postgresql.conf"
  sed -i "s/^#\?port = .*/port = ${port}/" "$conf/postgresql.conf"
  {
    echo "log_connections = on"
    echo "log_disconnections = on"
    echo "log_line_prefix = '%m [%p] %q%u@%d from %h '"
  } >> "$conf/postgresql.conf"
  {
    echo "local   all   postgres                peer"
    echo "local   all   all                     peer"
    echo "host    all   all   127.0.0.1/32      scram-sha-256"
    IFS=',' read -ra clients <<< "${IRIS_DB_CLIENTS:-}"
    for c in "${clients[@]}"; do
      [ -n "$c" ] && echo "host    ${db}   ${user}   ${c}/32   scram-sha-256"
    done
    has_weak db.listen_all && echo "host    all   all   0.0.0.0/0         scram-sha-256"
  } > "$conf/pg_hba.conf"
  if ! pg_ctlcluster "$ver" main start; then log "postgresql FAIL"; return; fi
  su postgres -c "psql -q -v ON_ERROR_STOP=1" <<SQL >/dev/null
ALTER USER postgres PASSWORD '${IRIS_PG_PASSWORD:-postgres}';
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${user}') THEN
    CREATE ROLE ${user} LOGIN PASSWORD '${pass}';
  ELSE
    ALTER ROLE ${user} PASSWORD '${pass}';
  END IF;
END \$\$;
SQL
  su postgres -c "psql -tAc \"SELECT 1 FROM pg_database WHERE datname='${db}'\"" | grep -q 1 \
    || su postgres -c "createdb -O ${user} ${db}"
  log "postgresql ok :${port} (${ver})"
}

# ---------------------------------------------------------------- unbound
start_unbound() {
  local domain="${IRIS_DOMAIN:-lan}"
  {
    echo "server:"
    echo "  interface: 0.0.0.0"
    echo "  port: $(svc_field unbound port)"
    echo "  access-control: 127.0.0.0/8 allow"
    IFS=',' read -ra nets <<< "${IRIS_DNS_CLIENTS:-}"
    for n in "${nets[@]}"; do [ -n "$n" ] && echo "  access-control: ${n} allow"; done
    echo "  module-config: \"iterator\""
    echo "  use-syslog: yes"
    echo "  log-queries: yes"
    echo "  local-zone: \"${domain}.\" static"
    IFS=';' read -ra recs <<< "${IRIS_DNS_RECORDS:-}"
    for r in "${recs[@]}"; do
      [ -z "$r" ] && continue
      echo "  local-data: \"${r%%=*}.${domain}. IN A ${r##*=}\""
      echo "  local-data-ptr: \"${r##*=} ${r%%=*}.${domain}\""
    done
    echo "remote-control:"
    echo "  control-enable: no"
  } > /etc/unbound/unbound.conf.d/site.conf
  rm -f /etc/unbound/unbound.conf.d/remote-control.conf
  # Debian enables DNSSEC validation with a root trust anchor that systemd's unbound-anchor
  # would create; the range has no Internet and only serves its own zone, so it is not used.
  rm -f /etc/unbound/unbound.conf.d/root-auto-trust-anchor-file.conf
  unbound-checkconf >/dev/null 2>&1 && unbound && log "unbound ok" || log "unbound FAIL $(unbound-checkconf 2>&1 | tail -1)"
}

# ---------------------------------------------------------------- shop app
start_shop() {
  local port; port=$(svc_field flask_shop port)
  id svc_flask >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin svc_flask
  mkdir -p /var/log/shop && chown svc_flask /var/log/shop
  SHOP_DB="${IRIS_DB:-}" SHOP_WEAKNESSES="${IRIS_WEAKNESSES:-}" SHOP_SECRET="${IRIS_ROOT_PASSWORD:-x}" \
    runuser -u svc_flask -- gunicorn --chdir /opt/shop -b "0.0.0.0:${port}" -w 2 --preload --daemon \
      --access-logfile /var/log/shop/access.log --error-logfile /var/log/shop/error.log app:app \
    && log "flask_shop ok :${port}" || log "flask_shop FAIL"
}

has_recipe openssh && start_sshd
has_recipe postgresql && start_postgres
has_recipe unbound && start_unbound
has_recipe flask_shop && start_shop
has_recipe nginx && start_nginx

# ---------------------------------------------------------------- wazuh agent
add_localfile() { # add_localfile <format> <path>
  grep -q "<location>$2</location>" /var/ossec/etc/ossec.conf && return
  sed -i "0,/<\/ossec_config>/s##  <localfile>\n    <log_format>$1</log_format>\n    <location>$2</location>\n  </localfile>\n</ossec_config>#" \
    /var/ossec/etc/ossec.conf
}
if [ -n "${WAZUH_MANAGER:-}" ] && [ -n "${AGENT_NAME:-}" ]; then
  sed -i "s#<address>.*</address>#<address>${WAZUH_MANAGER}</address>#" /var/ossec/etc/ossec.conf
  add_localfile syslog /var/log/auth.log
  add_localfile syslog /var/log/syslog
  has_recipe nginx && add_localfile apache /var/log/nginx/access.log && add_localfile apache /var/log/nginx/error.log
  has_recipe postgresql && add_localfile syslog "/var/log/postgresql/postgresql-*-main.log"
  has_recipe flask_shop && add_localfile json /var/log/shop/app.log
  if [ ! -s /var/ossec/etc/client.keys ]; then
    for _ in $(seq 1 90); do
      /var/ossec/bin/agent-auth -m "${WAZUH_MANAGER}" -A "${AGENT_NAME}" >/dev/null 2>&1 && break
      sleep 2
    done
  fi
  if [ -s /var/ossec/etc/client.keys ]; then
    /var/ossec/bin/wazuh-control start >/dev/null 2>&1 && log "wazuh-agent ok" || log "wazuh-agent FAIL start"
  else
    log "wazuh-agent FAIL enrolment"
  fi
fi

log "ready"
stop() {
  log "stopping"
  [ -x /var/ossec/bin/wazuh-control ] && /var/ossec/bin/wazuh-control stop >/dev/null 2>&1
  pkill -TERM nginx gunicorn sshd unbound 2>/dev/null
  ls /etc/postgresql >/dev/null 2>&1 && pg_ctlcluster "$(ls /etc/postgresql | sort -V | tail -1)" main stop 2>/dev/null
  exit 0
}
trap stop TERM INT
sleep infinity &
wait $!
