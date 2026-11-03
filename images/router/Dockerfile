# Router/firewall of the live range: forwards between zone bridges, nftables policy from
# the compiler (router.nft, mounted read-only). The Suricata sensor joins this namespace.
FROM debian:12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 nftables iputils-ping procps conntrack \
 && rm -rf /var/lib/apt/lists/*

COPY router-init.sh /usr/local/sbin/router-init
RUN chmod 0755 /usr/local/sbin/router-init
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/sbin/router-init"]
