# Node in the simulated Internet: clients, the attacker and a background scanner.
# Attack tooling arrives with the P4 attack templates; this is the reachable baseline.
FROM debian:12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 iputils-ping curl netcat-openbsd dnsutils nmap \
      openssh-client sshpass python3 procps ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY external-init.sh /usr/local/sbin/external-init
RUN chmod 0755 /usr/local/sbin/external-init
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/sbin/external-init"]
