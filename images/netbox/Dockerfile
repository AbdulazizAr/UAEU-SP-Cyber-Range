# Minimal network node (python3, not python3-minimal: http.server lives in the full stdlib)
# for spikes: router/firewall (nftables), clients and simple servers.
FROM debian:12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 nftables iputils-ping curl netcat-openbsd python3 procps \
 && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
