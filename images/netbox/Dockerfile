# Minimal network node for spikes: router/firewall (nftables), clients and simple servers.
FROM debian:12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 nftables iputils-ping curl netcat-openbsd python3-minimal procps \
 && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
