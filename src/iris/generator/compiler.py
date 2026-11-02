"""ScenarioSpec -> runnable Docker objects (INPUT Part 1, 0 and 2.5).

Produces, deterministically from the spec:

* ``compose.yaml``: one internal bridge network per zone (no egress to the real
  internet; Docker's bridge holds the last usable address), one container per asset and
  external node, per-container state volumes for Wazuh, virtual-time variables;
* ``router.nft``: the zone policy as an nftables forward chain (default drop);
* ``compiled.json``: images to build, sensor plan, memory estimate, address map.

Containers route through the router: each gets ``IRIS_GATEWAY`` and NET_ADMIN so its
entrypoint can replace the default route (the Docker bridge is not a gateway here).
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from iris.contracts.common import AssetRole
from iris.contracts.spec import FlowRule, ScenarioSpec
from iris.core.hashing import canonical_json, sha256_hex

WAZUH_IMAGE = "iris/wazuh-manager:4.14.9-1"
SURICATA_IMAGE = "jasonish/suricata:8.0.6"
ROUTER_IMAGE = "iris/router:0.1.0"
EXTERNAL_IMAGE = "iris/external:0.1.0"
LIBFAKETIME = "/usr/local/lib/libfaketime.so.1"

#: Planning estimates (MiB) per container; replaced by P1/P2 measurements.
MEM_MIB: dict[str, int] = {
    "router_firewall": 64,
    "ids_sensor": 512,
    "siem": 1536,
    "database": 384,
    "directory": 256,
    "app_server": 256,
    "web_server": 128,
    "reverse_proxy": 128,
    "file_server": 256,
    "mail_server": 128,
    "dns_server": 64,
    "backup_server": 128,
    "bastion": 64,
    "workstation": 128,
    "admin_workstation": 128,
    "external": 64,
}

VIRTUAL_TIME_ENV = {
    "FAKETIME": "${FAKETIME:-}",
    "LD_PRELOAD": "${IRIS_LD_PRELOAD:-}",
    "FAKETIME_DONT_FAKE_MONOTONIC": "1",
}


@dataclass
class CompiledRange:
    project: str
    compose: dict[str, Any]
    router_nft: str
    meta: dict[str, Any] = field(default_factory=dict)

    def write(self, out_dir: Path) -> list[Path]:
        out_dir.mkdir(parents=True, exist_ok=True)
        files = {
            "compose.yaml": yaml.safe_dump(self.compose, sort_keys=False, width=120),
            "router.nft": self.router_nft,
            "compiled.json": json.dumps(self.meta, indent=2, sort_keys=True) + "\n",
        }
        written = []
        for name, text in files.items():
            path = out_dir / name
            path.write_text(text, encoding="utf-8")
            written.append(path)
        return written


def bridge_address(subnet: str) -> str:
    """Docker's bridge takes the last usable address of each zone."""
    return str(ipaddress.ip_network(subnet).broadcast_address - 1)


def _tag(text: str) -> str:
    clean = re.sub(r"[^a-z0-9_.-]+", "-", text.lower()).strip("-.")
    return clean if len(clean) <= 120 else f"{clean[:100]}-{sha256_hex(clean)[:12]}"


def _nft_rule(rule: FlowRule, subnets: dict[str, str]) -> str:
    parts = [f"ip saddr {subnets[rule.src_zone]}", f"ip daddr {subnets[rule.dst_zone]}"]
    if rule.protocol in ("tcp", "udp") and rule.ports:
        ports = ", ".join(str(p) for p in sorted(rule.ports))
        parts.append(f"{rule.protocol} dport {{ {ports} }}")
    elif rule.protocol != "any":
        parts.append(f"meta l4proto {rule.protocol}")
    verdict = "accept" if rule.action == "allow" else "drop"
    note = f"{rule.src_zone}->{rule.dst_zone}" + (" exception" if rule.is_exception else "")
    return f'    {" ".join(parts)} {verdict} comment "{note}"'


def render_nft(spec: ScenarioSpec) -> str:
    subnets = {z.name: z.subnet for z in spec.zones}
    lines = [
        "#!/usr/sbin/nft -f",
        "# Generated from the scenario policy. Default: drop everything not allowed.",
        "flush ruleset",
        "table inet iris {",
        "  chain forward {",
        "    type filter hook forward priority 0; policy drop;",
        "    ct state established,related accept",
        "    ct state invalid drop",
        *[_nft_rule(r, subnets) for r in spec.policy],
        "  }",
        "}",
        "",
    ]
    return "\n".join(lines)


def node_image(spec: ScenarioSpec, asset_id: str, role: AssetRole, os_profile: str) -> str:
    services = sorted(f"{s.recipe}{s.version}" for s in spec.services if s.asset_id == asset_id)
    role_name = role.value.replace("_", "-")
    return f"iris/node-{role_name}:{_tag('-'.join([*services, os_profile]))}"


def asset_images(spec: ScenarioSpec) -> dict[str, str]:
    """Image each asset runs (the sensor shares the router namespace but has its own image)."""
    out: dict[str, str] = {}
    for a in spec.assets:
        if a.role is AssetRole.ROUTER_FIREWALL:
            out[a.asset_id] = ROUTER_IMAGE
        elif a.role is AssetRole.SIEM:
            out[a.asset_id] = WAZUH_IMAGE
        elif a.role is AssetRole.IDS_SENSOR:
            out[a.asset_id] = SURICATA_IMAGE
        else:
            out[a.asset_id] = node_image(spec, a.asset_id, a.role, a.os_profile)
    return out


def compile_spec(spec: ScenarioSpec) -> CompiledRange:
    spec_hash = sha256_hex(canonical_json(spec.model_dump(mode="json")))
    project = f"iris-{spec_hash[:10]}"
    zones = {z.name: z for z in spec.zones}
    net_key = {z: f"z_{z}" for z in zones}

    networks = {
        net_key[name]: {
            "driver": "bridge",
            "internal": True,
            "ipam": {"config": [{"subnet": z.subnet, "gateway": bridge_address(z.subnet)}]},
            "labels": {"iris.project": project, "iris.zone": name},
        }
        for name, z in zones.items()
    }

    siem = next((a for a in spec.assets if a.role is AssetRole.SIEM), None)
    siem_ip = siem.attachments[0].ip if siem and siem.attachments else None
    router = next(a for a in spec.assets if a.role is AssetRole.ROUTER_FIREWALL)
    router_ip = {att.zone: att.ip for att in router.attachments}

    services: dict[str, Any] = {}
    volumes: dict[str, Any] = {}
    images: set[str] = set()
    mem_total = 0
    address_map: dict[str, str] = {}

    def labels(node_id: str, role: str) -> dict[str, str]:
        return {"iris.project": project, "iris.node": node_id, "iris.role": role}

    for a in spec.assets:
        if a.role is AssetRole.IDS_SENSOR:
            mem_total += MEM_MIB["ids_sensor"]
            continue
        nets = {net_key[att.zone]: {"ipv4_address": att.ip} for att in a.attachments}
        for att in a.attachments:
            address_map[att.ip] = a.asset_id
        svc: dict[str, Any] = {
            "hostname": a.hostname,
            "container_name": f"{project}-{a.hostname}",
            "networks": nets,
            "labels": labels(a.asset_id, a.role.value),
            "mem_limit": f"{MEM_MIB[a.role.value] * 2}m",
        }
        if a.role is AssetRole.ROUTER_FIREWALL:
            svc.update(
                image=ROUTER_IMAGE,
                cap_add=["NET_ADMIN"],
                sysctls={"net.ipv4.ip_forward": "1"},
                volumes=["./router.nft:/etc/iris/router.nft:ro"],
            )
        elif a.role is AssetRole.SIEM:
            vol = f"{a.hostname}_state"
            volumes[vol] = {"labels": {"iris.project": project}}
            svc.update(
                image=WAZUH_IMAGE,
                cap_add=["NET_ADMIN"],
                environment={**VIRTUAL_TIME_ENV, "IRIS_GATEWAY": router_ip[a.attachments[0].zone]},
                volumes=[f"{vol}:/var/ossec"],
            )
        else:
            image = node_image(spec, a.asset_id, a.role, a.os_profile)
            env: dict[str, str] = {
                **VIRTUAL_TIME_ENV,
                "IRIS_GATEWAY": router_ip[a.attachments[0].zone],
                "IRIS_ROLE": a.role.value,
                "IRIS_SERVICES": ",".join(
                    f"{s.recipe}:{s.version}:{s.port}/{s.protocol}{':tls' if s.tls else ''}"
                    for s in spec.services
                    if s.asset_id == a.asset_id
                ),
            }
            vols: list[str] = []
            if a.monitored and siem_ip:
                env.update(WAZUH_MANAGER=siem_ip, AGENT_NAME=a.hostname)
                vol = f"{a.hostname}_ossec"
                volumes[vol] = {"labels": {"iris.project": project}}
                vols.append(f"{vol}:/var/ossec")
            svc.update(image=image, cap_add=["NET_ADMIN"], environment=env)
            if vols:
                svc["volumes"] = vols
        images.add(svc["image"])
        mem_total += MEM_MIB[a.role.value]
        services[a.hostname] = svc

    for ext in spec.externals:
        name = ext.node_id.lower()
        address_map[ext.ip] = ext.node_id
        services[name] = {
            "image": EXTERNAL_IMAGE,
            "hostname": f"host-{ext.ip.replace('.', '-')}",
            "container_name": f"{project}-{name}",
            "networks": {net_key[ext.zone]: {"ipv4_address": ext.ip}},
            "cap_add": ["NET_ADMIN"],
            "environment": {
                **VIRTUAL_TIME_ENV,
                "IRIS_GATEWAY": router_ip[ext.zone],
                "IRIS_EXTERNAL_KIND": ext.kind,
            },
            "labels": labels(ext.node_id, f"external_{ext.kind}"),
            "mem_limit": f"{MEM_MIB['external'] * 2}m",
        }
        images.add(EXTERNAL_IMAGE)
        mem_total += MEM_MIB["external"]

    compose: dict[str, Any] = {"name": project, "services": services, "networks": networks}
    if volumes:
        compose["volumes"] = volumes

    sensor = next(a for a in spec.assets if a.role is AssetRole.IDS_SENSOR)
    meta = {
        "project": project,
        "spec_hash": spec_hash,
        "group_id_hint": None,  # group_id is hidden-plane; computed from seeds by the packager
        "images": sorted(images | {SURICATA_IMAGE}),
        "container_count": len(services) + 1,
        "mem_estimate_mib": mem_total,
        "address_map": dict(sorted(address_map.items())),
        "sensor": {
            "asset_id": sensor.asset_id,
            "image": SURICATA_IMAGE,
            "network_mode": f"container:{project}-{router.hostname}",
            "capture": "all router interfaces (resolved at deploy)",
            "dedup": "community_id + event_type + signature within 1 s",
        },
        "virtual_time": {"libfaketime": LIBFAKETIME, "monotonic_faked": False},
    }
    return CompiledRange(project=project, compose=compose, router_nft=render_nft(spec), meta=meta)
