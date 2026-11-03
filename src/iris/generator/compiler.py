"""ScenarioSpec -> runnable Docker objects (INPUT Part 1, 0 and 2.5).

Produces, deterministically from the spec:

* ``compose.yaml``: one internal bridge network per zone (no egress to the real
  internet; Docker's bridge holds the last usable address), one container per asset and
  external node, per-container state volumes for Wazuh, the node configuration as environment variables
  (services, upstreams, users, planted weaknesses, DNS records), DNS pointed at the
  enterprise's own resolver;
* ``router.nft``: the zone policy as an nftables forward chain (default drop);
* ``compiled.json``: images to build (with build args), sensor plan, memory estimate,
  address map, DNS domain, and the scenario's credentials (hidden; run directory only).

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
from iris.generator.grc.reality import build_reality
from iris.generator.secrets import Secrets, scenario_secrets
from iris.generator.soc import build_soc
from iris.settings import repo_root

WAZUH_IMAGE = "iris/wazuh-manager:4.14.9-1"
SURICATA_IMAGE = "jasonish/suricata:8.0.6"
ROUTER_IMAGE = "iris/router:0.1.0"
EXTERNAL_IMAGE = "iris/external:0.1.0"

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

#: Containers run on the real clock; records are moved into virtual time at export
#: (iris.generator.retime, iris.generator.eve). libfaketime breaks Wazuh 4.14 (P1).
VIRTUAL_TIME = {"mode": "real-time capture, constant per-episode shift at export"}


@dataclass
class CompiledRange:
    project: str
    compose: dict[str, Any]
    router_nft: str
    meta: dict[str, Any] = field(default_factory=dict)
    extra_files: dict[str, str] = field(default_factory=dict)  # relative path -> text

    def write(self, out_dir: Path) -> list[Path]:
        out_dir.mkdir(parents=True, exist_ok=True)
        files = {
            "compose.yaml": yaml.safe_dump(self.compose, sort_keys=False, width=120),
            "router.nft": self.router_nft,
            "compiled.json": json.dumps(self.meta, indent=2, sort_keys=True) + "\n",
            **self.extra_files,
        }
        written = []
        for name, text in files.items():
            path = out_dir / name
            path.parent.mkdir(parents=True, exist_ok=True)
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


NODE_CONTEXT = "node/debian-12"
RULES_PATH = "/var/ossec/etc/rules/local_rules.xml"
ROUTER_CONTEXT, EXTERNAL_CONTEXT, WAZUH_CONTEXT = "router", "external", "wazuh-manager"
DB_NAME = "shop"


def org_domain(spec: ScenarioSpec) -> str:
    """Internal DNS domain, e.g. ``dunewell.lan``."""
    word = re.sub(r"[^a-z0-9]", "", spec.organization.name.split()[0].lower()) or "corp"
    return f"{word}.lan"


def _first_ip(spec: ScenarioSpec, asset_id: str) -> str | None:
    a = next(x for x in spec.assets if x.asset_id == asset_id)
    return a.attachments[0].ip if a.attachments else None


def _svc(spec: ScenarioSpec, service_id: str) -> Any:
    return next(s for s in spec.services if s.service_id == service_id)


def _host_users(spec: ScenarioSpec, asset_id: str, sec: Secrets) -> str:
    """``user:password:privilege`` entries (``;``-separated) for local accounts on one host."""
    a = next(x for x in spec.assets if x.asset_id == asset_id)
    is_server = any(s.asset_id == asset_id for s in spec.services)
    out = []
    for i in sorted(spec.identities, key=lambda i: i.identity_id):
        on_host = asset_id in i.assigned_assets or (is_server and i.privilege == "admin")
        if (
            a.role in (AssetRole.WORKSTATION, AssetRole.ADMIN_WORKSTATION)
            and asset_id not in i.assigned_assets
        ):
            on_host = False
        if on_host:
            out.append(f"{i.username}:{sec.users[i.username]}:{i.privilege}")
    return ";".join(out)


def node_env(spec: ScenarioSpec, asset_id: str, sec: Secrets) -> dict[str, str]:
    """Everything a node's init script needs, as environment variables."""
    a = next(x for x in spec.assets if x.asset_id == asset_id)
    mine = [s for s in spec.services if s.asset_id == asset_id]
    env: dict[str, str] = {
        "IRIS_ROLE": a.role.value,
        "IRIS_DOMAIN": org_domain(spec),
        "IRIS_SERVICES": ",".join(
            f"{s.recipe}:{s.version}:{s.port}/{s.protocol}{':tls' if s.tls else ''}" for s in mine
        ),
        "IRIS_WEAKNESSES": ",".join(sorted({w.module for w in spec.weaknesses if w.asset_id == asset_id})),
        "IRIS_USERS": _host_users(spec, asset_id, sec),
        "IRIS_ROOT_PASSWORD": sec.root[asset_id],
    }
    recipes = {s.recipe for s in mine}
    if "nginx" in recipes:
        ups = [
            f"{_first_ip(spec, _svc(spec, d).asset_id)}:{_svc(spec, d).port}"
            for s in mine
            for d in s.depends_on
            if _svc(spec, d).recipe == "flask_shop"
        ]
        env["IRIS_UPSTREAM"] = ",".join(sorted(set(ups)))
    if "flask_shop" in recipes:
        dbs = [_svc(spec, d) for s in mine for d in s.depends_on if _svc(spec, d).recipe == "postgresql"]
        if dbs:
            db = sorted(dbs, key=lambda x: x.service_id)[0]
            env["IRIS_DB"] = f"{_first_ip(spec, db.asset_id)}:{db.port}:{DB_NAME}:svc_flask:{sec.app_db}"
    if "postgresql" in recipes:
        pg = next(s for s in mine if s.recipe == "postgresql")
        clients = sorted(
            {
                ip
                for s in spec.services
                if pg.service_id in s.depends_on and (ip := _first_ip(spec, s.asset_id)) is not None
            }
        )
        env.update(
            IRIS_DB_CLIENTS=",".join(clients),
            IRIS_DB_APP=f"{DB_NAME}:svc_flask:{sec.app_db}",
            IRIS_PG_PASSWORD=sec.postgres[asset_id],
        )
    if "unbound" in recipes:
        recs = []
        for x in spec.assets:
            for att in x.attachments[:1]:
                recs.append(f"{x.hostname}={att.ip}")
        env["IRIS_DNS_RECORDS"] = ";".join(sorted(recs))
        env["IRIS_DNS_CLIENTS"] = ",".join(z.subnet for z in spec.zones if z.kind.value != "internet")
    return env


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
    sec = scenario_secrets(spec)
    soc = build_soc(spec, build_reality(spec))
    domain = org_domain(spec)
    dns_asset = next((s.asset_id for s in spec.services if s.recipe == "unbound"), None)
    dns_ip = _first_ip(spec, dns_asset) if dns_asset else None
    builds: dict[str, dict[str, Any]] = {
        ROUTER_IMAGE: {"context": ROUTER_CONTEXT, "args": {}},
        EXTERNAL_IMAGE: {"context": EXTERNAL_CONTEXT, "args": {}},
        WAZUH_IMAGE: {"context": WAZUH_CONTEXT, "args": {}},
    }
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
            "init": True,  # PID 1 forwards SIGTERM: stop in ~1 s instead of the 20 s kill timeout
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
                environment={"IRIS_GATEWAY": router_ip[a.attachments[0].zone]},
                volumes=[f"{vol}:/var/ossec", f"./soc/local_rules.xml:{RULES_PATH}:ro"],
            )
        else:
            image = node_image(spec, a.asset_id, a.role, a.os_profile)
            builds[image] = {
                "context": NODE_CONTEXT,
                "args": {
                    "RECIPES": ",".join(sorted({x.recipe for x in spec.services if x.asset_id == a.asset_id}))
                },
            }
            env: dict[str, str] = {
                "IRIS_GATEWAY": router_ip[a.attachments[0].zone],
                **node_env(spec, a.asset_id, sec),
            }
            if dns_ip:  # the init script points resolv.conf at the enterprise resolver
                env["IRIS_DNS"] = dns_ip
            env.update(soc.env(a.asset_id))
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
            "init": True,
            "image": EXTERNAL_IMAGE,
            "hostname": f"host-{ext.ip.replace('.', '-')}",
            "container_name": f"{project}-{name}",
            "networks": {net_key[ext.zone]: {"ipv4_address": ext.ip}},
            "cap_add": ["NET_ADMIN"],
            "environment": {
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
        "virtual_time": VIRTUAL_TIME,
        "builds": {k: builds[k] for k in sorted(builds) if k in images},
        "domain": domain,
        "dns_server": dns_ip,
        "secrets": sec.to_dict(),
        "soc": soc.to_dict(),
    }
    rules = (repo_root() / "configs" / "soc" / "local_rules.xml").read_text(encoding="utf-8")
    meta["rules_sha256"] = sha256_hex(rules)
    return CompiledRange(
        project=project,
        compose=compose,
        router_nft=render_nft(spec),
        meta=meta,
        extra_files={"soc/local_rules.xml": rules},
    )
