"""Periodic Wazuh modules derived from world state (builder brief file 04 §4): SCA, syscollector,
FIM baseline, agent status, manager health, rule metadata.

These are "one source, two views": syscollector packages equal the SBOM, and SCA results are
the visible evidence of the hidden planted weaknesses (a weakness surfaces only through the
SCA failure / open port / auth pattern it causes, never as a labelled weakness — that is what
makes inferring it a real ML task, contract §7). Each SCA check records the control it tests
(``org_controls``), so a "paper" control has visible counter-evidence (DC2 for D6).
"""

from __future__ import annotations

import random
from typing import Any

from iris.core.vclock import iso_z
from iris.synth.posture import InstalledPackage
from iris.synth.world import World

MODULES_VERSION = "synth-wazuh-modules-0.1.0"

# weakness module -> SCA check (id, short title, the control it tests). Short titles + our own
# wording only; no copyrighted CIS benchmark text is reproduced (brief file 04 §4).
_SCA_FOR_WEAKNESS: dict[str, tuple[str, str, str]] = {
    "auth.ssh_password": ("28001", "Ensure SSH password authentication is disabled", "CTRL-IAM-002"),
    "auth.ssh_root_login": ("28002", "Ensure SSH PermitRootLogin is set to no", "CTRL-IAM-004"),
    "auth.shared_ssh_key": ("28003", "Ensure SSH host keys are unique per host", "CTRL-IAM-005"),
    "host.sudo_nopasswd": ("28004", "Ensure sudo requires a password (no NOPASSWD)", "CTRL-ACC-003"),
    "db.default_creds": ("28005", "Ensure database default credentials are changed", "CTRL-IAM-003"),
    "db.listen_all": ("28006", "Ensure the database listens only on required interfaces", "CTRL-NET-002"),
    "tls.weak_config": ("28007", "Ensure only strong TLS versions and ciphers are enabled", "CTRL-CRY-001"),
    "web.admin_exposed": ("28008", "Ensure admin interfaces are not internet-exposed", "CTRL-NET-003"),
    "smb.anonymous_share": ("28009", "Ensure file shares require authentication", "CTRL-ACC-002"),
    "ldap.anonymous_bind": ("28010", "Ensure the directory disallows anonymous bind", "CTRL-ACC-004"),
    "mail.open_relay": ("28011", "Ensure the mail server is not an open relay", "CTRL-NET-004"),
    "backup.unauth_repo": ("28012", "Ensure backup repositories require authentication", "CTRL-ACC-005"),
}


def sca_results(world: World, asset_id: str) -> list[dict[str, Any]]:
    """CIS-style SCA results for one host: the planted weaknesses fail their check; the rest pass.

    Only checks applicable to the host's services are emitted (a DB check is meaningless on a
    web host)."""
    from iris.generator.catalog import load_catalog

    recipes = {s.recipe for s in world.services_by_asset.get(asset_id, [])}
    present_modules = {w.module for w in world.weaknesses_by_asset.get(asset_id, [])}
    cat = load_catalog()
    out: list[dict[str, Any]] = []
    for module, (check_id, title, control) in sorted(_SCA_FOR_WEAKNESS.items()):
        meta = cat.weaknesses.get(module)
        if meta is None or meta["recipe"] not in recipes:
            continue  # not applicable on this host
        failed = module in present_modules
        out.append(
            {
                "policy": "org_baseline",
                "policy_id": "cis_linux_org",
                "check_id": check_id,
                "title": title,
                "result": "failed" if failed else "passed",
                "org_controls": [control],
            }
        )
    return out


def syscollector(world: World, asset_id: str, installed: list[InstalledPackage]) -> dict[str, Any]:
    """Per-agent inventory: OS, interfaces, packages (== SBOM), listening ports, processes.

    Ports include weakness-induced listeners (e.g. a database bound to 0.0.0.0), which is
    visible evidence of the ``db.listen_all`` weakness."""
    asset = world.assets[asset_id]
    services = world.services_by_asset.get(asset_id, [])
    ports: list[dict[str, Any]] = []
    listen_all = world.weakness("db.listen_all", asset_id) is not None
    for s in services:
        bind = "0.0.0.0" if (s.recipe == "postgresql" and listen_all) else _default_bind(world, asset_id)
        ports.append(
            {
                "local_ip": bind,
                "local_port": s.port,
                "protocol": s.protocol,
                "process": s.recipe,
                "state": "listening",
            }
        )
    packages = [{"name": ip.package.purl_name, "version": ip.version} for ip in installed]
    processes = sorted({s.recipe for s in services} | {"sshd", "systemd", "cron"})
    return {
        "agent": asset.hostname,
        "os": {"profile": asset.os_profile, "platform": asset.os_profile.split("-")[0]},
        "interfaces": [{"name": "eth0", "ipv4": att.ip} for att in asset.attachments],
        "packages": sorted(packages, key=lambda p: p["name"]),
        "ports": sorted(ports, key=lambda p: p["local_port"]),
        "processes": [{"name": p} for p in processes],
    }


def _default_bind(world: World, asset_id: str) -> str:
    asset = world.assets[asset_id]
    return asset.attachments[0].ip if asset.attachments else "127.0.0.1"


def fim_baseline(world: World, asset_id: str, rng: random.Random) -> list[dict[str, Any]]:
    """Benign file-integrity events a host produces between scans (package updates, logrotate).

    Attack-driven FIM (authorized_keys, cron, new SUID) is added by the attack executors, so
    this is the benign baseline a model must distinguish from (brief file 04 §4)."""
    paths = [
        ("/etc/ld.so.cache", "modified"),
        ("/usr/share/misc/magic.mgc", "modified"),
        ("/var/lib/dpkg/status", "modified"),
    ]
    out: list[dict[str, Any]] = []
    for path, event in paths:
        if rng.random() < 0.5:
            out.append(
                {
                    "path": path,
                    "event": event,
                    "mode": "scheduled",
                    "attrs": {"size": rng.randint(1000, 500000), "perm": "rw-r--r--", "uid": "0", "gid": "0"},
                }
            )
    return out


def agents_status(world: World) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for aid in sorted(world.assets):
        asset = world.assets[aid]
        if aid not in world.soc.sources and not asset.monitored:
            continue
        monitored = world.is_monitored(aid)
        out.append(
            {
                "name": asset.hostname,
                "ip": asset.attachments[0].ip if asset.attachments else None,
                "os": asset.os_profile,
                "status": "active" if monitored else "disconnected",
                "group": "default",
            }
        )
    return out


def manager_health(world: World) -> dict[str, Any]:
    return {
        "manager": "wazuh-manager",
        "version": "4.14.9",
        "queue_usage": 0.03,
        "events_dropped": 0,
        "restarts": 0,
        "agents_active": sum(world.is_monitored(a) for a in world.assets),
    }


def rule_metadata(loaded_rule_ids: list[int], rules: dict[int, Any], library_version: str) -> dict[str, Any]:
    """Loaded rules for the scenario (ids/levels/groups/MITRE), for evaluation & explanation."""
    entries = []
    for rid in sorted(set(loaded_rule_ids)):
        r = rules.get(rid)
        if r is None:
            continue
        entries.append(
            {
                "id": r.id,
                "level": r.level,
                "description": r.description,
                "groups": list(r.groups),
                "mitre": list(r.mitre),
                "stock_or_custom": "custom" if r.id >= 100000 else "stock",
            }
        )
    return {"wazuh_version": "4.14.9", "library_version": library_version, "rules": entries}


def iso_now(dt: Any) -> str:
    return iso_z(dt)
