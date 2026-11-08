"""Attack templates F1-F9 and their footprint executors (builder brief file 05 §2-3).

Executors are pure functions that render the *telemetry footprint* of an attack step — log
lines, flows, FIM changes, auth/app events — never runnable exploit code. A step's outcome is
decided by world state (is the enabling weakness present? is the path allowed?), not a coin
flip, so a success footprint (e.g. an Accepted login after failures) only appears when the
weakness is really there. ATT&CK ids are validated against the pinned v20.0 catalog at load.
"""

from __future__ import annotations

import random
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from iris.settings import repo_root
from iris.synth.activity.model import Footprint
from iris.synth.refs import attack_catalog
from iris.synth.soc.logs import emitters
from iris.synth.world import World

ATTACK_CATALOG_VERSION = "synth-attacks-0.1.0"

COMMON_WORDLIST = (
    "root",
    "admin",
    "test",
    "ubuntu",
    "oracle",
    "postgres",
    "ftp",
    "pi",
    "user",
    "guest",
    "git",
)


@dataclass(frozen=True)
class AttackTemplate:
    template_id: str
    family: str
    technique: str
    tactic: str
    executor: str
    target_roles: tuple[str, ...]
    weakness: str | None = None
    expected_rules: tuple[int, ...] = ()
    expected_detection: str = ""


@dataclass
class AttackContext:
    activity_id: str
    source_ip: str
    target_asset: str
    target_host: str
    target_ip: str
    target_port: int
    username: str
    start: datetime
    end: datetime
    success: bool
    skill: int  # 1..5 (higher = stealthier/slower)
    world: World


@lru_cache(maxsize=2)
def load_templates(root: Path | None = None) -> dict[str, AttackTemplate]:
    base = root if root is not None else repo_root() / "configs" / "catalog"
    raw = yaml.safe_load((base / "attacks.yaml").read_text(encoding="utf-8"))
    families = raw["families"]
    catalog = attack_catalog()
    templates: dict[str, AttackTemplate] = {}
    for tid, t in raw["templates"].items():
        technique = t["technique"]
        if technique not in catalog.techniques:
            raise ValueError(f"attack template {tid}: ATT&CK {technique} not in pinned catalog")
        templates[tid] = AttackTemplate(
            template_id=tid,
            family=t["family"],
            technique=technique,
            tactic=families[t["family"]]["tactic"],
            executor=t["executor"],
            target_roles=tuple(t["target_roles"]),
            weakness=t.get("weakness"),
            expected_rules=tuple(t.get("expected_rules", [])),
            expected_detection=t.get("expected_detection", ""),
        )
    return templates


def family_name(family: str, root: Path | None = None) -> str:
    base = root if root is not None else repo_root() / "configs" / "catalog"
    raw = yaml.safe_load((base / "attacks.yaml").read_text(encoding="utf-8"))
    return str(raw["families"][family]["name"])


# ---------------------------------------------------------------- footprint helpers


def _spread(ctx: AttackContext, n: int, rng: random.Random) -> list[datetime]:
    """n timestamps across the window; fast/regular for low skill, jittered for high skill."""
    span = max(1.0, (ctx.end - ctx.start).total_seconds())
    if ctx.skill >= 4:
        points = sorted(rng.uniform(0, span) for _ in range(n))  # low-and-slow, irregular
    else:
        step = span / (n + 1)
        points = [step * (i + 1) + rng.uniform(-step / 4, step / 4) for i in range(n)]
    # distinct timestamps (microsecond offset by index) so every footprint has a unique event id
    return [ctx.start + timedelta(seconds=max(0.0, p), microseconds=i) for i, p in enumerate(points)]


def _log(ctx: AttackContext, ts: datetime, program: str, line: str) -> Footprint:
    return Footprint(
        "raw_log",
        ts,
        {"asset_id": ctx.target_asset, "host": ctx.target_host, "program": program, "line": line},
        ctx.activity_id,
        ctx.target_asset,
    )


def _flow(ctx: AttackContext, ts: datetime, dport: int, **kw: Any) -> Footprint:
    data = {"src_ip": ctx.source_ip, "dst_ip": ctx.target_ip, "dst_port": dport, "proto": "tcp", **kw}
    return Footprint("flow", ts, data, ctx.activity_id, None)


def _fim(ctx: AttackContext, ts: datetime, path: str, event: str) -> Footprint:
    return Footprint(
        "fim",
        ts,
        {"asset_id": ctx.target_asset, "path": path, "event": event, "mode": "realtime"},
        ctx.activity_id,
        ctx.target_asset,
    )


def _auth(ctx: AttackContext, ts: datetime, success: bool, **kw: Any) -> Footprint:
    data = {
        "asset_id": ctx.target_asset,
        "account": ctx.username,
        "success": success,
        "src_ip": ctx.source_ip,
        **kw,
    }
    return Footprint("auth_event", ts, data, ctx.activity_id, ctx.target_asset)


def _app(ctx: AttackContext, ts: datetime, **kw: Any) -> Footprint:
    return Footprint(
        "app_event",
        ts,
        {"asset_id": ctx.target_asset, "src_ip": ctx.source_ip, **kw},
        ctx.activity_id,
        ctx.target_asset,
    )


# ---------------------------------------------------------------- executors (footprint only)


def ssh_bruteforce(ctx: AttackContext, rng: random.Random) -> list[Footprint]:
    n = rng.randint(8, 20)
    fps: list[Footprint] = []
    for i, ts in enumerate(_spread(ctx, n, rng)):
        user = rng.choice(COMMON_WORDLIST)
        pid = 2000 + i
        port = rng.randint(30000, 60000)
        fps.append(
            _log(ctx, ts, "sshd", emitters.ssh_failed(ts, ctx.target_host, pid, user, ctx.source_ip, port))
        )
        fps.append(
            _auth(
                ctx,
                ts,
                False,
                service="ssh",
                method="password",
                mfa_used=False,
                failure_reason="bad_password",
            )
        )
    if ctx.success:  # only when the weakness really makes a weak credential guessable
        ts = ctx.end - timedelta(seconds=2)
        fps.append(
            _log(
                ctx,
                ts,
                "sshd",
                emitters.ssh_accepted(
                    ts, ctx.target_host, 2999, ctx.username, ctx.source_ip, rng.randint(30000, 60000)
                ),
            )
        )
        fps.append(_auth(ctx, ts, True, service="ssh", method="password", mfa_used=False))
    return fps


def ssh_spray(ctx: AttackContext, rng: random.Random) -> list[Footprint]:
    users = rng.sample([*{*COMMON_WORDLIST, ctx.username}], k=min(6, len(set(COMMON_WORDLIST)) + 1))
    fps: list[Footprint] = []
    for user, ts in zip(users, _spread(ctx, len(users), rng), strict=False):
        fps.append(
            _log(
                ctx,
                ts,
                "sshd",
                emitters.ssh_failed(
                    ts,
                    ctx.target_host,
                    rng.randint(2000, 3000),
                    user,
                    ctx.source_ip,
                    rng.randint(30000, 60000),
                ),
            )
        )
        fps.append(_auth(ctx, ts, False, service="ssh", method="password", mfa_used=False))
    return fps


def web_exploit(ctx: AttackContext, rng: random.Random) -> list[Footprint]:
    # suspicious request *shapes* only (encoded markers), never a working payload
    probes = [
        ("/items?id=1%27", 500),
        ("/search?q=%27%20OR%20%271%27=%271", 403),
        ("/download?file=..%2f..%2fetc%2fpasswd", 403),
        ("/api/v1/user?id=5%27", 500),
    ]
    fps: list[Footprint] = []
    for (url, status), ts in zip(probes, _spread(ctx, len(probes), rng), strict=False):
        ua = rng.choice(emitters.USER_AGENTS)
        fps.append(
            _log(
                ctx,
                ts,
                "nginx",
                emitters.web_combined(
                    ts, ctx.target_host, "nginx", ctx.source_ip, "GET", url, status, rng.randint(200, 900), ua
                ),
            )
        )
        fps.append(_app(ctx, ts, service="web", method="GET", url=url, status=status, result="error"))
    if ctx.success:
        ts = ctx.end - timedelta(seconds=3)
        fps.append(_app(ctx, ts, service="web", method="POST", url="/upload", status=200, result="ok"))
        fps.append(_fim(ctx, ts, "/var/www/app/uploads/._shell.php", "added"))
    return fps


def idor_harvest(ctx: AttackContext, rng: random.Random) -> list[Footprint]:
    fps: list[Footprint] = []
    base = rng.randint(1000, 2000)
    for i, ts in enumerate(_spread(ctx, rng.randint(10, 25), rng)):
        oid = base + i  # sequential object ids, other customers' objects return 200
        fps.append(_app(ctx, ts, service="web", method="GET", url=f"/orders/{oid}", status=200, result="ok"))
    return fps


def privilege_abuse(ctx: AttackContext, rng: random.Random) -> list[Footprint]:
    ts = ctx.start + timedelta(seconds=5)
    line = emitters.sudo_command(
        ts, ctx.target_host, ctx.username, "root", "pts/1", "/home/" + ctx.username, "/bin/bash"
    )
    return [_log(ctx, ts, "sudo", line), _auth(ctx, ts, True, service="sudo", method="sudo", dstuser="root")]


def recon_scan(ctx: AttackContext, rng: random.Random) -> list[Footprint]:
    # flow-only: many destination ports, no host alert unless a signature matches (Phase 6)
    ports = rng.sample(range(1, 1024), k=rng.randint(20, 60))
    fps: list[Footprint] = []
    for port, ts in zip(ports, _spread(ctx, len(ports), rng), strict=False):
        fps.append(
            _flow(
                ctx,
                ts,
                port,
                bytes_toserver=rng.randint(40, 120),
                bytes_toclient=rng.randint(0, 60),
                pkts=rng.randint(1, 3),
                app="failed",
            )
        )
    return fps


def lateral_ssh(ctx: AttackContext, rng: random.Random) -> list[Footprint]:
    ts = ctx.start + timedelta(seconds=10)
    # an Accepted login from an internal host not normally used for admin
    line = emitters.ssh_accepted(
        ts, ctx.target_host, 3100, ctx.username, ctx.source_ip, rng.randint(30000, 60000), method="publickey"
    )
    return [
        _log(ctx, ts, "sshd", line),
        _auth(ctx, ts, True, service="ssh", method="publickey", mfa_used=False),
    ]


def exfiltration(ctx: AttackContext, rng: random.Random) -> list[Footprint]:
    ts0 = ctx.start + timedelta(seconds=5)
    big = rng.randint(50_000_000, 500_000_000)
    fps = [_fim(ctx, ts0, f"/tmp/.stage-{rng.randint(1000, 9999)}.tar.gz", "added")]
    fps.append(
        _flow(
            ctx,
            ctx.end - timedelta(seconds=10),
            443,
            bytes_toserver=big,
            bytes_toclient=rng.randint(1000, 5000),
            pkts=rng.randint(4000, 40000),
            app="tls",
        )
    )
    return fps


def persistence(ctx: AttackContext, rng: random.Random) -> list[Footprint]:
    kind = rng.choice(["authorized_keys", "cron"])
    ts = ctx.start + timedelta(seconds=8)
    if kind == "authorized_keys":
        return [_fim(ctx, ts, "/root/.ssh/authorized_keys", "modified")]
    return [_fim(ctx, ts, f"/etc/cron.d/{rng.choice(['sysupdate', 'logrotate2', 'mdm'])}", "added")]


def agent_disable(ctx: AttackContext, rng: random.Random) -> list[Footprint]:
    ts = ctx.start + timedelta(seconds=15)
    # the sensor goes dark: an agent-stop event, then silence (tests "no alert != safe")
    return [
        Footprint(
            "agent_event",
            ts,
            {"asset_id": ctx.target_asset, "event": "agent_stopped", "host": ctx.target_host},
            ctx.activity_id,
            ctx.target_asset,
        )
    ]


def insider_misuse(ctx: AttackContext, rng: random.Random) -> list[Footprint]:
    fps: list[Footprint] = []
    # valid credentials, no failures, unusual volume/time (subtle, context-dependent)
    for ts in _spread(ctx, rng.randint(15, 40), rng):
        fps.append(
            _app(
                ctx,
                ts,
                service="fileshare",
                method="READ",
                url=f"/share/dept-finance/doc{rng.randint(1, 999)}.xlsx",
                status=200,
                result="ok",
                identity=ctx.username,
            )
        )
    return fps


def c2_beacon(ctx: AttackContext, rng: random.Random) -> list[Footprint]:
    fps: list[Footprint] = []
    interval = rng.choice([30, 60, 120])
    t = ctx.start
    while t < ctx.end:
        jitter = rng.uniform(-0.2, 0.2) * interval
        fps.append(
            _flow(
                ctx,
                t,
                443,
                bytes_toserver=rng.randint(200, 600),
                bytes_toclient=rng.randint(100, 400),
                pkts=rng.randint(4, 10),
                app="tls",
            )
        )
        t += timedelta(seconds=interval + jitter)
    return fps


EXECUTORS: dict[str, Callable[[AttackContext, random.Random], list[Footprint]]] = {
    "ssh_bruteforce": ssh_bruteforce,
    "ssh_spray": ssh_spray,
    "web_exploit": web_exploit,
    "idor_harvest": idor_harvest,
    "privilege_abuse": privilege_abuse,
    "recon_scan": recon_scan,
    "lateral_ssh": lateral_ssh,
    "exfiltration": exfiltration,
    "persistence": persistence,
    "agent_disable": agent_disable,
    "insider_misuse": insider_misuse,
    "c2_beacon": c2_beacon,
}
