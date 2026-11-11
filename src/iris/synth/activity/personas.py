"""Benign behaviour and hard negatives (builder brief file 05 §4).

Benign activity is the dominant majority of records. Hard negatives are benign activities
whose footprint overlaps an attack family (an authorized scan looks like recon; a nightly
bulk backup looks like exfiltration; an admin's sudo looks like privilege abuse; a user
fat-fingering their password then succeeding looks like a brute force). Each carries a benign
context an attack lacks — a known identity, an in-hours schedule, a documented source — which
is exactly the signal the model must learn, so a volume/rate/time classifier alone cannot
separate the twin from the attack (brief T-A4).
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta

from iris.synth.activity.model import Footprint
from iris.synth.soc.logs import emitters
from iris.synth.world import World


def _times(start: datetime, end: datetime, n: int, rng: random.Random) -> list[datetime]:
    span = max(1.0, (end - start).total_seconds())
    offs = sorted(rng.uniform(0, span) for _ in range(n))
    # distinct timestamps (microsecond offset by index) so every footprint gets a unique event id
    return [start + timedelta(seconds=o, microseconds=i) for i, o in enumerate(offs)]


def web_browsing(
    world: World, web_asset: str, src_ip: str, start: datetime, end: datetime, rng: random.Random
) -> list[Footprint]:
    host = world.assets[web_asset].hostname
    urls = ["/", "/products", "/cart", "/account", "/search?q=shoes", "/api/v1/items", "/static/app.css"]
    fps: list[Footprint] = []
    for ts in _times(start, end, rng.randint(6, 20), rng):
        url = rng.choice(urls)
        # legitimate browsing is overwhelmingly 2xx/3xx; an occasional 404 (dead link) is normal
        # background noise and realistically trips Wazuh rule 31101, but it should be rare so
        # clean episodes are mostly quiet (not a flood of benign level-5 web alerts).
        status = rng.choices([200, 200, 200, 304, 404], weights=[60, 20, 12, 7, 1])[0]
        ua = rng.choice(emitters.USER_AGENTS[:4])
        line = emitters.web_combined(
            ts, host, "nginx", src_ip, "GET", url, status, rng.randint(200, 9000), ua
        )
        fps.append(
            Footprint(
                "raw_log",
                ts,
                {"asset_id": web_asset, "host": host, "program": "nginx", "line": line},
                None,
                web_asset,
            )
        )
    return fps


def admin_ssh(
    world: World,
    target_asset: str,
    user: str,
    src_ip: str,
    start: datetime,
    end: datetime,
    rng: random.Random,
    *,
    typos: bool = False,
) -> list[Footprint]:
    """A legitimate admin SSH session. With ``typos`` it mistypes the password a couple of times
    then succeeds — a hard-negative twin of F1 credential access."""
    host = world.assets[target_asset].hostname
    fps: list[Footprint] = []
    ts0 = start + timedelta(seconds=rng.uniform(0, 30))
    if typos:
        for i in range(rng.randint(1, 3)):
            t = ts0 + timedelta(seconds=i * 4)
            fps.append(
                Footprint(
                    "raw_log",
                    t,
                    {
                        "asset_id": target_asset,
                        "host": host,
                        "program": "sshd",
                        "line": emitters.ssh_failed(
                            t, host, 1500 + i, user, src_ip, rng.randint(30000, 60000)
                        ),
                    },
                    None,
                    target_asset,
                )
            )
    t = ts0 + timedelta(seconds=15)
    fps.append(
        Footprint(
            "raw_log",
            t,
            {
                "asset_id": target_asset,
                "host": host,
                "program": "sshd",
                "line": emitters.ssh_accepted(
                    t, host, 1599, user, src_ip, rng.randint(30000, 60000), method="publickey"
                ),
            },
            None,
            target_asset,
        )
    )
    return fps


def authorized_scan(
    world: World, target_asset: str, scanner_ip: str, start: datetime, end: datetime, rng: random.Random
) -> list[Footprint]:
    """The internal vulnerability scanner sweeping ports — near-identical traffic to F4 recon,
    but from the documented scanner asset (hard negative)."""
    ip = (
        world.assets[target_asset].attachments[0].ip if world.assets[target_asset].attachments else "10.0.0.9"
    )
    fps: list[Footprint] = []
    for port, ts in zip(
        rng.sample(range(1, 1024), k=rng.randint(20, 50)), _times(start, end, 50, rng), strict=False
    ):
        fps.append(
            Footprint(
                "flow",
                ts,
                {
                    "src_ip": scanner_ip,
                    "dst_ip": ip,
                    "dst_port": port,
                    "proto": "tcp",
                    "bytes_toserver": rng.randint(40, 120),
                    "bytes_toclient": rng.randint(0, 60),
                    "pkts": rng.randint(1, 3),
                    "app": "failed",
                },
                None,
                None,
            )
        )
    return fps


def nightly_backup(
    world: World, backup_asset: str, db_ip: str, start: datetime, end: datetime, rng: random.Random
) -> list[Footprint]:
    """Bulk backup transfer — large outbound volume, a hard-negative twin of F6 exfiltration."""
    ip = (
        world.assets[backup_asset].attachments[0].ip if world.assets[backup_asset].attachments else "10.0.0.8"
    )
    big = rng.randint(80_000_000, 800_000_000)
    ts = start + timedelta(seconds=rng.uniform(0, 60))
    return [
        Footprint(
            "flow",
            ts,
            {
                "src_ip": db_ip,
                "dst_ip": ip,
                "dst_port": 8000,
                "proto": "tcp",
                "bytes_toserver": big,
                "bytes_toclient": rng.randint(1000, 4000),
                "pkts": rng.randint(5000, 40000),
                "app": "backup",
            },
            None,
            None,
        )
    ]


def admin_sudo(
    world: World, target_asset: str, user: str, start: datetime, end: datetime, rng: random.Random
) -> list[Footprint]:
    """Legitimate privileged administration — a hard-negative twin of F3 sudo abuse."""
    host = world.assets[target_asset].hostname
    ts = start + timedelta(seconds=rng.uniform(0, 120))
    cmd = rng.choice(
        ["/usr/bin/apt-get upgrade", "/bin/systemctl restart nginx", "/usr/bin/journalctl -u app"]
    )
    line = emitters.sudo_command(ts, host, user, "root", "pts/0", "/home/" + user, cmd)
    return [
        Footprint(
            "raw_log",
            ts,
            {"asset_id": target_asset, "host": host, "program": "sudo", "line": line},
            None,
            target_asset,
        )
    ]


def machine_noise(
    world: World, asset_id: str, start: datetime, end: datetime, rng: random.Random
) -> list[Footprint]:
    host = world.assets[asset_id].hostname
    units = [
        "cron.service",
        "systemd-timesyncd.service",
        "apt-daily.service",
        "logrotate.service",
        "man-db.service",
        "fstrim.service",
    ]
    actions = [
        "Started",
        "Succeeded",
        "Deactivated successfully",
        "Finished daily apt download activities",
        "Consumed 1.284s CPU time",
        "Reached target timers, reloaded system logger configuration",
    ]
    fps: list[Footprint] = []
    for ts in _times(start, end, rng.randint(2, 8), rng):
        line = emitters.systemd_unit(ts, host, rng.choice(units), rng.choice(actions))
        fps.append(
            Footprint(
                "raw_log",
                ts,
                {"asset_id": asset_id, "host": host, "program": "systemd", "line": line},
                None,
                asset_id,
            )
        )
    return fps


def routine_ssh(
    world: World,
    target_asset: str,
    user: str,
    src_ip: str,
    start: datetime,
    end: datetime,
    rng: random.Random,
) -> list[Footprint]:
    """Normal admin/service SSH sessions (clean key logins). Gives benign episodes the same ssh
    record types attacks have, so surface form (length/timing) doesn't fingerprint attacks."""
    host = world.assets[target_asset].hostname
    fps: list[Footprint] = []
    for ts in _times(start, end, rng.randint(1, 4), rng):
        pid = rng.randint(1200, 1800)
        line = emitters.ssh_accepted(
            ts, host, pid, user, src_ip, rng.randint(30000, 60000), method="publickey"
        )
        fps.append(
            Footprint(
                "raw_log",
                ts,
                {"asset_id": target_asset, "host": host, "program": "sshd", "line": line},
                None,
                target_asset,
            )
        )
        fps.append(
            Footprint(
                "auth_event",
                ts,
                {
                    "asset_id": target_asset,
                    "account": user,
                    "success": True,
                    "src_ip": src_ip,
                    "service": "ssh",
                    "method": "publickey",
                    "mfa_used": True,
                },
                None,
                target_asset,
            )
        )
    return fps


def app_traffic(
    world: World,
    target_asset: str,
    user: str,
    src_ip: str,
    start: datetime,
    end: datetime,
    rng: random.Random,
) -> list[Footprint]:
    """Normal application/database use (200-OK API and query events). Benign app-event volume the
    model must not confuse with insider misuse."""
    urls = [
        "/api/v1/orders?status=open&page=3&limit=50",
        "/api/v1/items/48213/details",
        "/api/v1/profile?fields=name,email,roles",
        "/healthz",
        "/api/v1/search?q=invoice&from=2026-01-01&sort=desc",
        "/static/js/app.bundle.min.js",
    ]
    fps: list[Footprint] = []
    for ts in _times(start, end, rng.randint(3, 12), rng):
        fps.append(
            Footprint(
                "app_event",
                ts,
                {
                    "asset_id": target_asset,
                    "src_ip": src_ip,
                    "service": "web",
                    "method": rng.choice(["GET", "GET", "POST"]),
                    "url": rng.choice(urls),
                    "status": rng.choices([200, 200, 200, 304, 404], weights=[6, 3, 3, 2, 1])[0],
                    "result": "ok",
                    "identity": user,
                },
                None,
                target_asset,
            )
        )
    return fps


def service_flows(
    world: World, src_ip: str, dst_asset: str, start: datetime, end: datetime, rng: random.Random
) -> list[Footprint]:
    """Normal service-to-service network flows (DB connections, API calls). Benign flow records so
    flows are not an attack-only record type."""
    dst_ip = world.assets[dst_asset].attachments[0].ip if world.assets[dst_asset].attachments else "10.0.0.5"
    port = rng.choice([443, 5432, 8080, 3306, 6379])
    fps: list[Footprint] = []
    for ts in _times(start, end, rng.randint(3, 10), rng):
        fps.append(
            Footprint(
                "flow",
                ts,
                {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": port,
                    "proto": "tcp",
                    "bytes_toserver": rng.randint(200, 8000),
                    "bytes_toclient": rng.randint(200, 40000),
                    "pkts": rng.randint(6, 40),
                    "app": "tls" if port == 443 else "flow",
                },
                None,
                None,
            )
        )
    return fps
