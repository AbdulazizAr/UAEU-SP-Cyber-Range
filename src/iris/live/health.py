"""Health gate: a deployed range must prove it works before anything is recorded.

The checks run during pre-roll, which is hidden and never exported:
1. containers: every expected container is running.
2. init: every node finished its init script with no FAIL step.
3. router: the policy is loaded and there is no default route (containment).
4. ports: every service listens on its port.
5. dns: an internal hostname resolves through the enterprise resolver.
6. app_db: the shop answers /health with the database up.
7. paths: allowed internet -> DMZ works; internet -> database is blocked.
8. egress: nothing reaches a real-internet address.
9. wazuh: the manager is ready, monitored hosts' agents are Active, unmonitored hosts
   have none.
10. canary: each monitored agent's syslog canary reaches the manager archives.
11. suricata: the sensor sees the canary connections, exactly one per connection after
    dedup.
12. weaknesses: every planted weakness is present, and spot checks show unplanted ones
    are absent.
"""

from __future__ import annotations

import json
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from iris.contracts.common import AssetRole
from iris.contracts.spec import ScenarioSpec
from iris.generator.eve import dedup
from iris.spikes.common import SpikeResult, docker_exec, wait_until
from iris.spikes.wazuh import manager_ready_from, parse_agent_list

Exec = Callable[[str, str], str]  # (container, shell command) -> stdout (never raises)
_SS = re.compile(r"^(tcp|udp)\s+\S+\s+\d+\s+\d+\s+(\S+):(\d+)\s", re.M)


def default_exec(container: str, cmd: str) -> str:
    return docker_exec(container, cmd, timeout=60, check=False)


def parse_ss(text: str) -> set[tuple[str, int]]:
    """``ss -Hltun`` output -> {(proto, port)}."""
    return {(m.group(1), int(m.group(3))) for m in _SS.finditer(text)}


def init_status(log_text: str) -> tuple[bool, list[str]]:
    """Node init log -> (finished, failed steps)."""
    lines = [
        ln for ln in log_text.splitlines() if ln.startswith(("node-init:", "router-init:", "external-init:"))
    ]
    ready = any(ln.endswith(": ready") or ": ready " in ln for ln in lines)
    return ready, [ln for ln in lines if " FAIL" in ln]


@dataclass
class Target:
    spec: ScenarioSpec
    project: str
    meta: dict[str, Any]

    def container(self, asset_id: str) -> str:
        a = next(x for x in self.spec.assets if x.asset_id == asset_id)
        return f"{self.project}-{a.hostname}"

    def external(self, kind: str) -> str | None:
        ext = next((e for e in self.spec.externals if e.kind == kind), None)
        return f"{self.project}-{ext.node_id.lower()}" if ext else None

    def by_role(self, role: AssetRole) -> list[Any]:
        return [a for a in self.spec.assets if a.role is role]

    def ip(self, asset_id: str) -> str:
        a = next(x for x in self.spec.assets if x.asset_id == asset_id)
        return a.attachments[0].ip

    def nodes(self) -> list[Any]:
        return [
            a
            for a in self.spec.assets
            if a.role not in (AssetRole.ROUTER_FIREWALL, AssetRole.IDS_SENSOR, AssetRole.SIEM)
        ]


#: switches that need a logged-in session to exercise are verified on the app's configuration
_ENV_FLAG = "tr '\\0' '\\n' < /proc/1/environ | grep -q 'IRIS_WEAKNESSES=.*{module}'"
WEAKNESS_PROBES: dict[str, str] = {  # module -> shell test on the host (exit 0 = present)
    "auth.ssh_password": "sshd -T 2>/dev/null | grep -qi '^passwordauthentication yes'",
    "auth.ssh_root_login": "sshd -T 2>/dev/null | grep -qi '^permitrootlogin yes'",
    "auth.shared_ssh_key": "grep -qf /opt/vendor/deploy_key.pub /root/.ssh/authorized_keys",
    "host.sudo_nopasswd": "grep -rqs NOPASSWD /etc/sudoers.d",
    "db.default_creds": (
        "PGPASSWORD=postgres psql -h 127.0.0.1 -U postgres -tAc 'select 1' 2>/dev/null | grep -q 1"
    ),
    "db.listen_all": "grep -qs '0.0.0.0/0' /etc/postgresql/*/main/pg_hba.conf",
    "tls.weak_config": "grep -qs 'TLSv1 ' /etc/nginx/conf.d/site.conf",
    "web.admin_exposed": "! grep -qs 'return 403' /etc/nginx/conf.d/site.conf",
    "web.sqli_login": (
        "curl -s -o /dev/null -w '%{http_code}' -X POST "
        "--data-urlencode \"username=x' OR '1'='1' --\" --data-urlencode 'password=x' "
        "http://127.0.0.1:{port}/login | grep -q 200"
    ),
    "web.path_traversal": (
        "curl -s -o /dev/null -w '%{http_code}' "
        "'http://127.0.0.1:{port}/download?file=../../../etc/hostname' | grep -q 200"
    ),
    "web.idor_object": _ENV_FLAG.format(module="web.idor_object"),
    "web.privilege_update": _ENV_FLAG.format(module="web.privilege_update"),
}
#: unplanted modules checked for absence when their service is present (catches leaks)
ABSENCE_SPOT_CHECKS = ("auth.ssh_password", "auth.ssh_root_login", "web.sqli_login", "web.path_traversal")


class HealthGate:
    def __init__(self, target: Target, run: Exec = default_exec) -> None:
        self.t = target
        self.run = run
        self.r = SpikeResult("health", "")

    def _ok(self, container: str, cmd: str) -> bool:
        return self.run(container, f"{cmd} && echo __OK__").strip().endswith("__OK__")

    # ---- checks

    def containers(self, running: dict[str, str]) -> None:
        expected = {
            self.t.container(a.asset_id) for a in self.t.spec.assets if a.role is not AssetRole.IDS_SENSOR
        }
        expected |= {f"{self.t.project}-{e.node_id.lower()}" for e in self.t.spec.externals}
        bad = sorted(n for n in expected if running.get(n) != "running")
        self.r.check(
            "containers.running", not bad, len(expected) - len(bad), f"not running: {bad}" if bad else ""
        )

    def init(self, logs: Callable[[str], str], timeout: float = 240) -> None:
        names = [self.t.container(a.asset_id) for a in self.t.nodes()]
        names.append(self.t.container(self.t.by_role(AssetRole.ROUTER_FIREWALL)[0].asset_id))
        pending = set(names)

        def all_ready() -> bool:
            for n in list(pending):
                if init_status(logs(n))[0]:
                    pending.discard(n)
            return not pending

        ok, secs = wait_until(all_ready, timeout=timeout, interval=3)
        fails = {n: init_status(logs(n))[1] for n in names}
        fails = {n: f for n, f in fails.items() if f}
        self.r.check("init.ready", ok, secs, f"pending: {sorted(pending)}" if pending else "")
        self.r.check("init.no_failed_steps", not fails, len(fails), json.dumps(fails)[:800] if fails else "")

    def router(self) -> None:
        rc = self.t.container(self.t.by_role(AssetRole.ROUTER_FIREWALL)[0].asset_id)
        rules = self.run(rc, "nft list ruleset")
        routes = self.run(rc, "ip route")
        self.r.check("router.policy_loaded", "table inet iris" in rules and "policy drop" in rules)
        self.r.check("router.no_default_route", "default" not in routes, routes.strip().splitlines()[:1])

    def ports(self) -> None:
        missing = []
        for s in self.t.spec.services:
            c = self.t.container(s.asset_id)
            if (s.protocol, s.port) not in parse_ss(self.run(c, "ss -Hltun")):
                missing.append(f"{s.service_id}:{s.recipe}:{s.port}/{s.protocol}")
        self.r.check("ports.listening", not missing, len(self.t.spec.services) - len(missing), str(missing))

    def dns(self) -> None:
        ws = (self.t.by_role(AssetRole.WORKSTATION) or self.t.nodes())[0]
        app = (self.t.by_role(AssetRole.APP_SERVER) or self.t.nodes())[0]
        out = self.run(self.t.container(ws.asset_id), f"getent hosts {app.hostname}")
        self.r.check("dns.internal_name_resolves", self.t.ip(app.asset_id) in out, out.strip()[:80])

    def app_db(self) -> None:
        for s in self.t.spec.services:
            if s.recipe == "flask_shop":
                out = self.run(self.t.container(s.asset_id), f"curl -s -m 5 http://127.0.0.1:{s.port}/health")
                self.r.check(f"app_db.{s.service_id}", '"db":"ok"' in out.replace(" ", ""), out.strip()[:80])

    def paths(self) -> None:
        client = self.t.external("client")
        web = next((s for s in self.t.spec.services if s.recipe == "nginx"), None)
        db = next((s for s in self.t.spec.services if s.recipe == "postgresql"), None)
        if client and web:
            scheme = "https" if web.tls else "http"
            code = self.run(
                client,
                f"curl -sk -o /dev/null -w '%{{http_code}}' -m 8 {scheme}://{self.t.ip(web.asset_id)}:{web.port}/",
            ).strip()
            self.r.check("paths.internet_to_web_allowed", code in {"200", "301", "302"}, code)
        if client and db:
            ok = self._ok(client, f"nc -z -w 3 {self.t.ip(db.asset_id)} {db.port}")
            self.r.check("paths.internet_to_db_blocked", not ok)

    def egress(self) -> None:
        node = self.t.container(self.t.nodes()[0].asset_id)
        ok = self._ok(node, "curl -s -m 4 -o /dev/null http://1.1.1.1/")
        self.r.check("egress.blocked", not ok)

    def wazuh(self, timeout: float = 240) -> None:
        siem = self.t.by_role(AssetRole.SIEM)[0]
        mgr = self.t.container(siem.asset_id)
        ok, secs = wait_until(
            lambda: manager_ready_from(self.run(mgr, "/var/ossec/bin/wazuh-control status"))[0],
            timeout=timeout,
        )
        self.r.check("wazuh.manager_ready", ok, secs)
        monitored = {a.hostname for a in self.t.nodes() if a.monitored}
        unmonitored = {a.hostname for a in self.t.nodes() if not a.monitored}

        def agents_ok() -> bool:
            listed = parse_agent_list(self.run(mgr, "/var/ossec/bin/agent_control -l"))
            return all(listed.get(h, ("", ""))[1].startswith("Active") for h in monitored)

        ok, secs = wait_until(agents_ok, timeout=timeout, interval=3)
        listed = parse_agent_list(self.run(mgr, "/var/ossec/bin/agent_control -l"))
        self.r.check("wazuh.agents_active", ok, secs, f"{len(monitored)} monitored")
        self.r.check("wazuh.blind_spots_have_no_agent", not (unmonitored & set(listed)), sorted(unmonitored))

    def canary(self, timeout: float = 180) -> None:
        siem = self.t.by_role(AssetRole.SIEM)[0]
        mgr = self.t.container(siem.asset_id)
        nonce = secrets.token_hex(4)
        monitored = [a for a in self.t.nodes() if a.monitored]
        seen: set[str] = set()
        t0 = time.monotonic()
        last_emit = -1e9
        while time.monotonic() - t0 < timeout and len(seen) < len(monitored):
            if time.monotonic() - last_emit >= 15:  # (re-)emit: an agent may still be restarting
                for a in monitored:
                    if a.hostname not in seen:
                        self.run(
                            self.t.container(a.asset_id),
                            f"logger -p auth.info -t healthcheck hc-{nonce}-{a.hostname}",
                        )
                last_emit = time.monotonic()
            time.sleep(2)
            archive = self.run(
                mgr, f"grep -o 'hc-{nonce}-[a-z0-9-]*' /var/ossec/logs/archives/archives.json | sort -u"
            )
            seen |= {line.split(f"hc-{nonce}-", 1)[1] for line in archive.split() if f"hc-{nonce}-" in line}
        missing = sorted({a.hostname for a in monitored} - seen)
        self.r.check(
            "canary.all_agents_seen", not missing, round(time.monotonic() - t0, 1), f"missing {missing}"
        )

    def suricata(self, sensor: str, n: int = 3) -> None:
        client = self.t.external("client")
        web = next((s for s in self.t.spec.services if s.recipe == "nginx"), None)
        if not client or not web:
            return
        ip = self.t.ip(web.asset_id)
        scheme = "https" if web.tls else "http"
        for _ in range(n):
            self.run(client, f"curl -sk -o /dev/null -m 5 {scheme}://{ip}:{web.port}/hc")
        kind = "tls" if web.tls else "http"
        events: list[dict[str, Any]] = []

        def seen_all() -> bool:
            events[:] = [
                json.loads(x)
                for x in self.run(sensor, "cat /var/log/suricata/eve.json").splitlines()
                if x.startswith("{")
            ]
            got = [e for e in dedup(events) if e.get("event_type") == kind and e.get("dest_ip") == ip]
            return len(got) >= n

        wait_until(seen_all, timeout=20, interval=1)
        raw = [e for e in events if e.get("event_type") == kind and e.get("dest_ip") == ip]
        clean = [e for e in dedup(events) if e.get("event_type") == kind and e.get("dest_ip") == ip]
        self.r.check(
            "suricata.canary_seen_once",
            n <= len(clean) <= len(raw),
            f"{len(raw)} raw -> {len(clean)} after dedup",
        )
        self.r.check("suricata.community_id", bool(clean) and all(e.get("community_id") for e in clean))

    def weaknesses(self) -> None:
        planted = {(w.module, w.asset_id) for w in self.t.spec.weaknesses}
        results: dict[str, bool] = {}
        for module, aid in sorted(planted):
            probe = WEAKNESS_PROBES.get(module)
            if probe is None:
                results[f"{module}@{aid}"] = False
                continue
            port = next(
                (s.port for s in self.t.spec.services if s.asset_id == aid and s.recipe == "flask_shop"), 8000
            )
            results[f"{module}@{aid}"] = self._ok(self.t.container(aid), probe.replace("{port}", str(port)))
        missing = sorted(k for k, ok in results.items() if not ok)
        self.r.check(
            "weaknesses.planted_present", not missing, len(results) - len(missing), f"missing {missing}"
        )
        leaks = []
        for s in self.t.spec.services:
            for module in ABSENCE_SPOT_CHECKS:
                recipe = "openssh" if module.startswith("auth.") else "flask_shop"
                if s.recipe != recipe or (module, s.asset_id) in planted:
                    continue
                probe = WEAKNESS_PROBES[module].replace("{port}", str(s.port))
                if self._ok(self.t.container(s.asset_id), probe):
                    leaks.append(f"{module}@{s.asset_id}")
        self.r.check("weaknesses.unplanted_absent", not leaks, len(leaks), f"leaks {leaks}")
        self.r.measure("weaknesses.verified", results)
