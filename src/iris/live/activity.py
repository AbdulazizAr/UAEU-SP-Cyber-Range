"""Scripted activity for a recorded episode: ordinary business traffic plus a set of
labelled, known-detectable actions used to validate the SOC's detection coverage.

Every action carries ground truth: ``label`` (benign | malicious), the actor, the target,
an ATT&CK technique for malicious ones, and ``expect_rules`` (the Wazuh rule IDs that a
correctly configured SOC should raise). A malicious action is only scheduled when the
scenario truth actually contains the enabling weakness, so "what should be detected" is
grounded in the planted weakness ledger, never assumed. The exporter and the detection
check compare the alerts really produced against ``expect_rules``.

This module builds the plan and renders each action as a shell command run from an
external node; it does not run anything itself (that is the recorder's job, on a host
with Docker). The commands exercise the shop application's own endpoints over HTTP, the
same way a black-box SOC test would.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from typing import Any

from iris.contracts.spec import ScenarioSpec
from iris.generator.secrets import Secrets

ACTIVITY_VERSION = "activity-0.1.0"

#: weakness module -> (technique, rule ids a correct SOC raises, short name)
DETECTABLE = {
    "web.sqli_login": ("T1190", [100104, 100105], "sql_injection_login"),
    "web.path_traversal": ("T1190", [100112], "path_traversal"),
    # a successful IDOR lets the attacker read other customers' orders: it shows up as
    # data harvesting (100109), not denied-access enumeration (100107, which fires when the
    # flaw is absent).
    "web.idor_object": ("T1213", [100109], "order_harvesting"),
    "web.privilege_update": ("T1098", [100110], "self_service_admin"),
}
#: number of order IDs the harvesting action reads (over the 100109 frequency threshold of 15)
HARVEST_ORDERS = 22


@dataclass
class Action:
    step: int
    label: str  # benign | malicious
    actor: str  # external node kind: client | attacker
    target_asset: str
    name: str
    command: str  # shell run inside the actor container
    technique: str | None = None
    expect_rules: list[int] = field(default_factory=list)
    weakness_id: str | None = None

    def truth(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "label": self.label,
            "actor": self.actor,
            "target_asset": self.target_asset,
            "name": self.name,
            "technique": self.technique,
            "expect_rules": self.expect_rules,
            "weakness_id": self.weakness_id,
        }


@dataclass
class ActivityPlan:
    version: str
    actions: list[Action]

    @property
    def expected_detections(self) -> list[tuple[int, int]]:
        """(step, rule_id) pairs a correct SOC should produce."""
        return [(a.step, rid) for a in self.actions if a.label == "malicious" for rid in a.expect_rules]

    def truth(self) -> list[dict[str, Any]]:
        return [a.truth() for a in self.actions]


def _web_service(spec: ScenarioSpec) -> Any | None:
    return next((s for s in spec.services if s.recipe == "nginx"), None)


def _base_url(spec: ScenarioSpec, web: Any) -> str:
    a = next(x for x in spec.assets if x.asset_id == web.asset_id)
    ip = a.attachments[0].ip
    scheme = "https" if web.tls else "http"
    return f"{scheme}://{ip}:{web.port}"


def _curl(
    url: str, *, data: list[str] | None = None, cookie: str | None = None, out_code: bool = False
) -> str:
    parts = ["curl", "-sk", "-m", "8"]
    if out_code:
        parts += ["-o", "/dev/null", "-w", "%{http_code}"]
    if cookie:
        parts += ["-b", shlex.quote(cookie), "-c", shlex.quote(cookie)]
    for d in data or []:
        parts += ["--data-urlencode", shlex.quote(d)]
    parts.append(shlex.quote(url))
    return " ".join(parts)


def build_plan(spec: ScenarioSpec, secrets: Secrets, rng: Any) -> ActivityPlan:
    """Plan an episode: steady benign traffic, with labelled detectable actions where the
    matching weakness is planted. ``rng`` is a seeded ``random.Random`` (traffic sub-seed)."""
    actions: list[Action] = []
    web = _web_service(spec)
    client = next((e for e in spec.externals if e.kind == "client"), None)
    planted = {w.module: w for w in spec.weaknesses}
    step = 0

    def add(**kw: Any) -> None:
        nonlocal step
        step += 1
        actions.append(Action(step=step, **kw))

    if web is None or client is None:
        return ActivityPlan(ACTIVITY_VERSION, actions)
    base = _base_url(spec, web)
    cj = "/tmp/jar"

    # ---- benign business traffic (several ordinary customers)
    n_browse = rng.randint(6, 12)
    for _ in range(n_browse):
        pid = rng.randint(1, 12)
        add(
            label="benign",
            actor="client",
            target_asset=web.asset_id,
            name="browse_product",
            command=_curl(f"{base}/product/{pid}", out_code=True),
        )
    # a customer logs in and views their own orders (uses a real seeded account)
    add(
        label="benign",
        actor="client",
        target_asset=web.asset_id,
        name="customer_login",
        command=_curl(
            f"{base}/login", data=["username=customer03", "password=wrongbutbenign"], cookie=cj, out_code=True
        ),
    )
    add(
        label="benign",
        actor="client",
        target_asset=web.asset_id,
        name="browse_home",
        command=_curl(f"{base}/", out_code=True),
    )

    # ---- labelled detectable actions, only where the weakness is actually planted
    web_assets = {web.asset_id}
    app = next((s for s in spec.services if s.recipe == "flask_shop"), None)
    if app is not None:
        web_assets.add(app.asset_id)

    def planted_on_web(module: str) -> Any | None:
        w = planted.get(module)
        return w if w is not None and w.asset_id in web_assets else None

    def authed(user: str, *cmds: str) -> str:
        """Register a fresh account and sign in, then run the given requests in that session.
        The attacker needs a valid session to exploit IDOR or self-promotion; it cannot use
        the seeded customers' passwords, so it brings its own account."""
        register = _curl(f"{base}/register", data=[f"username={user}", "password=Str0ng!pw"], out_code=True)
        login = _curl(
            f"{base}/login", data=[f"username={user}", "password=Str0ng!pw"], cookie=cj, out_code=True
        )
        return " ; ".join([register, login, *cmds])

    if (w := planted_on_web("web.sqli_login")) is not None:
        tech, rules, name = DETECTABLE["web.sqli_login"]
        add(
            label="malicious",
            actor="attacker",
            target_asset=web.asset_id,
            name=name,
            technique=tech,
            expect_rules=rules,
            weakness_id=w.weakness_id,
            command=_curl(
                f"{base}/login", data=["username=admin' OR '1'='1' -- ", "password=x"], out_code=True
            ),
        )
    if (w := planted_on_web("web.path_traversal")) is not None:
        tech, rules, name = DETECTABLE["web.path_traversal"]
        add(
            label="malicious",
            actor="attacker",
            target_asset=web.asset_id,
            name=name,
            technique=tech,
            expect_rules=rules,
            weakness_id=w.weakness_id,
            command=_curl(f"{base}/download?file=../../../../etc/passwd", out_code=True),
        )
    if (w := planted_on_web("web.idor_object")) is not None:
        tech, rules, name = DETECTABLE["web.idor_object"]
        # with the flaw present, reading others' orders succeeds: many order views -> harvesting
        views = [_curl(f"{base}/orders/{i}", cookie=cj, out_code=True) for i in range(1, HARVEST_ORDERS + 1)]
        add(
            label="malicious",
            actor="attacker",
            target_asset=web.asset_id,
            name=name,
            technique=tech,
            expect_rules=rules,
            weakness_id=w.weakness_id,
            command=authed("harvester", *views),
        )
    if (w := planted_on_web("web.privilege_update")) is not None:
        tech, rules, name = DETECTABLE["web.privilege_update"]
        promote = _curl(f"{base}/profile/role", data=["role=admin"], cookie=cj, out_code=True)
        add(
            label="malicious",
            actor="attacker",
            target_asset=web.asset_id,
            name=name,
            technique=tech,
            expect_rules=rules,
            weakness_id=w.weakness_id,
            command=authed("escalator", promote),
        )

    # repeated failed logins (password guessing) are detectable on any shop
    guesses = " ; ".join(
        _curl(f"{base}/login", data=["username=admin", f"password=guess{i}"], out_code=True) for i in range(9)
    )
    add(
        label="malicious",
        actor="attacker",
        target_asset=web.asset_id,
        name="login_guessing",
        technique="T1110",
        expect_rules=[100102],
        weakness_id=None,
        command=guesses,
    )

    return ActivityPlan(ACTIVITY_VERSION, actions)
