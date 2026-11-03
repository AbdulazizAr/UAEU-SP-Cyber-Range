"""SOC profile: what the SOC really collects, and what it believes it collects (INPUT Part 3).

Reality drives the live range: the compiler turns it into per-node agent configuration
(log sources, FIM, SCA). Belief is the visible ``soc/soc_inventory.json``: the standard
source set per role, plus coverage statements. Where belief and reality differ, a hidden
SOC gap is recorded. That gap is detectable from telemetry (a source that should report
never does), so it is DC2.

Coupling to GRC reality:
- FIM follows CTRL-LOG-003 (FIM on critical hosts): implemented means on; partial
  means on for about half the hosts; missing means off.
- The SCA baseline follows CTRL-CFG-001 (secure baseline configuration).
- The coverage statements repeat the recorded control state, so a "paper" control
  becomes a false SOC belief.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from typing import Any

from iris.contracts.common import AssetRole
from iris.contracts.spec import ScenarioSpec
from iris.contracts.visible import SocInventory
from iris.core.seeds import SeedSet
from iris.generator.grc.reality import GrcReality

SOC_VERSION = "soc-0.1.0"
WAZUH_VERSION = "4.14.9"
RULESET_VERSION = "wazuh-4.14.9+org-rules-0.1.1"
BASE_SOURCES = ("auth", "syslog")
RECIPE_SOURCES = {
    "nginx": ("nginx_access", "nginx_error"),
    "postgresql": ("postgres",),
    "flask_shop": ("shop_app",),
}
SOURCE_PATHS = {  # source -> (Wazuh log_format, path)
    "auth": ("syslog", "/var/log/auth.log"),
    "syslog": ("syslog", "/var/log/syslog"),
    "nginx_access": ("apache", "/var/log/nginx/access.log"),
    "nginx_error": ("apache", "/var/log/nginx/error.log"),
    "postgres": ("syslog", "/var/log/postgresql/postgresql-*-main.log"),
    "shop_app": ("json", "/var/log/shop/app.log"),
}
COLLECT_P = {"high": 0.97, "medium": 0.88, "low": 0.70}  # each non-auth source really collected
ALERT_RETENTION = {"high": 365, "medium": 180, "low": 90}
ARCHIVES_P = {"high": 1.0, "medium": 0.5, "low": 0.0}
NON_NODE = {AssetRole.ROUTER_FIREWALL, AssetRole.IDS_SENSOR, AssetRole.SIEM}


@dataclass
class SocGap:
    gap_id: str
    kind: str  # source_not_collected | fim_believed_on | sca_believed_on
    asset_id: str
    detail: str
    detectability: str = "DC2"


@dataclass
class SocProfile:
    version: str
    sources: dict[str, list[str]]  # asset_id -> sources really collected (monitored hosts)
    believed: dict[str, list[str]]  # asset_id -> sources the SOC configuration lists
    fim: dict[str, bool]
    sca: dict[str, bool]
    alert_retention_days: int
    archives_retained: bool
    servers: list[str] = field(default_factory=list)  # monitored hosts that run services (SCA scope)
    gaps: list[SocGap] = field(default_factory=list)

    def env(self, asset_id: str) -> dict[str, str]:
        """Agent configuration for one node (empty for unmonitored hosts)."""
        if asset_id not in self.sources:
            return {}
        return {
            "IRIS_LOGSOURCES": ";".join(
                f"{SOURCE_PATHS[s][0]}|{SOURCE_PATHS[s][1]}" for s in self.sources[asset_id]
            ),
            "IRIS_FIM": "1" if self.fim[asset_id] else "0",
            "IRIS_SCA": "1" if self.sca[asset_id] else "0",
        }

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _standard(spec: ScenarioSpec, asset_id: str) -> list[str]:
    out = list(BASE_SOURCES)
    for s in spec.services:
        if s.asset_id == asset_id:
            out += [x for x in RECIPE_SOURCES.get(s.recipe, ()) if x not in out]
    return out


def _state(reality: GrcReality, cid: str) -> str:
    c = reality.controls.get(cid)
    return c.state if c else "missing"


def build_soc(spec: ScenarioSpec, reality: GrcReality, seeds: SeedSet | None = None) -> SocProfile:
    seeds = seeds or SeedSet.from_dict(spec.seeds.model_dump())
    rng = seeds.stream("monitoring", "soc_profile")
    maturity = spec.organization.maturity.value
    fim_state, sca_state = _state(reality, "CTRL-LOG-003"), _state(reality, "CTRL-CFG-001")
    p = SocProfile(
        version=SOC_VERSION,
        sources={},
        believed={},
        fim={},
        sca={},
        alert_retention_days=ALERT_RETENTION[maturity],
        archives_retained=rng.random() < ARCHIVES_P[maturity],
    )
    for a in sorted(spec.assets, key=lambda a: a.asset_id):
        if a.role in NON_NODE or not a.monitored:
            continue
        std = _standard(spec, a.asset_id)
        p.believed[a.asset_id] = std
        real = [s for s in std if s == "auth" or rng.random() < COLLECT_P[maturity]]
        p.sources[a.asset_id] = real
        for s in std:
            if s not in real:
                p.gaps.append(
                    SocGap(
                        f"S-{len(p.gaps) + 1:03d}", "source_not_collected", a.asset_id, f"{s} not forwarded"
                    )
                )
        p.fim[a.asset_id] = {"implemented": True, "partial": rng.random() < 0.5}.get(fim_state, False)
        is_server = any(s.asset_id == a.asset_id for s in spec.services)
        if is_server:
            p.servers.append(a.asset_id)
        p.sca[a.asset_id] = is_server and {"implemented": True, "partial": rng.random() < 0.5}.get(
            sca_state, False
        )
    return p


def soc_inventory(
    spec: ScenarioSpec, profile: SocProfile, recorded_controls: Mapping[str, Any] | None = None
) -> SocInventory:
    """Visible ``soc/soc_inventory.json``: the roster and configuration the SOC believes in."""
    by_id = {a.asset_id: a for a in spec.assets}
    by_role: dict[str, list[str]] = {}
    for aid, sources in profile.believed.items():
        role = by_id[aid].role.value
        by_role[role] = sorted(set(by_role.get(role, [])) | set(sources))
    rec = recorded_controls or {}
    statements = ["All monitored hosts forward authentication logs to the SIEM"]
    if any("nginx_access" in s for s in profile.believed.values()):
        statements.append("Web servers forward access and error logs")
    if any("postgres" in s for s in profile.believed.values()):
        statements.append("Database connection logging is forwarded to the SIEM")
    if rec.get("CTRL-LOG-003") in ("implemented", "partial"):
        statements.append("File integrity monitoring covers critical servers")
    if rec.get("CTRL-CFG-001") in ("implemented", "partial"):
        statements.append("Servers are assessed against the internal configuration baseline")
    return SocInventory(
        wazuh_version=WAZUH_VERSION,
        agents=[
            {"name": by_id[aid].hostname, "os": by_id[aid].os_profile, "group": "default"}
            for aid in sorted(profile.sources)
        ],
        groups={"default": sorted(by_id[aid].hostname for aid in profile.sources)},
        log_sources_by_role=by_role,
        ruleset_version=RULESET_VERSION,
        loaded_rule_files=["0010-rules_config.xml", "0095-sshd_rules.xml", "local_rules.xml"],
        fim_scope={"default": ["/etc"]},
        sca_policies=["org_baseline"] if rec.get("CTRL-CFG-001") in ("implemented", "partial") else [],
        retention_days={
            "alerts": profile.alert_retention_days,
            "archives": 30 if profile.archives_retained else 0,
        },
        archives_retained=profile.archives_retained,
        coverage_statements=statements,
    )


def belief_gaps(profile: SocProfile, recorded_controls: Mapping[str, Any]) -> list[SocGap]:
    """Hidden gaps where the recorded control claims coverage the SOC does not have."""
    gaps = list(profile.gaps)
    n = len(gaps)
    for cid, kind, real in (
        ("CTRL-LOG-003", "fim_believed_on", profile.fim),
        ("CTRL-CFG-001", "sca_believed_on", profile.sca),
    ):
        if recorded_controls.get(cid) == "implemented":
            for aid, on in sorted(real.items()):
                if not on and (kind == "fim_believed_on" or aid in profile.servers):
                    n += 1
                    gaps.append(
                        SocGap(f"S-{n:03d}", kind, aid, f"{cid} recorded implemented; not active on host")
                    )
    return gaps
