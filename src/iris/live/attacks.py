"""Attack family catalog (INPUT Part 4). Each labelled action belongs to a family and a
stage with an ATT&CK technique and a post-condition (what success looks like). The family
metadata feeds the oracle (classification and priority reference keys) and the ATT&CK
coverage report; it does not change how an action runs.

v1 executes two reachable families end to end: F1 (web application compromise) and F2
(credential access by password guessing). F4 (lateral movement) and F5 (collection and
exfiltration) are declared here with their ATT&CK mapping and weakness preconditions;
they need an internal foothold to launch and are enabled as the attack surface grows.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from iris.contracts.spec import ScenarioSpec
    from iris.live.activity import ActivityPlan

FAMILIES: dict[str, dict[str, Any]] = {
    "F1": {
        "name": "Web application compromise",
        "tactic": "initial-access/collection",
        "modules": ["web.sqli_login", "web.path_traversal", "web.idor_object", "web.privilege_update"],
        "active": True,
    },
    "F2": {
        "name": "Credential access (password guessing)",
        "tactic": "credential-access",
        "modules": [],  # detectable on any shop; needs no planted weakness
        "active": True,
    },
    "F4": {
        "name": "Lateral movement",
        "tactic": "lateral-movement",
        "modules": ["auth.ssh_password", "auth.ssh_root_login", "auth.shared_ssh_key", "host.sudo_nopasswd"],
        "active": False,
    },
    "F5": {
        "name": "Collection and exfiltration",
        "tactic": "collection/exfiltration",
        "modules": ["db.default_creds", "db.listen_all"],
        "active": False,
    },
}

#: action name -> (family, stage, post-condition the controller verifies)
ACTION_META: dict[str, tuple[str, str, str]] = {
    "sql_injection_login": ("F1", "exploit", "authenticated as another identity or a DB error raised"),
    "path_traversal": ("F1", "exploit", "a file outside the web root was returned"),
    "order_harvesting": ("F1", "collection", "orders belonging to other customers were read"),
    "self_service_admin": ("F1", "privilege-escalation", "the attacker's own account was elevated to admin"),
    "login_guessing": ("F2", "credential-access", "repeated failed logins from one source"),
}

MODULE_FAMILY = {m: fam for fam, meta in FAMILIES.items() for m in meta["modules"]}


def family_of_action(name: str) -> str | None:
    meta = ACTION_META.get(name)
    return meta[0] if meta else None


def annotate(plan: ActivityPlan) -> ActivityPlan:
    """Fill family/stage/postcondition on each malicious action from the catalog."""
    for a in plan.actions:
        if a.label == "malicious" and a.name in ACTION_META:
            a.family, a.stage, a.postcondition = ACTION_META[a.name]
    return plan


def applicable_families(spec: ScenarioSpec) -> dict[str, list[str]]:
    """Active families whose precondition this scenario meets -> the weakness ids involved."""
    planted = {w.module: w.weakness_id for w in spec.weaknesses}
    out: dict[str, list[str]] = {}
    for fam, meta in FAMILIES.items():
        if not meta["active"]:
            continue
        if fam == "F2":  # always applicable (needs no weakness)
            out[fam] = []
            continue
        ids = [planted[m] for m in meta["modules"] if m in planted]
        if ids:
            out[fam] = ids
    return out
