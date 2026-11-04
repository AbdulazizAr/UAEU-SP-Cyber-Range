"""Build the concrete<->token mapping for a scenario so its telemetry can be abstracted
on recording and realised onto another enterprise on composition.

Tokens encode role and index (``IP_WEB_SERVER_1``, ``HOST_DATABASE_1``, ``USER_ADMIN_1``,
``ATTACKER_IP``, ``DOMAIN``), so the composer can substitute values of the same role in
the target enterprise and keep the activity coherent.
"""

from __future__ import annotations

from iris.contracts.spec import ScenarioSpec
from iris.fragments.model import token
from iris.generator.compiler import org_domain
from iris.generator.secrets import Secrets


def _priv_group(priv: str) -> str:
    return {"admin": "ADMIN", "power": "POWER", "service": "SERVICE"}.get(priv, "STANDARD")


def scenario_mapping(spec: ScenarioSpec, secrets: Secrets) -> tuple[list[tuple[str, str]], dict[str, str]]:
    """Return (concrete->token pairs for abstraction, token->role-hint for the composer)."""
    pairs: list[tuple[str, str]] = []
    hints: dict[str, str] = {}

    def bind(concrete: str, name: str, hint: str) -> None:
        if concrete:
            pairs.append((concrete, token(name)))
            hints[token(name)] = hint

    # assets: hostname and each IP, indexed per role
    role_n: dict[str, int] = {}
    for a in sorted(spec.assets, key=lambda a: a.asset_id):
        role = a.role.value.upper()
        role_n[role] = role_n.get(role, 0) + 1
        n = role_n[role]
        bind(a.hostname, f"HOST_{role}_{n}", f"{a.role.value}.hostname")
        for i, att in enumerate(a.attachments, start=1):
            bind(att.ip, f"IP_{role}_{n}" if i == 1 else f"IP_{role}_{n}_{i}", f"{a.role.value}.ip")

    # identities: username, indexed per privilege group
    priv_n: dict[str, int] = {}
    for ident in sorted(spec.identities, key=lambda i: i.identity_id):
        grp = _priv_group(ident.privilege)
        priv_n[grp] = priv_n.get(grp, 0) + 1
        bind(ident.username, f"USER_{grp}_{priv_n[grp]}", f"identity.{ident.privilege}")

    # externals
    for e in spec.externals:
        name = {"attacker": "ATTACKER_IP", "scanner": "SCANNER_IP", "client": "CLIENT_IP"}.get(e.kind)
        if name:
            bind(e.ip, name, f"external.{e.kind}")

    # passwords (so weak credentials in logs are abstracted, never leaked verbatim into fragments)
    for user, pw in sorted(secrets.users.items()):
        bind(pw, f"PW_{user.upper().replace('.', '_').replace('-', '_')}", "secret.password")
    for aid, pw in sorted(secrets.root.items()):
        bind(pw, f"PW_ROOT_{aid.replace('-', '_')}", "secret.password")

    bind(org_domain(spec), "DOMAIN", "org.domain")
    return pairs, hints


def target_bindings(spec: ScenarioSpec, secrets: Secrets, source_tokens: set[str]) -> dict[str, str]:
    """token -> concrete value in THIS enterprise, for every source token whose role/index
    this enterprise also has. Used by the composer to realise a fragment here."""
    pairs, _ = scenario_mapping(spec, secrets)
    local = {tok: concrete for concrete, tok in pairs}
    return {tok: local[tok] for tok in source_tokens if tok in local}


def unresolved(source_tokens: set[str], bindings: dict[str, str]) -> list[str]:
    """Source tokens this enterprise cannot bind (role/index absent): the fragment does not fit."""
    return sorted(source_tokens - set(bindings))
