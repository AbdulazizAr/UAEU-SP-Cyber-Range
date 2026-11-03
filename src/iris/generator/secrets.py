"""Credentials of a live range: deterministic per scenario, hidden plane only.

Strong passwords are random (20 characters). A planted weakness makes the matching
credential weak, from a small list of real-world favourites:
- ``auth.ssh_password``: the first administrator's password.
- ``auth.ssh_root_login``: root's password on that host.
- ``db.default_creds``: postgres/postgres.
The secrets travel only in the compose file of the run directory and in hidden truth,
never in the visible plane.
"""

from __future__ import annotations

import random
import string
from dataclasses import dataclass, field

from iris.contracts.spec import ScenarioSpec
from iris.core.seeds import SeedSet

WEAK_PASSWORDS = ("Welcome1", "Password123", "changeme", "Summer2025!", "Qwerty123", "admin123", "P@ssw0rd")
ALPHABET = string.ascii_letters + string.digits


@dataclass
class Secrets:
    users: dict[str, str] = field(default_factory=dict)  # username -> password
    root: dict[str, str] = field(default_factory=dict)  # asset_id -> root password
    postgres: dict[str, str] = field(default_factory=dict)  # asset_id -> postgres superuser password
    app_db: str = ""  # application database role password
    weak: list[str] = field(default_factory=list)  # which credentials are weak ("user:x", "root:AST-..")

    def to_dict(self) -> dict[str, object]:
        return {
            "users": self.users,
            "root": self.root,
            "postgres": self.postgres,
            "app_db": self.app_db,
            "weak": self.weak,
        }


def _strong(rng: random.Random) -> str:
    return "".join(rng.choice(ALPHABET) for _ in range(20))


def scenario_secrets(spec: ScenarioSpec) -> Secrets:
    rng = SeedSet.from_dict(spec.seeds.model_dump()).stream("identity", "secrets")
    mods: dict[str, set[str]] = {}
    for w in spec.weaknesses:
        mods.setdefault(w.module, set()).add(w.asset_id)
    s = Secrets()
    admins = [i.username for i in spec.identities if i.privilege == "admin"]
    for ident in sorted(spec.identities, key=lambda i: i.identity_id):
        s.users[ident.username] = _strong(rng)
    if mods.get("auth.ssh_password") and admins:
        s.users[admins[0]] = rng.choice(WEAK_PASSWORDS)
        s.weak.append(f"user:{admins[0]}")
    for a in sorted(spec.assets, key=lambda a: a.asset_id):
        if a.asset_id in mods.get("auth.ssh_root_login", set()):
            s.root[a.asset_id] = rng.choice(WEAK_PASSWORDS)
            s.weak.append(f"root:{a.asset_id}")
        else:
            s.root[a.asset_id] = _strong(rng)
    for svc in spec.services:
        if svc.recipe != "postgresql":
            continue
        if svc.asset_id in mods.get("db.default_creds", set()):
            s.postgres[svc.asset_id] = "postgres"
            s.weak.append(f"postgres:{svc.asset_id}")
        else:
            s.postgres[svc.asset_id] = _strong(rng)
    s.app_db = _strong(rng)
    return s
