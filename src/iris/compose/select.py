"""Choose fragments for a composed scenario.

Rules (decisions.md "Architecture", "Splits"):

* A scenario of group G is built only from fragments whose group is in G's allowed set
  (its own group for in-distribution; the composer is handed the allowed set).
* Every token a fragment carries must bind to a value of the same role on the target
  enterprise, or the fragment does not fit and is skipped.
* A fragment's ``requires`` placement constraints must hold on the target.
* Reuse of any one fragment is capped across the whole dataset; a shared
  :class:`ReuseLedger` enforces the cap as scenarios are composed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from iris.contracts.spec import ScenarioSpec
from iris.fragments.mapping import target_bindings, unresolved
from iris.fragments.model import Fragment
from iris.generator.secrets import Secrets


@dataclass
class ReuseLedger:
    """How many times each fragment has been placed, with a per-fragment cap."""

    cap: int = 5
    used: dict[str, int] = field(default_factory=dict)

    def available(self, fragment_id: str) -> bool:
        return self.used.get(fragment_id, 0) < self.cap

    def take(self, fragment_id: str) -> None:
        self.used[fragment_id] = self.used.get(fragment_id, 0) + 1


def _web_recipes(spec: ScenarioSpec) -> set[str]:
    return {s.recipe for s in spec.services}


def requirements_met(fragment: Fragment, spec: ScenarioSpec) -> bool:
    """Check a fragment's ``requires`` placement constraints against the target.

    A malicious fragment that exploits a specific weakness module may only be placed on an
    enterprise that actually has that weakness planted, so the label stays truthful and the
    D4/D6 reference keys resolve against the target's own weakness ledger.
    """
    req: dict[str, Any] = fragment.requires or {}
    recipe = req.get("service_recipe")
    if recipe is not None and recipe not in _web_recipes(spec):
        return False
    role = req.get("role")
    if role is not None and not any(a.role.value == role for a in spec.assets):
        return False
    tls = req.get("tls")
    if tls is not None and not any(bool(s.tls) == bool(tls) for s in spec.services):
        return False
    module = fragment.truth.weakness_module
    if fragment.truth.label == "malicious" and module:
        return any(w.module == module for w in spec.weaknesses)
    return True


def bindings_for(fragment: Fragment, spec: ScenarioSpec, secrets: Secrets) -> dict[str, str] | None:
    """token -> concrete bindings for this enterprise, or ``None`` if the fragment cannot
    be fully bound here (a role/index it needs is absent)."""
    source_tokens = set(fragment.tokens)
    bindings = target_bindings(spec, secrets, source_tokens)
    if unresolved(source_tokens, bindings):
        return None
    return bindings


def fits(
    fragment: Fragment,
    spec: ScenarioSpec,
    secrets: Secrets,
    allowed_groups: set[str],
    ledger: ReuseLedger,
) -> dict[str, str] | None:
    """Return bindings if the fragment may be placed on this enterprise now, else ``None``."""
    if fragment.group_id not in allowed_groups:
        return None
    if not ledger.available(fragment.fragment_id):
        return None
    if not requirements_met(fragment, spec):
        return None
    return bindings_for(fragment, spec, secrets)


def choose(
    candidates: list[Fragment],
    spec: ScenarioSpec,
    secrets: Secrets,
    allowed_groups: set[str],
    ledger: ReuseLedger,
    want: int,
    rng: Any,
    *,
    label: str | None = None,
    family: str | None = None,
) -> list[tuple[Fragment, dict[str, str]]]:
    """Pick up to ``want`` placeable fragments matching ``label``/``family`` filters.

    Selection is deterministic for a given ``rng``. The reuse ledger is updated as each
    fragment is taken, so a later scenario in the same run sees the reduced availability.
    """
    pool = [
        f
        for f in candidates
        if (label is None or f.truth.label == label) and (family is None or f.truth.family == family)
    ]
    order = list(pool)
    rng.shuffle(order)
    chosen: list[tuple[Fragment, dict[str, str]]] = []
    for frag in order:
        if len(chosen) >= want:
            break
        bindings = fits(frag, spec, secrets, allowed_groups, ledger)
        if bindings is None:
            continue
        ledger.take(frag.fragment_id)
        chosen.append((frag, bindings))
    return chosen
