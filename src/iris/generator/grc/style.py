"""Organisational GRC style (INPUT Part 2, A3): how THIS organisation writes things down.

The same reality is recorded on different risk scales, criticality scales and control
vocabularies; ``scale_definition.json`` tells the Engine how to read them.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from iris.contracts.visible import ScaleDefinition

RISK_LEVELS = {
    "5x5": ["Low", "Medium", "High", "Critical"],
    "3_level": ["Low", "Medium", "High"],
    "1_10": [str(n) for n in range(1, 11)],
    "qualitative": ["Low", "Moderate", "Significant", "Severe"],
}
CRIT_LEVELS = {  # ordered low -> high; index = criticality 1..5 mapped below
    "1_5": ["1", "2", "3", "4", "5"],
    "tier_0_3": ["Tier 3", "Tier 2", "Tier 1", "Tier 0"],
    "named": ["normal", "important", "business critical"],
    "cia": ["L", "M", "H"],
}
CADENCE_DAYS = {"monthly": 30, "quarterly": 91, "annual": 365, "ad_hoc": 540}
FAMILY_NAMES = {
    "nist_csf": {f: f.title() for f in ("GOVERN", "IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER")},
    "iso_27001": {
        "GOVERN": "Organizational",
        "IDENTIFY": "Organizational",
        "PROTECT": "Technological",
        "DETECT": "Technological",
        "RESPOND": "Organizational",
        "RECOVER": "Technological",
    },
    "cis": {
        "GOVERN": "Governance",
        "IDENTIFY": "Inventory and Vulnerability",
        "PROTECT": "Protective Safeguards",
        "DETECT": "Monitoring",
        "RESPOND": "Incident Response",
        "RECOVER": "Recovery",
    },
    "home_grown": {
        "GOVERN": "Policy",
        "IDENTIFY": "Asset Management",
        "PROTECT": "Security Engineering",
        "DETECT": "SOC",
        "RESPOND": "SOC",
        "RECOVER": "IT Operations",
    },
}
CONTROL_STATE_WORDS = ("implemented", "partial", "missing", "not_assessed", "compensating", "exception")


@dataclass(frozen=True)
class GrcStyle:
    risk_scale: str
    criticality_scale: str
    vocabulary: str
    cadence: str

    @classmethod
    def sample(cls, rng: random.Random) -> GrcStyle:
        return cls(
            risk_scale=rng.choice(sorted(RISK_LEVELS)),
            criticality_scale=rng.choice(sorted(CRIT_LEVELS)),
            vocabulary=rng.choice(sorted(FAMILY_NAMES)),
            cadence=rng.choice(sorted(CADENCE_DAYS)),
        )

    # ---- criticality

    def crit_levels(self) -> list[str]:
        return CRIT_LEVELS[self.criticality_scale]

    def crit_to_text(self, crit: int) -> str:
        return self.crit_levels()[_bucket(crit, len(self.crit_levels()))]

    def crit_rank(self, text: str) -> int:
        return self.crit_levels().index(text)

    # ---- risk

    def risk_levels(self) -> list[str]:
        return RISK_LEVELS[self.risk_scale]

    def risk_level_index(self, score: float) -> int:
        """Score 1..25 -> index into this scale's ordered levels."""
        if self.risk_scale == "1_10":
            return max(0, min(9, round(score / 2.5) - 1))
        n = len(self.risk_levels())
        if n == 3:
            return 0 if score < 6 else (1 if score < 13 else 2)
        return 0 if score < 5 else (1 if score < 10 else (2 if score < 16 else 3))

    def risk_to_text(self, score: float) -> str:
        return self.risk_levels()[self.risk_level_index(score)]

    def factor_to_text(self, value: int) -> str:
        """Likelihood or impact 1..5 in this scale."""
        if self.risk_scale == "3_level":
            return ["Low", "Low", "Medium", "High", "High"][value - 1]
        if self.risk_scale == "1_10":
            return str(value * 2)
        if self.risk_scale == "qualitative":
            return ["Rare", "Unlikely", "Possible", "Likely", "Almost certain"][value - 1]
        return str(value)

    def family(self, function: str) -> str:
        return FAMILY_NAMES[self.vocabulary][function]

    def scale_definition(self) -> ScaleDefinition:
        return ScaleDefinition(
            risk_scale=self.risk_scale,
            risk_levels=self.risk_levels(),
            criticality_scale=self.criticality_scale,
            criticality_levels=self.crit_levels(),
            control_vocabulary=self.vocabulary,
            review_cadence=self.cadence,
        )


def _bucket(crit: int, n_levels: int) -> int:
    """Map criticality 1..5 onto n ordered levels (low -> high)."""
    return min(n_levels - 1, max(0, round((crit - 1) * (n_levels - 1) / 4)))
