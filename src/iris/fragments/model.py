"""Fragment data model and placeholder abstraction.

A fragment stores telemetry records whose concrete, enterprise-specific values (IPs,
hostnames, usernames, the attacker address) have been replaced by placeholder tokens.
Composition realises a fragment by substituting the target enterprise's values back in
and re-timing every record relative to a new base. Abstraction and realisation are exact
inverses over the token set, which the tests enforce.
"""

from __future__ import annotations

import copy
import re
from dataclasses import asdict, dataclass, field
from typing import Any

#: Token form unlikely to occur in real telemetry. ``@@IRIS:NAME@@``.
TOKEN_RE = re.compile(r"@@IRIS:[A-Z0-9_]+@@")


def token(name: str) -> str:
    return f"@@IRIS:{name}@@"


@dataclass
class FragmentTruth:
    label: str  # benign | malicious
    family: str  # persona name, or attack family F1..F9
    outcome: str = "n/a"  # success | failed | n/a
    technique: str | None = None
    weakness_module: str | None = None
    stage: str | None = None
    expected_rules: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Record:
    source: str  # wazuh_alert | wazuh_archive | suricata_eve | app_event | auth_event
    offset_ms: int  # from the fragment's first record
    ts_field: str  # dotted path to the timestamp field inside body
    body: dict[str, Any]  # the raw record, with placeholder tokens in its string values

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Record:
        return cls(source=d["source"], offset_ms=int(d["offset_ms"]), ts_field=d["ts_field"], body=d["body"])


@dataclass
class Fragment:
    fragment_id: str
    kind: str  # benign | attack_stage
    group_id: str
    duration_ms: int
    tokens: dict[str, str]  # token name -> role hint (e.g. TARGET_IP -> "web_server.ip")
    records: list[Record]
    truth: FragmentTruth
    requires: dict[str, Any] = field(default_factory=dict)  # placement constraints

    def to_dict(self) -> dict[str, Any]:
        return {
            "fragment_id": self.fragment_id,
            "kind": self.kind,
            "group_id": self.group_id,
            "duration_ms": self.duration_ms,
            "tokens": self.tokens,
            "records": [r.to_dict() for r in self.records],
            "truth": self.truth.to_dict(),
            "requires": self.requires,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Fragment:
        return cls(
            fragment_id=d["fragment_id"],
            kind=d["kind"],
            group_id=d["group_id"],
            duration_ms=int(d["duration_ms"]),
            tokens=d["tokens"],
            records=[Record.from_dict(r) for r in d["records"]],
            truth=FragmentTruth(**d["truth"]),
            requires=d.get("requires", {}),
        )


# ---------------------------------------------------------------- substitution


def _sub_strings(value: Any, replace: Any) -> Any:
    """Apply ``replace`` (a str->str function) to every string in a nested structure."""
    if isinstance(value, str):
        return replace(value)
    if isinstance(value, dict):
        return {k: _sub_strings(v, replace) for k, v in value.items()}
    if isinstance(value, list):
        return [_sub_strings(v, replace) for v in value]
    return value


def abstract_value(value: Any, mapping: list[tuple[str, str]]) -> Any:
    """Replace concrete substrings with tokens. ``mapping`` is (concrete, token), applied
    longest concrete first so that 10.0.0.1 never clobbers 10.0.0.10."""
    ordered = sorted(mapping, key=lambda kv: len(kv[0]), reverse=True)

    def rep(s: str) -> str:
        for concrete, tok in ordered:
            if concrete:
                s = s.replace(concrete, tok)
        return s

    return _sub_strings(value, rep)


def realize_value(value: Any, mapping: dict[str, str]) -> Any:
    """Replace tokens with concrete values. ``mapping`` is token -> concrete."""

    def rep(s: str) -> str:
        if "@@IRIS:" not in s:
            return s
        return TOKEN_RE.sub(lambda m: mapping.get(m.group(0), m.group(0)), s)

    return _sub_strings(value, rep)


def residual_tokens(value: Any) -> set[str]:
    """Any placeholder tokens still present (a realisation must leave none)."""
    found: set[str] = set()

    def collect(s: str) -> str:
        found.update(TOKEN_RE.findall(s))
        return s

    _sub_strings(value, collect)
    return found


def get_path(body: dict[str, Any], path: str) -> Any:
    node: Any = body
    for part in path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def set_path(body: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    node = body
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value


def deepcopy_body(body: dict[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(body)
