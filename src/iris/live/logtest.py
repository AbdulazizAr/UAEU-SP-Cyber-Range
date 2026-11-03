"""Rule library checks.

- ``rules_report``: a static check. Rule IDs are unique and within 100100-100199, every
  ``if_sid``/``if_matched_sid`` points to a known rule, and the ATT&CK IDs exist and are
  current in the pinned ATT&CK release (when it is available).
- ``run_logtest``: a live check. A throwaway manager container from the pinned image
  loads the rules, and every case in ``configs/soc/logtest.yaml`` goes through
  ``wazuh-logtest``. The last event of each case must match the expected rule and level.
"""

from __future__ import annotations

import re
import secrets
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from iris.generator.compiler import RULES_PATH, WAZUH_IMAGE
from iris.settings import repo_root
from iris.spikes.common import sh, wait_until
from iris.spikes.wazuh import manager_ready_from

RULE_RANGE = range(100100, 100200)
_ID = re.compile(r"id: '(\d+)'")
_LEVEL = re.compile(r"level: '(\d+)'")


def rules_path() -> Path:
    return repo_root() / "configs" / "soc" / "local_rules.xml"


def parse_rules(text: str) -> list[dict[str, Any]]:
    root = ET.fromstring(f"<root>{re.sub(r'<!--.*?-->', '', text, flags=re.S)}</root>")
    out: list[dict[str, Any]] = []
    for rule in root.iter("rule"):
        out.append(
            {
                "id": int(rule.get("id", "0")),
                "level": int(rule.get("level", "0")),
                "parents": [
                    int(x)
                    for tag in ("if_sid", "if_matched_sid")
                    for x in (rule.findtext(tag) or "").split(",")
                    if x.strip()
                ],
                "mitre": [e.text or "" for e in rule.iter("id")],
            }
        )
    return out


def rules_report(attack_ids: set[str] | None = None) -> list[str]:
    """Problems with the rule library (empty = OK)."""
    rules = parse_rules(rules_path().read_text(encoding="utf-8"))
    problems = []
    ids = [r["id"] for r in rules]
    problems += [f"duplicate rule id {i}" for i in sorted({i for i in ids if ids.count(i) > 1})]
    problems += [
        f"rule id {i} outside {RULE_RANGE.start}-{RULE_RANGE.stop - 1}" for i in ids if i not in RULE_RANGE
    ]
    known = set(ids)
    for r in rules:
        problems += [  # parents outside our range are built-in Wazuh rules
            f"rule {r['id']} parent {p} unknown" for p in r["parents"] if p in RULE_RANGE and p not in known
        ]
        for t in r["mitre"]:
            if not re.fullmatch(r"T\d{4}(\.\d{3})?", t):
                problems.append(f"rule {r['id']}: malformed ATT&CK id {t!r}")
            elif attack_ids is not None and t not in attack_ids:
                problems.append(f"rule {r['id']}: {t} is not a current technique in the pinned ATT&CK")
    return problems


def parse_logtest(output: str) -> list[tuple[int | None, int | None]]:
    """``wazuh-logtest`` output -> (rule id, level) per event, in input order."""
    out: list[tuple[int | None, int | None]] = []
    for chunk in output.split("**Phase 1:")[1:]:
        phase3 = chunk.split("**Phase 3:", 1)
        if len(phase3) < 2:
            out.append((None, None))
            continue
        rid, lvl = _ID.search(phase3[1]), _LEVEL.search(phase3[1])
        out.append((int(rid.group(1)) if rid else None, int(lvl.group(1)) if lvl else None))
    return out


@dataclass
class CaseResult:
    name: str
    ok: bool
    expected: tuple[int, int]
    got: tuple[int | None, int | None]


def load_cases() -> list[dict[str, Any]]:
    data: dict[str, Any] = yaml.safe_load((repo_root() / "configs" / "soc" / "logtest.yaml").read_text())
    cases: list[dict[str, Any]] = data["cases"]
    return cases


def run_logtest(image: str = WAZUH_IMAGE) -> list[CaseResult]:
    name = f"iris-logtest-{secrets.token_hex(4)}"
    sh(
        ["docker", "run", "-d", "--name", name, "--label", "iris.tool=logtest",
         "-v", f"{rules_path()}:{RULES_PATH}:ro", image],
        timeout=120,
    )  # fmt: skip
    try:
        ok, _ = wait_until(
            lambda: manager_ready_from(
                sh(["docker", "exec", name, "/var/ossec/bin/wazuh-control", "status"], check=False).stdout
            )[0],
            timeout=180,
        )
        if not ok:
            raise RuntimeError("manager did not start for logtest (rule syntax error?): " + sh(
                ["docker", "logs", "--tail", "30", name], check=False).stdout)  # fmt: skip
        results = []
        for case in load_cases():
            lines = list(case["lines"]) * int(case.get("repeat", 1))
            out = sh(
                ["docker", "exec", "-i", name, "/var/ossec/bin/wazuh-logtest"],
                input_text="\n".join(lines) + "\n",
                check=False,
                timeout=120,
            ).stdout
            events = parse_logtest(out)
            got = events[-1] if events else (None, None)
            want = (int(case["expect"]), int(case["level"]))
            results.append(CaseResult(case["name"], got == want, want, got))
        return results
    finally:
        sh(["docker", "rm", "-f", name], check=False)
