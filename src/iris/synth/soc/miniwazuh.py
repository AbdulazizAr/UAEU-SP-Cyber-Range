"""MiniWazuh: a faithful subset of the Wazuh analysis pipeline (builder brief file 04 §2).

Pipeline: raw log line -> predecoder (syslog header) -> decoder (program-specific field
extraction) -> rule engine (the pinned Wazuh 4.14.9 ruleset) -> alert. Alerts are PRODUCED
by this engine over emitted raw lines; they are never written directly, so every alert has
exactly one parent raw line and re-running the engine reproduces it (contract T-S2), and
every rule id/level/group/MITRE tag is real because it comes from the pinned XML (T-S1).

Fidelity is a reimplementation and is **unverified** until a one-time ``wazuh-logtest``
calibration (``tools/calibrate_wazuh.sh``); see docs. Rules using a construct this engine
does not model are flagged ``unsupported`` (never silently skipped) and listed in
``UNSUPPORTED_RULES.md``; a test asserts coverage of the groups we rely on.

OS_Regex vs PCRE: Wazuh uses its own regex. This engine translates the small subset the
loaded rules use (``\\w \\d \\s \\S \\p \\.`` and capture groups); a rule whose regex cannot
be translated is marked unsupported rather than mis-evaluated.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from iris.synth.refs import require_bundle

# ---------------------------------------------------------------- OS_Regex / OS_Match


#: a Wazuh variable reference like ``$BAD_WORDS`` (not the ``$`` end-anchor) — we do not
#: expand rule variables, so a rule using one is marked unsupported rather than mis-matched.
_WAZUH_VAR = re.compile(r"\$[A-Z_]{2,}")


def os_match_predicate(pattern: str) -> Any:
    """Wazuh ``<match>`` (OS_Match): ``|``-separated substrings, ``^`` anchors start,
    ``$`` anchors end. Returns a predicate ``(text) -> bool``."""
    alts = [p for p in pattern.split("|") if p != ""]

    def pred(text: str) -> bool:
        for alt in alts:
            a = alt
            start = a.startswith("^")
            end = a.endswith("$")
            a = a[1:] if start else a
            a = a[:-1] if end else a
            if start and end:
                if text == a:
                    return True
            elif start:
                if text.startswith(a):
                    return True
            elif end:
                if text.endswith(a):
                    return True
            elif a in text:
                return True
        return False

    return pred


_OSREGEX_OK = re.compile(r"^[\w\s\\\.\(\)\|\^\$\+\*\?\[\]\-:/@,='\"<>#!%&;]*$")


def os_regex_to_python(pattern: str) -> re.Pattern[str] | None:
    """Translate the OS_Regex subset the loaded rules use into a Python regex, or ``None``
    when it uses a construct we do not model (the rule is then marked unsupported)."""
    if not _OSREGEX_OK.match(pattern):
        return None
    py = pattern.replace("\\p", r"[\.\,\;\:\!\?\"\(\)\{\}\[\]\-\+\=\<\>\@\#\$\%\^\&\*/]")
    try:
        return re.compile(py)
    except re.error:
        return None


# ---------------------------------------------------------------- rule model

# Wazuh "dynamic field" match tags: ``<url>re</url>`` matches the decoded field of that
# name, exactly like ``<field name="url">``. Supporting them lifts web/auth rule coverage.
_FIELD_TAGS = {
    "srcip",
    "dstip",
    "srcport",
    "dstport",
    "user",
    "srcuser",
    "dstuser",
    "url",
    "id",
    "status",
    "action",
    "hostname",
    "location",
    "protocol",
    "data",
    "extra_data",
    "system_name",
    "category",
}
_SUPPORTED_TAGS = {
    "decoded_as",
    "if_sid",
    "if_matched_sid",
    "match",
    "regex",
    "program_name",
    "description",
    "mitre",
    "group",
    "field",
    "frequency",
    "timeframe",
    "same_source_ip",
    "same_srcip",
    "same_src_ip",
    "same_user",
    "same_srcuser",
    "ignore",
    "options",
    "info",
    "same_id",
    "noalert",
} | _FIELD_TAGS


@dataclass
class Rule:
    id: int
    level: int
    description: str = ""
    groups: tuple[str, ...] = ()
    mitre: tuple[str, ...] = ()
    decoded_as: str | None = None
    if_sid: int | None = None
    if_matched_sid: int | None = None
    program_name: re.Pattern[str] | None = None
    matches: list[Any] = field(default_factory=list)  # OR'd predicates
    regex: re.Pattern[str] | None = None
    fields: list[tuple[str, re.Pattern[str]]] = field(default_factory=list)
    frequency: int | None = None
    timeframe: int | None = None
    same: set[str] = field(default_factory=set)
    ignore: int | None = None
    maxsize: int | None = None
    noalert: bool = False
    unsupported: str | None = None
    source_group: str = ""


@dataclass
class Alert:
    rule: Rule
    full_log: str
    decoder: str
    program_name: str | None
    data: dict[str, str]
    timestamp: datetime
    hostname: str | None


# ---------------------------------------------------------------- rule loading


def _text(el: ET.Element | None) -> str:
    return (el.text or "").strip() if el is not None else ""


def load_rules(bundle_dir: Path | None = None) -> dict[int, Rule]:
    base = (bundle_dir or require_bundle("wazuh-ruleset")) / "rules"
    rules: dict[int, Rule] = {}
    for xml in sorted(base.glob("*.xml")):
        # Wazuh rule files are fragments with several top-level <group> elements, so wrap
        # them in one synthetic root before parsing.
        root = ET.fromstring("<ruleset>\n" + xml.read_text(encoding="utf-8") + "\n</ruleset>")
        groups_stack = ""
        for grp in root.iter("group"):
            gname = grp.attrib.get("name", groups_stack)
            for rel in grp.findall("rule"):
                rule = _parse_rule(rel, gname)
                rules[rule.id] = rule
    return rules


def _parse_rule(rel: ET.Element, group_name: str) -> Rule:
    rid = int(rel.attrib["id"])
    rule = Rule(
        id=rid,
        level=int(rel.attrib.get("level", "0")),
        frequency=int(rel.attrib["frequency"]) if "frequency" in rel.attrib else None,
        timeframe=int(rel.attrib["timeframe"]) if "timeframe" in rel.attrib else None,
        ignore=int(rel.attrib["ignore"]) if "ignore" in rel.attrib else None,
        maxsize=int(rel.attrib["maxsize"]) if "maxsize" in rel.attrib else None,
        noalert=rel.attrib.get("noalert") == "1",
        source_group=group_name,
    )
    unsupported: list[str] = []
    for child in rel:
        tag = child.tag
        if tag not in _SUPPORTED_TAGS:
            unsupported.append(tag)
            continue
        if tag == "description":
            rule.description = _text(child)
        elif tag == "decoded_as":
            rule.decoded_as = _text(child)
        elif tag == "if_sid":
            rule.if_sid = int(_text(child).split(",")[0]) if _text(child) else None
        elif tag == "if_matched_sid":
            rule.if_matched_sid = int(_text(child))
        elif tag == "program_name":
            rule.program_name = os_regex_to_python(_text(child))
            if rule.program_name is None:
                unsupported.append("program_name:regex")
        elif tag == "match":
            if _WAZUH_VAR.search(_text(child)):
                unsupported.append("match:variable")
            else:
                rule.matches.append(os_match_predicate(_text(child)))
        elif tag == "regex":
            compiled = os_regex_to_python(_text(child))
            if compiled is None:
                unsupported.append("regex")
            else:
                rule.regex = compiled
        elif tag == "field":
            name = child.attrib.get("name", "")
            compiled = os_regex_to_python(_text(child))
            if compiled is None or not name:
                unsupported.append("field")
            else:
                rule.fields.append((name, compiled))
        elif tag in _FIELD_TAGS:
            compiled = os_regex_to_python(_text(child))
            if compiled is None:
                unsupported.append(f"{tag}:regex")
            else:
                rule.fields.append((tag, compiled))
        elif tag in ("same_source_ip", "same_srcip", "same_src_ip"):
            rule.same.add("srcip")
        elif tag in ("same_user", "same_srcuser"):
            rule.same.add("user")
        elif tag == "same_id":
            rule.same.add("id")
        elif tag == "mitre":
            rule.mitre = tuple(_text(i) for i in child.findall("id"))
        elif tag == "group":
            rule.groups = tuple(g for g in _text(child).split(",") if g)
    base_groups = tuple(g for g in group_name.split(",") if g)
    rule.groups = tuple(dict.fromkeys(base_groups + rule.groups))
    if unsupported:
        rule.unsupported = ",".join(sorted(set(unsupported)))
    return rule


# ---------------------------------------------------------------- predecoder

_SYSLOG_HDR = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<prog>[\w\-/.]+?)(?:\[(?P<pid>\d+)\])?:\s(?P<msg>.*)$"
)
_MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1
    )
}


@dataclass
class PreDecoded:
    timestamp: datetime | None
    hostname: str | None
    program: str | None
    pid: str | None
    message: str


def predecode(line: str, year: int, tzinfo: Any = None) -> PreDecoded:
    """Parse a traditional syslog header into predecoder fields (brief file 04 §2.1)."""
    m = _SYSLOG_HDR.match(line)
    if not m:
        return PreDecoded(None, None, None, None, line)
    ts_text = m.group("ts")
    mon, day, clock = ts_text.split(None, 2)
    hh, mm, ss = clock.split(":")
    ts = datetime(year, _MONTHS[mon], int(day), int(hh), int(mm), int(ss), tzinfo=tzinfo)
    return PreDecoded(ts, m.group("host"), m.group("prog"), m.group("pid"), m.group("msg"))


# ---------------------------------------------------------------- decoders (faithful to the
# real Wazuh field extraction for the exact formats our emitters produce)

_SSHD_ACCEPTED = re.compile(r"^Accepted \S+ for (?:invalid user )?(\S+) from (\S+) port (\S+)")
_SSHD_FAILED = re.compile(r"^Failed \S+ for (?:invalid user )?(\S+) from (\S+) port (\S+)")
_SSHD_INVALID = re.compile(r"^Invalid user (\S+) from (\S+)")
_WEB = re.compile(r'^(\S+) \S+ (\S+) \[[^\]]+\] "(\S+) (\S+) (\S+)" (\d{3}) (\S+)')
_SUDO = re.compile(r"^\s*(\S+) : .*?(?:USER=(\S+))? ; COMMAND=(.*)$")
_PG = re.compile(r"(FATAL|ERROR|PANIC):\s+(.*)$")


def decode(pre: PreDecoded) -> tuple[str | None, dict[str, str]]:
    """Return ``(decoder_name, fields)``. ``decoder_name`` equals the Wazuh parent decoder a
    rule's ``<decoded_as>`` refers to (``sshd``, ``web-accesslog``, ``pam``, ...)."""
    prog, msg = pre.program, pre.message
    if prog == "sshd":
        for rx, keys in (
            (_SSHD_ACCEPTED, ("user", "srcip", "srcport")),
            (_SSHD_FAILED, ("user", "srcip", "srcport")),
            (_SSHD_INVALID, ("user", "srcip")),
        ):
            m = rx.match(msg)
            if m:
                return "sshd", dict(zip(keys, m.groups(), strict=True))
        return "sshd", {}
    if prog in ("nginx", "apache2", "httpd"):
        m = _WEB.match(msg)
        if m:
            return "web-accesslog", {
                "srcip": m.group(1),
                "user": m.group(2),
                "method": m.group(3),
                "url": m.group(4),
                "protocol": m.group(5),
                "id": m.group(6),
                "size": m.group(7),
            }
        return "web-accesslog", {}
    if prog == "sudo":
        m = _SUDO.match(msg)
        if m:
            f = {"user": m.group(1)}
            if m.group(2):
                f["dstuser"] = m.group(2)
            return "sudo", f
        return "sudo", {}
    if prog in ("su", "su[pam]"):
        return "su", {}
    if prog and prog.startswith("postgres"):
        m = _PG.search(msg)
        return "postgresql", ({"status": m.group(1)} if m else {})
    if prog in ("systemd", "cron", "CRON", "auditd", "kernel"):
        return prog.lower(), {}
    if "pam_" in msg or prog in ("login", "sshd-pam"):
        return "pam", {}
    return None, {}


# ---------------------------------------------------------------- engine


class MiniWazuh:
    """Stateful analysis engine: feed raw lines in time order; it emits alerts.

    State is the frequency window per ``if_matched_sid`` rule. One instance per episode (the
    live window); the manager is stateless across episodes per decisions.md.
    """

    def __init__(self, rules: dict[int, Rule] | None = None, manager_name: str = "wazuh-manager") -> None:
        self.rules = rules if rules is not None else load_rules()
        self.manager_name = manager_name
        self._children: dict[int, list[Rule]] = {}
        self._freq: dict[int, deque[tuple[datetime, str]]] = {}
        self._last_fired: dict[int, datetime] = {}
        for r in self.rules.values():
            if r.if_sid is not None:
                self._children.setdefault(r.if_sid, []).append(r)
        self._roots = [r for r in self.rules.values() if r.if_sid is None and r.if_matched_sid is None]

    # -- condition evaluation -------------------------------------------------
    @staticmethod
    def _own_conditions_match(rule: Rule, msg: str, data: dict[str, str]) -> bool:
        if rule.maxsize is not None and len(msg) < rule.maxsize:
            return False
        if rule.matches and not any(p(msg) for p in rule.matches):
            return False
        if rule.regex is not None and not rule.regex.search(msg):
            return False
        for name, rx in rule.fields:
            if not rx.search(data.get(name, "")):
                return False
        return True

    def _walk(
        self, rule: Rule, msg: str, data: dict[str, str], decoded_as: str | None, prog: str | None
    ) -> list[Rule]:
        """Depth-first: return every rule that matches on this event, root-to-leaf."""
        matched: list[Rule] = []
        if rule.unsupported:
            return matched
        if rule.decoded_as is not None and rule.decoded_as != decoded_as:
            return matched
        if rule.program_name is not None and (prog is None or not rule.program_name.search(prog)):
            return matched
        if not self._own_conditions_match(rule, msg, data):
            return matched
        matched.append(rule)
        for child in self._children.get(rule.id, []):
            matched.extend(self._walk(child, msg, data, decoded_as, prog))
        return matched

    def _frequency_escalation(self, base: Rule, ts: datetime, data: dict[str, str]) -> Rule | None:
        for freq in self.rules.values():
            if freq.if_matched_sid != base.id or freq.frequency is None or freq.unsupported:
                continue
            key = "|".join(data.get(s, "") for s in sorted(freq.same)) if freq.same else "*"
            win = self._freq.setdefault(freq.id, deque())
            win.append((ts, key))
            horizon = timedelta(seconds=freq.timeframe or 600)
            while win and ts - win[0][0] > horizon:
                win.popleft()
            same_key = [w for w in win if w[1] == key]
            if len(same_key) >= freq.frequency + 1:
                last = self._last_fired.get(freq.id)
                if last is not None and freq.ignore and (ts - last).total_seconds() < freq.ignore:
                    continue
                self._last_fired[freq.id] = ts
                win.clear()
                return freq
        return None

    def process(
        self, line: str, year: int, tzinfo: Any = None, agent: dict[str, str] | None = None
    ) -> Alert | None:
        pre = predecode(line, year, tzinfo)
        decoded_as, data = decode(pre)
        candidates: list[Rule] = []
        for root in self._roots:
            if root.decoded_as is not None and root.decoded_as != decoded_as:
                continue
            if root.program_name is not None and (
                pre.program is None or not root.program_name.search(pre.program)
            ):
                continue
            candidates.extend(self._walk(root, pre.message, data, decoded_as, pre.program))
        if not candidates:
            return None
        # a noalert catch-all never outranks a real alert: choose among alerting rules first
        alerting = [c for c in candidates if not c.noalert and c.level > 0]
        best = max(alerting or candidates, key=lambda r: (r.level, r.id))
        ts = pre.timestamp or datetime(year, 1, 1, tzinfo=tzinfo)
        escalated = self._frequency_escalation(best, ts, data)
        chosen = escalated or best
        if chosen.noalert or chosen.level == 0:
            return None
        return Alert(
            rule=chosen,
            full_log=line,
            decoder=decoded_as or (pre.program or ""),
            program_name=pre.program,
            data=data,
            timestamp=ts,
            hostname=pre.hostname,
        )


# ---------------------------------------------------------------- coverage reporting

#: rule-source-group keywords MiniWazuh claims to support (the sources our emitters produce).
CLAIMED_GROUP_KEYWORDS = (
    "sshd",
    "pam",
    "sudo",
    "syslog",
    "web,",
    "apache",
    "nginx",
    "appsec",
    "systemd",
    "postgresql",
    "auditd",
    "ossec",
    "wazuh,",
)


def coverage_report(rules: dict[int, Rule] | None = None) -> dict[str, Any]:
    """Supported/unsupported counts overall and within the claimed groups (brief T-S gate)."""
    rules = rules if rules is not None else load_rules()
    claimed = [r for r in rules.values() if any(k in r.source_group + "," for k in CLAIMED_GROUP_KEYWORDS)]
    claimed_unsupported = [r for r in claimed if r.unsupported]
    return {
        "total_rules": len(rules),
        "total_supported": sum(1 for r in rules.values() if not r.unsupported),
        "claimed_rules": len(claimed),
        "claimed_supported": len(claimed) - len(claimed_unsupported),
        "claimed_coverage": round((len(claimed) - len(claimed_unsupported)) / max(1, len(claimed)), 4),
        "unsupported": [
            {"id": r.id, "group": r.source_group, "reason": r.unsupported, "description": r.description}
            for r in sorted((r for r in rules.values() if r.unsupported), key=lambda r: r.id)
        ],
    }


def write_unsupported_doc(path: Path, rules: dict[int, Rule] | None = None) -> None:
    rep = coverage_report(rules)
    lines = [
        "# Unsupported Wazuh rules (MiniWazuh)",
        "",
        "Rules the pinned Wazuh 4.14.9 ruleset defines that MiniWazuh does not evaluate, because",
        "they use a construct this reimplementation does not model. They are flagged, never",
        "silently skipped (builder brief file 04 §2). MiniWazuh fidelity is **unverified** until a",
        "one-time `wazuh-logtest` calibration (`tools/calibrate_wazuh.sh`).",
        "",
        f"- Total rules loaded: **{rep['total_rules']}**, supported **{rep['total_supported']}**.",
        f"- Claimed groups (sources our emitters produce): "
        f"**{rep['claimed_supported']}/{rep['claimed_rules']} = {rep['claimed_coverage'] * 100:.1f}%**.",
        "",
        "Unsupported constructs seen: `regex` (OS_Regex this translator rejects), `list` (CDB",
        "lists), `if_fts` (first-time-seen), `check_diff`, `if_group`, `compiled_rule`, and rule",
        "variables such as `$BAD_WORDS`.",
        "",
        "| Rule | Group | Reason | Description |",
        "|------|-------|--------|-------------|",
    ]
    for r in rep["unsupported"]:
        desc = r["description"].replace("|", "\\|")[:70]
        lines.append(f"| {r['id']} | {r['group'].rstrip(',')} | {r['reason']} | {desc} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
