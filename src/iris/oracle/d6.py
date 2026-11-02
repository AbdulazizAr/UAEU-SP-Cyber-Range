"""D6 reference key: the GRC flaws active at each episode checkpoint (hidden plane).

The checkpoint is the episode start (the as-of time of the context the Engine gets).
Keys are entity IDs. Assets also accept their hostname and IP addresses as aliases,
because a shadow asset has no inventory ID and the Engine only knows it from what it observes.
Records changed by bounded noise are listed as tolerated: a claim on them is a noise claim,
not a false positive.
"""

from __future__ import annotations

from typing import Any

from iris.contracts.spec import ScenarioSpec
from iris.core.vclock import iso_z
from iris.generator.grc.recorded import RUBRIC_VERSION, GrcBundle
from iris.generator.grc.timeline import GrcTimeline

D6_KEY_VERSION = "d6-key-0.1.0"


def _aliases(key: str, spec: ScenarioSpec, timeline: GrcTimeline) -> list[str]:
    out = {key}
    a = next((x for x in spec.assets if x.asset_id == key), None)
    if a is not None:
        out.add(a.hostname)
        out.update(att.ip for att in a.attachments)
    rec = timeline.base["assets"].get(key)
    if rec is not None:  # ghost assets exist only in the record
        out.add(rec["hostname"])
        out.update(rec["ip_addresses"])
    return sorted(out)


def build_d6_key(spec: ScenarioSpec, bundle: GrcBundle, timeline: GrcTimeline) -> dict[str, dict[str, Any]]:
    tolerated = sorted({m.key for m in bundle.mutations if m.cause.startswith("noise:")})
    out: dict[str, dict[str, Any]] = {}
    for eid, at in timeline.episodes:
        flaws = []
        for f in timeline.active_flaws(at):
            coll, key = f.object_ref.split(":", 1)
            flaws.append(
                {
                    "flaw_id": f.flaw_id,
                    "key": key,
                    "aliases": _aliases(key, spec, timeline),
                    "collection": coll,
                    "module": f.module,
                    "level": f.level,
                    "detectability": f.detectability,
                    "fields": f.fields,
                    "harm": f.harm_if_ignored,
                    "reference_action": f.reference_action,
                    "origin": f.origin,
                    "evidence_refs": f.evidence_refs,
                }
            )
        out[eid] = {
            "version": D6_KEY_VERSION,
            "rubric_version": RUBRIC_VERSION,
            "episode_id": eid,
            "as_of": iso_z(at),
            "clean": not flaws,
            "flaws": flaws,
            "tolerated_keys": tolerated,
        }
    return out
