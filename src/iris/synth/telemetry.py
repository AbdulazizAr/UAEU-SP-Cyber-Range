"""Telemetry assembler: route activity footprints through the coverage model into the visible
v2.1 telemetry files, with exact evidence links (builder brief files 04-06).

The pipeline enforces observation (brief file 02 §5): a host produces Wazuh evidence only if it
carries an agent and collects that source; Suricata sees a flow only if it crosses a monitored
interface; blind segments produce nothing. Alerts are produced by MiniWazuh over the emitted raw
lines, so "no alert" can mean "benign", "unmonitored" or "sensor blind" — never assumed safe.

Output is CLEAN telemetry; the noise layer (Phase 8) is a separate post-processing stage.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from iris.core.hashing import event_id
from iris.core.vclock import iso_z
from iris.synth.activity.planner import ScenarioPlan
from iris.synth.posture import SynthPosture
from iris.synth.seeds import SynthSeeds
from iris.synth.soc import suricata
from iris.synth.soc.miniwazuh import MiniWazuh, Rule
from iris.synth.soc.wazuh_modules import (
    agents_status,
    fim_baseline,
    manager_health,
    rule_metadata,
    sca_results,
    syscollector,
)
from iris.synth.world import World, internet_zone

TELEMETRY_VERSION = "synth-telemetry-0.1.0"


@dataclass
class TelemetryBundle:
    visible: dict[str, Any] = field(default_factory=dict)
    hidden: dict[str, Any] = field(default_factory=dict)
    enabled_sensors: tuple[str, ...] = ()
    # event_id -> activity_id (exact evidence links, hidden)
    evidence: list[dict[str, Any]] = field(default_factory=list)


def _zone_of_ip(world: World, ip: str) -> str:
    aid = world.asset_for_ip(ip)
    if aid is not None:
        return world.zone_of.get(aid, "unknown")
    return internet_zone(world)


def _flow_is_seen(world: World, src_ip: str, dst_ip: str) -> bool:
    """One sensor at the router sees perimeter + inter-zone flows; intra-zone flows are seen
    only where a tap exists (high maturity)."""
    zs, zd = _zone_of_ip(world, src_ip), _zone_of_ip(world, dst_ip)
    if zs != zd:
        return True
    return world.spec.organization.maturity.value == "high"


def assemble_telemetry(
    world: World,
    plan: ScenarioPlan,
    synth: SynthSeeds,
    posture: SynthPosture,
    rules: dict[int, Rule],
) -> TelemetryBundle:
    scn = plan.scenario_id
    bundle = TelemetryBundle()
    archives_retained = world.soc.archives_retained

    alerts: list[dict[str, Any]] = []
    archives: list[dict[str, Any]] = []
    fim: list[dict[str, Any]] = []
    eve: list[dict[str, Any]] = []
    eve_stats: list[dict[str, Any]] = []
    app_events: list[dict[str, Any]] = []
    auth_events: list[dict[str, Any]] = []
    loaded_rule_ids: set[int] = set()
    coverage_windows: list[dict[str, Any]] = []
    sensor_health: list[dict[str, Any]] = []
    agent_dark: dict[str, datetime] = {}

    def env(
        source: str,
        ts: datetime,
        inner: dict[str, Any],
        eid_ep: str,
        asset_ref: str | None,
        activity_id: str | None,
        ingest: datetime | None = None,
        eve_event_id: str | None = None,
    ) -> dict[str, Any]:
        disc = {
            k: inner.get(k)
            for k in (
                "line",
                "path",
                "community_id",
                "url",
                "account",
                "dest_port",
                "src_ip",
                "src_port",
                "event_type",
                "event",
                "check_id",
                "result",
                "success",
            )
        }
        evid = event_id(source, {"ep": eid_ep, "ts": iso_z(ts), "asset": asset_ref, **disc})
        rec = {
            "event_id": evid,
            "scenario_id": scn,
            "episode_id": eid_ep,
            "source_type": source,
            "event_timestamp": iso_z(ts),
            "ingest_timestamp": iso_z(ingest or ts),
            "asset_ref": asset_ref,
            "eve_event_id": eve_event_id,
            "raw": inner,
        }
        if activity_id is not None:
            bundle.evidence.append(
                {
                    "activity_id": activity_id,
                    "event_id": evid,
                    "sensor": source,
                    "link_method": "generator_fact",
                    "link_quality": "exact",
                    "time_delta_ms": 0,
                    "review_status": "generator_fact",
                }
            )
        return rec

    for ep in plan.episodes:
        eid = ep.episode_id
        mw = MiniWazuh(dict(rules))
        ep_flows = 0
        for fp in sorted(ep.footprints, key=lambda f: f.ts):
            if fp.kind == "raw_log":
                aid = fp.asset_id
                if aid is None or not world.is_monitored(aid):
                    continue  # unmonitored host: no host evidence
                if agent_dark.get(aid) and fp.ts >= agent_dark[aid]:
                    continue  # sensor went dark (agent disabled) -> silence
                line = fp.data["line"]
                if archives_retained:
                    archives.append(
                        env(
                            "wazuh_archive",
                            fp.ts,
                            {"full_log": line, "location": fp.data.get("program")},
                            eid,
                            aid,
                            fp.activity_id,
                        )
                    )
                alert = mw.process(line, fp.ts.year, fp.ts.tzinfo)
                if alert is not None:
                    loaded_rule_ids.add(alert.rule.id)
                    inner = _wazuh_alert(alert, world.assets[aid].hostname)
                    alerts.append(env("wazuh_alert", fp.ts, inner, eid, aid, fp.activity_id))
            elif fp.kind == "fim":
                aid = fp.asset_id
                if aid is None or not world.is_monitored(aid) or not world.soc.fim.get(aid, False):
                    continue
                if agent_dark.get(aid) and fp.ts >= agent_dark[aid]:
                    continue  # sensor went dark (agent disabled) -> no FIM either
                path = fp.data["path"]
                event = fp.data["event"]
                fim.append(
                    env(
                        "wazuh_fim",
                        fp.ts,
                        {"path": path, "event": event, "mode": fp.data.get("mode", "scheduled")},
                        eid,
                        aid,
                        fp.activity_id,
                    )
                )
                # A monitored FIM change is a syscheck event: Wazuh tags it decoded_as
                # syscheck_{new_entry,integrity_changed,deleted} and rule 554/550/553 fires. Run
                # it through the engine so persistence (authorized_keys, cron) is detectable, not
                # just a silent fim.jsonl record.
                decoded_as = {
                    "added": "syscheck_new_entry",
                    "modified": "syscheck_integrity_changed",
                    "deleted": "syscheck_deleted",
                }.get(event)
                if decoded_as is not None:
                    verb = {
                        "added": "added to the system",
                        "modified": "modified",
                        "deleted": "deleted",
                    }[event]
                    fim_alert = mw.process_event(
                        decoded_as,
                        {"category": "ossec", "file": path, "path": path},
                        fp.ts,
                        full_log=f"File '{path}' {verb}.",
                        hostname=world.assets[aid].hostname,
                    )
                    if fim_alert is not None:
                        loaded_rule_ids.add(fim_alert.rule.id)
                        inner = _wazuh_alert(fim_alert, world.assets[aid].hostname)
                        alerts.append(env("wazuh_alert", fp.ts, inner, eid, aid, fp.activity_id))
            elif fp.kind == "flow":
                src, dst = fp.data["src_ip"], fp.data["dst_ip"]
                if not _flow_is_seen(world, src, dst):
                    continue
                ev = suricata.flow_event(
                    fp.ts,
                    src,
                    dst,
                    fp.data.get("src_port", 0) or _eph(fp),
                    dst_port=fp.data["dst_port"],
                    proto=fp.data.get("proto", "tcp"),
                    bytes_toserver=fp.data.get("bytes_toserver", 0),
                    bytes_toclient=fp.data.get("bytes_toclient", 0),
                    pkts_toserver=fp.data.get("pkts", 1),
                    app_proto=fp.data.get("app"),
                )
                eve.append(env("suricata_eve", fp.ts, ev, eid, world.asset_for_ip(dst), fp.activity_id))
                sig = suricata.match_signatures(ev)
                if sig is not None:
                    eve.append(
                        env(
                            "suricata_eve",
                            fp.ts,
                            suricata.alert_event(ev, sig),
                            eid,
                            world.asset_for_ip(dst),
                            fp.activity_id,
                        )
                    )
                ep_flows += 1
            elif fp.kind == "auth_event":
                aid = fp.asset_id
                if aid is not None and not world.is_monitored(aid):
                    continue
                auth_events.append(env("auth_event", fp.ts, dict(fp.data), eid, aid, fp.activity_id))
            elif fp.kind == "app_event":
                aid = fp.asset_id
                app_events.append(env("app_event", fp.ts, dict(fp.data), eid, aid, fp.activity_id))
            elif fp.kind == "agent_event" and fp.data.get("event") == "agent_stopped":
                if fp.asset_id:
                    agent_dark[fp.asset_id] = fp.ts

        # per-episode syscollector for monitored, service-bearing hosts
        for aid in sorted(posture.installed):
            if world.is_monitored(aid):
                bundle.visible[f"telemetry/wazuh/syscollector/{eid}/{world.assets[aid].hostname}.json"] = (
                    syscollector(world, aid, posture.installed[aid])
                )
        eve_stats.append(suricata.suricata_stats(ep.end, ep_flows))
        coverage_windows.append(
            {
                "sensor": "wazuh",
                "kind": "observed",
                "start": iso_z(ep.start),
                "end": iso_z(ep.end),
                "episode_id": eid,
            }
        )
        coverage_windows.append(
            {
                "sensor": "suricata",
                "kind": "observed",
                "start": iso_z(ep.start),
                "end": iso_z(ep.end),
                "episode_id": eid,
            }
        )
        for name, count in (("wazuh_manager", len(alerts)), ("suricata", len(eve))):
            sensor_health.append(
                {
                    "sensor": name,
                    "episode_id": eid,
                    "status": "healthy",
                    "collection_scope": ["host_logs"] if "wazuh" in name else ["flows"],
                    "known_gaps": [],
                    "event_count": count,
                }
            )

    # SCA (periodic, per monitored server)
    sca: list[dict[str, Any]] = []
    for aid in sorted(world.assets):
        if world.is_monitored(aid) and world.soc.sca.get(aid, False):
            for check in sca_results(world, aid):
                first_ep = plan.episodes[0]
                sca.append(env("wazuh_sca", first_ep.start, check, first_ep.episode_id, aid, None))

    bundle.visible.update(
        {
            "telemetry/wazuh/alerts.jsonl": alerts,
            "telemetry/wazuh/fim.jsonl": fim,
            "telemetry/wazuh/sca.jsonl": sca,
            "telemetry/wazuh/agents_status.jsonl": [agents_status(world)],
            "telemetry/wazuh/manager_health.jsonl": [manager_health(world)],
            "telemetry/wazuh/rule_metadata.json": rule_metadata(
                sorted(loaded_rule_ids), rules, "wazuh-4.14.9+iris-0.1.0"
            ),
            "telemetry/suricata/eve.jsonl": eve,
            "telemetry/suricata/suricata_stats.jsonl": eve_stats,
            "telemetry/suricata/sensor_inventory.json": suricata.sensor_inventory(
                ["router perimeter + inter-zone"], "2026-03-01"
            ),
            "telemetry/applications/application_events.jsonl": app_events,
            "telemetry/applications/authentication_events.jsonl": auth_events,
            "quality/coverage_windows.json": coverage_windows,
            "quality/sensor_health_visible.json": sensor_health,
        }
    )
    if archives_retained:
        bundle.visible["telemetry/wazuh/archives.jsonl"] = archives
    # de-duplicate: one record per real event (contract §9). An identical event_id means the
    # same 5-tuple+timestamp+type, i.e. the same event seen twice — collapse to one.
    _dedup_events(bundle)
    bundle.enabled_sensors = ("wazuh", "suricata")
    bundle.hidden["truth/evidence_links.jsonl"] = bundle.evidence
    bundle.hidden["truth/activities.jsonl"] = [a.truth_row() for a in plan.activities]
    _ = defaultdict, fim_baseline, synth  # reserved for FIM baseline + noise wiring
    return bundle


def _dedup_events(bundle: TelemetryBundle) -> None:
    seen: set[str] = set()
    kept_ids: set[str] = set()
    for path, content in bundle.visible.items():
        if path.endswith(".jsonl") and isinstance(content, list):
            out = []
            for rec in content:
                eid = rec.get("event_id") if isinstance(rec, dict) else None
                if eid is None:
                    out.append(rec)
                elif eid not in seen:
                    seen.add(eid)
                    kept_ids.add(eid)
                    out.append(rec)
            bundle.visible[path] = out
    # evidence links only reference events that survived de-duplication
    bundle.evidence[:] = [e for e in bundle.evidence if e["event_id"] in kept_ids]
    bundle.hidden["truth/evidence_links.jsonl"] = bundle.evidence


def _eph(fp: Any) -> int:
    """Deterministic ephemeral source port for a flow footprint that has none."""
    return 40000 + int(event_id("eph", {"t": iso_z(fp.ts)})[4:9], 16) % 20000


def _wazuh_alert(alert: Any, agent_name: str) -> dict[str, Any]:
    """Shape a MiniWazuh alert like a real Wazuh alert JSON (contract §8.2)."""
    return {
        "rule": {
            "id": str(alert.rule.id),
            "level": alert.rule.level,
            "description": alert.rule.description,
            "groups": list(alert.rule.groups),
            "mitre": {"id": list(alert.rule.mitre)} if alert.rule.mitre else {},
            "firedtimes": 1,
        },
        "agent": {"name": agent_name},
        "manager": {"name": "wazuh-manager"},
        "decoder": {"name": alert.decoder},
        "location": alert.program_name or alert.decoder,
        "full_log": alert.full_log,
        "predecoder": {"program_name": alert.program_name, "hostname": alert.hostname},
        "data": alert.data,
    }
