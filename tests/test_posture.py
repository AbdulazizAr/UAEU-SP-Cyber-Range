import gzip
import json
from datetime import UTC, date, datetime

import pytest

from iris.contracts.visible import Component, CveEnrichment, ScannerFinding
from iris.core.seeds import SeedSet
from iris.core.vclock import parse_iso
from iris.generator.compiler import asset_images
from iris.generator.grc.recorded import build_grc
from iris.generator.grc.timeline import build_timeline
from iris.generator.posture.build import MissingScans, build_posture
from iris.generator.posture.scan import scan_cmd
from iris.generator.posture.trivy import parse_trivy
from iris.references.intel import Intel, parse_epss, parse_kev
from iris.references.registry import load_registry, series
from tests.conftest_paths import ROOT

FIX = ROOT / "tests" / "fixtures"


def _report():
    return parse_trivy(json.loads((FIX / "trivy_mini.json").read_text()))


def _epss(d, rows):
    body = "#model_version:v2025.03.14,score_date:" + d + "T00:00:00Z\ncve,epss,percentile\n"
    body += "".join(f"{c},{e},{p}\n" for c, e, p in rows)
    return parse_epss(gzip.compress(body.encode()), date.fromisoformat(d))


def _intel():
    kev = parse_kev(json.loads((FIX / "kev_mini.json").read_text()))
    return Intel(
        kev=kev,
        epss=[
            _epss("2026-04-01", [("CVE-2023-44487", 0.8, 0.99), ("CVE-2026-0001", 0.5, 0.97)]),
            _epss("2025-04-01", [("CVE-2023-44487", 0.7, 0.98)]),
        ],
    )


def _build(master):
    seeds = SeedSet.from_master(master)
    from iris.generator.sampler import sample_spec

    spec = sample_spec(seeds)
    grc = build_grc(spec, seeds)
    tl = build_timeline(spec, grc, seeds)
    reports = {img: _report() for img in set(asset_images(spec).values())}
    return (
        spec,
        grc,
        build_posture(spec, grc, reports, _intel(), tl.episodes, seeds, "0.76.1", {"updated_at": "x"}),
    )


@pytest.fixture(scope="module")
def postures():
    return [_build(m) for m in range(40)]


def test_parse_trivy():
    r = _report()
    assert r.os_family == "debian" and r.image_id == "sha256:0123456789abcdef"
    assert {p.name for p in r.packages} == {
        "nginx",
        "libssl3",
        "openssh-server",
        "libc6",
        "werkzeug",
        "flask",
    }
    ssh = next(p for p in r.packages if p.name == "openssh-server")
    assert ssh.version == "1:9.2p1-2+deb12u2"
    nginx = next(p for p in r.packages if p.name == "nginx")
    assert nginx.depends_on == ("pkg:deb/debian/libssl3@3.0.13-1~deb12u1?arch=amd64&distro=debian-12.7",)
    assert r.skipped_ids == 1  # TEMP-... advisory
    v = {x.cve_id: x for x in r.vulns}
    assert v["CVE-2026-0001"].cvss_version == "4.0" and v["CVE-2023-44487"].cvss_version == "3.1"
    assert v["CVE-2024-34069"].cvss == 7.5 and v["CVE-2024-34069"].kind == "lang"
    assert v["CVE-2010-4756"].published_at is None


def test_intel_is_date_gated():
    intel = _intel()
    early = datetime(2025, 6, 1, tzinfo=UTC)
    late = datetime(2026, 7, 1, tzinfo=UTC)
    assert intel.kev_at("CVE-2026-0001", early) is None and intel.kev_at("CVE-2026-0001", late)
    assert intel.epss_at("CVE-2023-44487", early) == (0.7, 0.98)
    assert intel.epss_at("CVE-2026-0001", early) is None
    assert intel.epss_snapshot_at(datetime(2025, 1, 1, tzinfo=UTC)) is None
    assert intel.epss[0].model_version == "v2025.03.14"


def test_epss_series_is_registered():
    members = series("epss", load_registry())
    assert len(members) >= 12
    assert members[0].id == "epss-2025-04-01" and members[0].filename.endswith("2025-04-01.csv.gz")


def test_no_future_leakage(postures):
    for _, _, p in postures:
        for f in p.findings:
            assert f.cve != "CVE-2010-4756"  # undated: never shown
            if f.cve == "CVE-2026-0001":
                assert f.timestamp >= datetime(2026, 3, 1, tzinfo=UTC)
        for e in p.enrichment:
            if e.published_at:
                assert e.published_at <= e.as_of
            if e.kev_date_added:
                assert e.kev_date_added <= e.as_of.date()
            if e.modified_at:
                assert e.modified_at <= e.as_of
        for eid, at in p.episodes:
            assert all(ts <= at for ts in p.scans_at[eid].values()) if eid in p.scans_at else True


def test_scanner_follows_vulnerability_control(postures):
    states = set()
    for _, grc, p in postures:
        state = p.reality["scanner"]["control_state"]
        states.add(state)
        if state == "missing":
            assert not p.findings and not p.reality["scanner"]["scanned_assets"]
        else:
            assert p.findings and p.reality["scanner"]["cadence_days"] in (7, 30)
        assert state == (
            grc.reality.controls["CTRL-VUL-001"].state
            if "CTRL-VUL-001" in grc.reality.controls
            else "missing"
        )
    assert {"implemented", "missing"} <= states or len(states) >= 2


def test_contract_models_and_ids(postures):
    for _, _, p in postures:
        vis = p.visible()
        for row in vis["posture/scanner_findings.jsonl"]:
            ScannerFinding(**row)
        for row in vis["posture/cve_enrichment.jsonl"]:
            CveEnrichment(**row)
        comps = [Component(**row) for row in vis["enterprise/components.json"]]
        ids = [f.finding_id for f in p.findings]
        assert len(set(ids)) == len(ids)
        assert len({c.component_id for c in comps}) == len(comps)
        first = p.scans_at.get(p.episodes[0][0], {})
        valid = {f.finding_id for f in p.findings if first.get(f.asset_id) == f.timestamp}
        linked = [fid for c in comps for fid in c.linked_finding_ids]
        assert set(linked) <= valid and len(linked) == len(set(linked))


def test_visible_plane_has_no_generator_traces(postures):
    for _, _, p in postures[:15]:
        text = json.dumps(p.visible(), default=str)
        assert "iris/" not in text and "iris-" not in text and "sha256:" not in text


def test_sbom_shape_and_determinism():
    _, _, a = _build(3)
    _, _, b = _build(3)
    assert json.dumps(a.visible(), default=str) == json.dumps(b.visible(), default=str)
    for bom in a.sboms.values():
        assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6"
        refs = [c["bom-ref"] for c in bom["components"]]
        assert len(refs) == len(set(refs))
        assert parse_iso(bom["metadata"]["timestamp"]) < a.episodes[0][1]


def test_asof_view_matches_scans(postures):
    for _, _, p in postures[:10]:
        for eid, at in p.episodes:
            view = p.asof(eid)
            for row in view["posture/scanner_findings.jsonl"]:
                assert parse_iso(row["timestamp"]) <= at
            assert all(parse_iso(r["as_of"]) == at for r in view["posture/cve_enrichment.jsonl"])


def test_missing_scans_are_reported():
    from iris.generator.sampler import sample_spec

    seeds = SeedSet.from_master(5)
    spec = sample_spec(seeds)
    grc = build_grc(spec, seeds)
    with pytest.raises(MissingScans) as err:
        build_posture(spec, grc, {}, _intel(), [], seeds)
    assert err.value.images


def test_scan_command_is_isolated(tmp_path):
    cmd = scan_cmd(tmp_path / "db", tmp_path / "in", "x.tar", tmp_path / "out", "r.json")
    assert cmd[cmd.index("--network") + 1] == "none"
    assert not any("docker.sock" in c for c in cmd)
    assert "--skip-db-update" in cmd and "--offline-scan" in cmd
    assert any(c.endswith(":/in:ro") for c in cmd)
