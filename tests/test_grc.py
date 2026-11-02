import copy
import json
from collections import Counter

import pytest

from iris.core.seeds import SeedSet
from iris.generator.grc.reality import build_reality, level_of
from iris.generator.grc.recorded import DC_WEIGHTS, FLAW_BUDGET, build_grc, diff_audit
from iris.generator.grc.style import CRIT_LEVELS, RISK_LEVELS, GrcStyle
from iris.generator.sampler import sample_spec

N = 400


@pytest.fixture(scope="module")
def bundles():
    out = []
    for m in range(N):
        spec = sample_spec(SeedSet.from_master(m))
        out.append((spec, build_grc(spec)))
    return out


def test_every_difference_is_explained(bundles):
    failing = [(i, b.audit) for i, (_, b) in enumerate(bundles) if not b.audit.ok]
    assert not failing, failing[:2]


def test_reality_does_not_depend_on_grc_seed():
    base = SeedSet.from_master(20261102)
    spec_a = sample_spec(base)
    spec_b = sample_spec(base.with_override("grc", 777))
    ra = build_reality(spec_a).to_dict()
    rb = build_reality(spec_b).to_dict()
    assert ra == rb


def test_grc_seed_changes_record_not_enterprise():
    base = SeedSet.from_master(31)
    a = build_grc(sample_spec(base))
    b = build_grc(sample_spec(base.with_override("grc", 4242)))
    assert a.reality.to_dict() == b.reality.to_dict()
    assert (a.style, len(a.ledger), a.audit.noise_changes) != (b.style, len(b.ledger), b.audit.noise_changes)


def test_same_seed_same_grc():
    spec = sample_spec(SeedSet.from_master(9))
    a, b = build_grc(spec), build_grc(spec)
    assert json.dumps(a.visible(), sort_keys=True) == json.dumps(b.visible(), sort_keys=True)
    assert [f.flaw_id for f in a.ledger] == [f.flaw_id for f in b.ledger]


def test_flaw_rates_follow_maturity(bundles):
    clean, total = Counter(), Counter()
    for spec, b in bundles:
        m = spec.organization.maturity.value
        total[m] += 1
        clean[m] += not b.ledger
    for m, (p_clean, _, _) in FLAW_BUDGET.items():
        assert abs(clean[m] / total[m] - p_clean) < 0.12, (m, clean[m] / total[m])
    for spec, b in bundles:
        assert len(b.ledger) <= FLAW_BUDGET[spec.organization.maturity.value][2]


def test_detectability_mix_near_target(bundles):
    dc = Counter(f.detectability for _, b in bundles for f in b.ledger)
    n = sum(dc.values())
    for cls, target in DC_WEIGHTS.items():
        assert abs(dc[cls] / n - target) < 0.07, (cls, dc[cls] / n)


def test_visible_plane_has_no_truth(bundles):
    forbidden = ("flaw", "WK-", "truth", "reality", "ledger", "noise", "F-0")
    for _, b in bundles[:100]:
        text = json.dumps(b.visible(), default=str)
        for word in forbidden:
            assert word not in text, word


def test_hidden_plane_is_complete(bundles):
    _, b = bundles[0]
    hidden = b.hidden()
    assert set(hidden) == {
        "truth/grc_reality.json",
        "truth/grc_style.json",
        "truth/grc_flaw_ledger.jsonl",
        "truth/grc_noise_log.jsonl",
        "truth/grc_diff_audit.json",
    }
    json.dumps(hidden, default=str)


def test_risk_formula_sanity(bundles):
    for _, b in bundles[:150]:
        for r in b.reality.risks.values():
            assert 1 <= r.likelihood <= 5 and 1 <= r.impact <= 5
            assert r.residual <= r.inherent
            assert 0.4 <= r.control_factor <= 1


def test_audit_detects_silent_tampering():
    spec = sample_spec(SeedSet.from_master(12))
    b = build_grc(spec)
    faithful_like = {
        "assets": {a.asset_id: a.model_dump() for a in b.assets},
        "business_context": {}, "controls": {}, "risks": {}, "exceptions": {},
    }  # fmt: skip
    tampered = copy.deepcopy(faithful_like)
    first = next(iter(tampered["assets"]))
    tampered["assets"][first]["hostname"] = "changed-silently"
    result = diff_audit(faithful_like, tampered, [], [], b.style)
    assert not result.ok and result.unexplained == [f"assets:{first}:hostname"]


def test_style_scales_are_ordered():
    for crit_scale, levels in CRIT_LEVELS.items():
        style = GrcStyle("5x5", crit_scale, "nist_csf", "quarterly")
        ranks = [levels.index(style.crit_to_text(c)) for c in range(1, 6)]
        assert ranks == sorted(ranks) and ranks[0] == 0 and ranks[-1] == len(levels) - 1
    for risk_scale, levels in RISK_LEVELS.items():
        style = GrcStyle(risk_scale, "1_5", "nist_csf", "quarterly")
        idx = [style.risk_level_index(s) for s in range(1, 26)]
        assert idx == sorted(idx) and idx[-1] == len(levels) - 1
    assert [level_of(s) for s in (1, 5, 10, 16, 25)] == [1, 2, 3, 4, 4]


def test_controls_reflect_weaknesses():
    for m in range(40):
        spec = sample_spec(SeedSet.from_master(m))
        r = build_reality(spec)
        for w in spec.weaknesses:
            assert r.controls[w.enabling_control].per_asset[w.asset_id] == "missing"
