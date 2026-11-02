import shutil
import subprocess
from collections import Counter
from pathlib import Path

import pytest
import yaml

from iris.contracts.spec import ScenarioSpec
from iris.core.seeds import SeedSet
from iris.generator.compiler import bridge_address, compile_spec
from iris.generator.invariants import check
from iris.generator.sampler import SampleOverrides, sample_spec

from .conftest_paths import ROOT

N_SEEDS = 400


def _dump(spec: ScenarioSpec, drop: tuple[str, ...] = ()) -> dict:
    d = spec.model_dump(mode="json")
    d.pop("seeds")
    for key in drop:
        d.pop(key)
    return d


@pytest.fixture(scope="module")
def many() -> list[ScenarioSpec]:
    return [sample_spec(SeedSet.from_master(m)) for m in range(N_SEEDS)]


def test_same_seed_same_spec():
    a = sample_spec(SeedSet.from_master(7))
    b = sample_spec(SeedSet.from_master(7))
    assert a.model_dump_json() == b.model_dump_json()


def test_different_seeds_differ():
    assert _dump(sample_spec(SeedSet.from_master(1))) != _dump(sample_spec(SeedSet.from_master(2)))


def test_all_specs_valid_and_plausible(many):
    bad = {i: v for i, s in enumerate(many) if (v := check(s))}
    assert not bad, list(bad.items())[:3]


def test_factor_coverage(many):
    archetypes = Counter(s.archetype for s in many)
    sizes = Counter(s.organization.size.value for s in many)
    maturity = Counter(s.organization.maturity.value for s in many)
    industries = Counter(s.organization.industry.value for s in many)
    assert set(archetypes) == {"compact_three_zone", "segmented_five_zone", "flat_small_office"}
    assert set(sizes) == {"S", "M", "L"}
    assert set(maturity) == {"low", "medium", "high"}
    assert len(industries) == 8


def test_weakness_counts_follow_maturity(many):
    avg = {
        m: sum(len(s.weaknesses) for s in many if s.organization.maturity.value == m)
        / max(1, sum(1 for s in many if s.organization.maturity.value == m))
        for m in ("low", "medium", "high")
    }
    assert avg["low"] > avg["medium"] > avg["high"]


def test_weaknesses_target_existing_services(many):
    for s in many:
        svc = {x.service_id: x for x in s.services}
        for w in s.weaknesses:
            assert w.service_id in svc and svc[w.service_id].asset_id == w.asset_id


def test_usernames_unique_and_services_have_accounts(many):
    for s in many[:50]:
        names = [i.username for i in s.identities]
        assert len(names) == len(set(names))
        assert any(i.kind == "service" for i in s.identities)


@pytest.mark.parametrize(
    ("module", "changes"),
    [
        ("attack", set()),
        ("traffic", set()),
        ("grc", set()),
        ("weakness", {"weaknesses"}),
        ("time", {"calendar", "episodes"}),
    ],
)
def test_alterations_only_change_their_part(module, changes):
    base = SeedSet.from_master(20261102)
    a = sample_spec(base)
    b = sample_spec(base.with_override(module, 424242))
    da, db = _dump(a), _dump(b)
    differing = {k for k in da if da[k] != db[k]}
    assert differing <= changes, differing
    assert b.seeds.overridden == [module]


def test_monitoring_alteration_only_changes_blind_spots():
    base = SeedSet.from_master(5)
    a, b = sample_spec(base), sample_spec(base.with_override("monitoring", 99))
    da, db = _dump(a), _dump(b)
    for asset in da["assets"] + db["assets"]:
        asset.pop("monitored")
    assert da == db


def test_enterprise_alteration_changes_group():
    base = SeedSet.from_master(5)
    assert base.with_override("topology", 1).group_id() != base.group_id()


def test_overrides_are_respected():
    s = sample_spec(SeedSet.from_master(3), SampleOverrides(industry="hospital", maturity="low", size="M"))
    assert (s.organization.industry.value, s.organization.maturity.value, s.organization.size.value) == (
        "hospital",
        "low",
        "M",
    )


def test_episodes_are_virtual_ordered_and_in_the_past(many):
    for s in many[:100]:
        assert 2 <= len(s.episodes) <= 3
        assert s.episodes[-1].virtual_end.year <= 2026
        assert s.calendar.start.isoformat() < "2026-06-01"


# ---------------------------------------------------------------- compiler


def test_compiled_range_structure(many):
    for spec in many[:60]:
        c = compile_spec(spec)
        nets = c.compose["networks"]
        assert all(n["internal"] for n in nets.values())
        for z in spec.zones:
            gw = nets[f"z_{z.name}"]["ipam"]["config"][0]["gateway"]
            assert gw == bridge_address(z.subnet) != z.gateway
        router = next(
            svc for svc in c.compose["services"].values() if svc["labels"]["iris.role"] == "router_firewall"
        )
        assert len(router["networks"]) == len(spec.zones)
        ips = {
            cfg["ipv4_address"] for svc in c.compose["services"].values() for cfg in svc["networks"].values()
        }
        for a in spec.assets:
            assert all(att.ip in ips for att in a.attachments)
        assert c.router_nft.count(" accept comment") + c.router_nft.count(" drop comment") == len(spec.policy)
        assert c.meta["container_count"] == len(spec.assets) + len(spec.externals)


def test_compile_is_deterministic():
    s = sample_spec(SeedSet.from_master(11))
    assert compile_spec(s).compose == compile_spec(s).compose


def test_golden_example_compiles():
    spec = ScenarioSpec.model_validate(
        yaml.safe_load((ROOT / "examples" / "golden_v0.spec.yaml").read_text())
    )
    c = compile_spec(spec)
    assert "AST-ADM-001" in c.meta["address_map"].values()
    assert "adm-01" in c.compose["services"]
    assert "WAZUH_MANAGER" not in c.compose["services"]["adm-01"]["environment"]  # deliberate blind spot


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not available")
def test_compose_validates_with_docker(tmp_path: Path):
    c = compile_spec(sample_spec(SeedSet.from_master(20261102)))
    c.write(tmp_path)
    proc = subprocess.run(
        ["docker", "compose", "-f", str(tmp_path / "compose.yaml"), "config", "--quiet"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr


@pytest.mark.skipif(shutil.which("nft") is None, reason="nft not available")
def test_nft_ruleset_parses(tmp_path: Path):
    c = compile_spec(sample_spec(SeedSet.from_master(20261102)))
    path = tmp_path / "router.nft"
    path.write_text(c.router_nft)
    proc = subprocess.run(["nft", "-c", "-f", str(path)], capture_output=True, text=True, check=False)
    if "Operation not permitted" in proc.stderr:
        pytest.skip("nft check needs CAP_NET_ADMIN")
    assert proc.returncode == 0, proc.stderr
