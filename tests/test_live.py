import py_compile
import re
import subprocess

import pytest

from iris.core.seeds import SeedSet
from iris.generator.catalog import load_catalog
from iris.generator.compiler import compile_spec, node_env
from iris.generator.invariants import check
from iris.generator.sampler import SampleOverrides, sample_spec
from iris.generator.secrets import scenario_secrets
from iris.live.health import WEAKNESS_PROBES, HealthGate, Target, init_status, parse_ss
from iris.live.state import RunState, StateError

from .conftest_paths import ROOT

LIVE = load_catalog().live


@pytest.fixture(scope="module")
def specs():
    return [sample_spec(SeedSet.from_master(m), SampleOverrides(live=True)) for m in range(120)]


def test_live_specs_stay_inside_the_build_matrix(specs):
    for s in specs:
        assert not check(s)
        assert s.archetype == LIVE["archetype"] and s.organization.size.value == LIVE["size"]
        assert all(a.os_profile == LIVE["os_profile"] for a in s.assets)
        assert all(sv.version == LIVE["recipes"][sv.recipe] for sv in s.services)
        assert all(w.module in LIVE["weaknesses"] for w in s.weaknesses)


def test_every_live_weakness_has_a_probe_and_a_recipe_in_the_image():
    assert set(LIVE["weaknesses"]) <= set(WEAKNESS_PROBES)
    dockerfile = (ROOT / "images" / "node" / "debian-12" / "Dockerfile").read_text()
    for recipe in LIVE["recipes"]:
        if recipe != "wazuh_manager":
            assert re.search(rf"^\s+{recipe}\)", dockerfile, re.M), recipe


def test_node_env_wires_services(specs):
    for s in specs[:40]:
        sec = scenario_secrets(s)
        ip = {a.asset_id: a.attachments[0].ip for a in s.assets if a.attachments}
        for a in s.assets:
            if not a.attachments or a.role.value in ("router_firewall", "siem"):
                continue
            env = node_env(s, a.asset_id, sec)
            planted = sorted({w.module for w in s.weaknesses if w.asset_id == a.asset_id})
            assert env["IRIS_WEAKNESSES"] == ",".join(planted)
            if "IRIS_DB" in env:
                db_ip = env["IRIS_DB"].split(":")[0]
                assert db_ip in ip.values()
                db_asset = next(k for k, v in ip.items() if v == db_ip)
                assert ip[a.asset_id] in node_env(s, db_asset, sec)["IRIS_DB_CLIENTS"].split(",")
            if "IRIS_DNS_RECORDS" in env:
                for x in s.assets:
                    if x.attachments:
                        assert f"{x.hostname}={x.attachments[0].ip}" in env["IRIS_DNS_RECORDS"]


def test_secrets_follow_weaknesses(specs):
    for s in specs:
        sec = scenario_secrets(s)
        for w in s.weaknesses:
            if w.module == "db.default_creds":
                assert sec.postgres[w.asset_id] == "postgres"
            if w.module == "auth.ssh_root_login":
                assert f"root:{w.asset_id}" in sec.weak
        strong = [p for k, p in sec.root.items() if f"root:{k}" not in sec.weak]
        assert all(len(p) == 20 for p in strong)
        assert scenario_secrets(s).to_dict() == sec.to_dict()  # deterministic


def test_compiled_live_range(specs):
    c = compile_spec(specs[0])
    text = str(c.compose)
    assert "FAKETIME" not in text and "LD_PRELOAD" not in text
    nodes = {k: v for k, v in c.meta["builds"].items() if "node-" in k}
    assert nodes and all(v["context"] == "node/debian-12" for v in nodes.values())
    assert c.meta["secrets"]["app_db"]
    assert set(c.meta["builds"]) <= set(c.meta["images"])


def test_parsers():
    ss = (
        "tcp   LISTEN 0      511          0.0.0.0:80         0.0.0.0:*\n"
        "tcp   LISTEN 0      128             [::]:22            [::]:*\n"
        "udp   UNCONN 0      0            0.0.0.0:53         0.0.0.0:*\n"
    )
    assert parse_ss(ss) == {("tcp", 80), ("tcp", 22), ("udp", 53)}
    log = "node-init: route ok via 10.0.0.1\nnode-init: nginx FAIL bad\nnode-init: ready\n"
    assert init_status(log) == (True, ["node-init: nginx FAIL bad"])
    assert init_status("node-init: route ok") == (False, [])


def test_health_gate_with_a_fake_host(specs):
    s = next(x for x in specs if x.weaknesses)
    planted = {(w.module, w.asset_id) for w in s.weaknesses}
    t = Target(s, "iris-test", {})
    host_of = {t.container(a.asset_id): a.asset_id for a in s.assets}

    def fake(container: str, cmd: str) -> str:
        aid = host_of.get(container)
        if cmd.startswith("ss "):
            return "".join(
                f"{sv.protocol}   LISTEN 0 1 0.0.0.0:{sv.port} 0.0.0.0:*\n"
                for sv in s.services
                if sv.asset_id == aid
            )
        for module, probe in WEAKNESS_PROBES.items():
            if cmd.startswith(probe.split("{port}")[0][:40]) and (module, aid) in planted:
                return "__OK__\n"
        return ""

    g = HealthGate(t, run=fake)
    g.ports()
    g.weaknesses()
    status = {c.name: c.status for c in g.r.checks}
    assert status["ports.listening"] == "pass"
    assert status["weaknesses.planted_present"] == "pass"
    assert status["weaknesses.unplanted_absent"] == "pass"


def test_state_machine(tmp_path):
    st = RunState(tmp_path / "state.json", "iris-x")
    for s in ("BUILDING", "DEPLOYING", "CHECKING", "HEALTHY", "TEARING_DOWN", "TORN_DOWN"):
        st.to(s)
    assert (tmp_path / "state.json").exists()
    with pytest.raises(StateError):
        st.to("DEPLOYING")


def test_image_scripts_are_valid():
    scripts = sorted((ROOT / "images").rglob("*.sh"))
    assert len(scripts) >= 5
    for sh in scripts:
        subprocess.run(["bash", "-n", str(sh)], check=True)
    py_compile.compile(str(ROOT / "images" / "node" / "debian-12" / "shop" / "app.py"), doraise=True)


def test_subnet_conflicts(specs):
    from iris.live.deploy import subnet_conflicts

    s = specs[0]
    zone = next(z for z in s.zones if z.name != "internet")
    assert subnet_conflicts(s, {"bridge": ["10.250.0.0/16"]}) == [] or zone.subnet.startswith("10.25")
    hits = subnet_conflicts(s, {"other_default": [zone.subnet.rsplit(".", 2)[0] + ".0.0/16"]})
    assert hits and "other_default" in hits[0]


def test_weak_tls_only_on_tls_services():
    for m in range(300):
        s = sample_spec(SeedSet.from_master(m), SampleOverrides(live=True))
        tls = {x.service_id: x.tls for x in s.services}
        assert all(tls[w.service_id] for w in s.weaknesses if w.module == "tls.weak_config")


def test_gate_checks_conflicts_before_deploying(monkeypatch):
    from iris.live import deploy as d
    from iris.live import gate

    monkeypatch.setattr(gate, "require_docker", lambda: None)
    monkeypatch.setattr(d, "running_projects", lambda: {})
    monkeypatch.setattr(
        d, "docker_subnets", lambda: {"old": ["172.18.0.0/16", "10.0.0.0/8", "192.168.0.0/16"]}
    )
    monkeypatch.setattr(d, "new_run", lambda spec: (_ for _ in ()).throw(AssertionError("must not deploy")))
    sm = gate.run_once(11, build=False)
    assert sm.state == "SKIPPED_CONFLICT" and sm.conflict
