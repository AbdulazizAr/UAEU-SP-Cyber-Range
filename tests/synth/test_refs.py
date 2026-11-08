"""Phase 1 gate: the committed reference bundles are pinned and match lock.json, and the
ATT&CK bundle covers the techniques the F1-F9 families use."""

from __future__ import annotations

from iris.synth import refs

# Linux-valid ATT&CK techniques referenced by the synth attack families (file 05).
FAMILY_TECHNIQUES = [
    "T1110",
    "T1110.001",
    "T1110.003",
    "T1078",  # F1 credential
    "T1190",  # F2 web
    "T1548",
    "T1068",
    "T1213",  # F3 access/privilege
    "T1046",
    "T1018",
    "T1595",  # F4 recon
    "T1021.004",
    "T1550",
    "T1021",  # F5 lateral
    "T1041",
    "T1048",
    "T1567",  # F6 exfil
    "T1098",
    "T1053",
    "T1136",
    "T1070",
    "T1556",  # F7 persistence
    "T1039",  # F8 insider
    "T1071",
    "T1071.001",
    "T1571",  # F9 C2
]


def test_all_bundles_pinned_and_matching():
    checks = {c.bundle_id: c.status for c in refs.verify_bundles()}
    assert set(checks) == set(refs.BUNDLE_IDS)
    assert all(status == "ok" for status in checks.values()), checks


def test_attack_bundle_is_v20_and_covers_families():
    cat = refs.attack_catalog()
    assert cat.version == "20.0"
    missing = [t for t in FAMILY_TECHNIQUES if t not in cat.techniques]
    assert not missing, f"techniques missing from pinned ATT&CK: {missing}"
    # tactic names come from the pinned data, not code
    assert cat.get("T1110.001").tactics == ("credential-access",)


def test_wazuh_and_suricata_bundles_have_real_files():
    wz = refs.require_bundle("wazuh-ruleset")
    assert (wz / "rules" / "0095-sshd_rules.xml").exists()
    assert (wz / "decoders" / "0310-ssh_decoders.xml").exists()
    sr = refs.require_bundle("suricata-rules")
    assert (sr / "ssh-events.rules").exists()


def test_bundle_digest_changes_on_edit(tmp_path):
    d = tmp_path / "b"
    (d / "sub").mkdir(parents=True)
    (d / "sub" / "a.txt").write_text("one")
    first, nfiles, _ = refs.bundle_digest(d)
    assert nfiles == 1
    (d / "sub" / "a.txt").write_text("two")
    assert refs.bundle_digest(d)[0] != first
