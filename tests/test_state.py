import pytest

from iris.live.state import RunState, StateError


def _run(tmp_path, name="iris-x"):
    return RunState(tmp_path / "state.json", name)


def test_begin_teardown_from_checking_routes_via_failed(tmp_path):
    s = _run(tmp_path)
    s.to("DEPLOYING")
    s.to("CHECKING")
    s.begin_teardown()  # the old bug: CHECKING -> TEARING_DOWN is illegal directly
    assert s.state == "TEARING_DOWN"
    assert any(h["to"] == "FAILED" for h in s.history)  # routed via FAILED


def test_begin_teardown_direct_from_healthy(tmp_path):
    s = _run(tmp_path)
    s.to("DEPLOYING")
    s.to("CHECKING")
    s.to("HEALTHY")
    s.begin_teardown()
    assert s.state == "TEARING_DOWN"
    assert not any(h["to"] == "FAILED" for h in s.history)


def test_begin_teardown_from_planned(tmp_path):
    s = _run(tmp_path)
    s.begin_teardown()
    assert s.state == "TEARING_DOWN"


def test_begin_teardown_idempotent_when_terminal(tmp_path):
    s = _run(tmp_path)
    s.begin_teardown()
    s.to("TORN_DOWN")
    s.begin_teardown()  # no-op, no raise
    assert s.state == "TORN_DOWN"


def test_illegal_transition_still_raises(tmp_path):
    s = _run(tmp_path)
    with pytest.raises(StateError):
        s.to("HEALTHY")  # PLANNED -> HEALTHY is not allowed
