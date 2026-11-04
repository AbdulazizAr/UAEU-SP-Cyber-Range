from iris.cli_ui import Progress, Spinner, bar, fmt_dur, result_line


def test_fmt_dur():
    assert fmt_dur(0) == "00:00"
    assert fmt_dur(5) == "00:05"
    assert fmt_dur(65) == "01:05"
    assert fmt_dur(3665) == "1:01:05"
    assert fmt_dur(-3) == "00:00"  # clamped


def test_bar():
    assert bar(0.0, 4) == "░░░░"
    assert bar(1.0, 4) == "████"
    assert bar(0.5, 10) == "█████░░░░░"
    assert bar(2.0, 4) == "████"  # clamps over 1
    assert bar(-1.0, 4) == "░░░░"  # clamps under 0


def test_progress_line_and_eta():
    p = Progress(total=4)
    assert p.eta() is None  # nothing done yet
    p.start -= 10  # pretend 10s have passed
    p.tick()
    assert p.frac == 0.25
    line = p.line()
    assert "25%" in line and "1/4" in line and "left" in line


def test_progress_complete():
    p = Progress(total=2)
    p.tick(2)
    assert p.frac == 1.0
    assert "100%" in p.line()


def test_spinner_non_tty_is_quiet(capsys):
    # enabled=False -> no animation thread, just plain phase lines
    with Spinner("starting", enabled=False) as sp:
        sp.set_label("working")
    out = capsys.readouterr().out
    assert "starting" in out and "working" in out


def test_result_line_renders(capsys):
    result_line(True, "[1/3] grp-x", "15 fragments", 131.0, Progress(total=3, done=1))
    out = capsys.readouterr().out
    assert "grp-x" in out and "15 fragments" in out and "1/3" in out
