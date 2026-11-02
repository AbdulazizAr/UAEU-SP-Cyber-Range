import json
from pathlib import Path

from click.testing import CliRunner

from iris.cli import main
from iris.devtools.boundaries import check_tree

ROOT = Path(__file__).resolve().parents[1]


def _write(base: Path, rel: str, text: str) -> None:
    p = base / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def test_repository_has_no_violations():
    assert check_tree(ROOT / "src") == []


def test_real_clock_ban(tmp_path):
    _write(tmp_path, "iris/generator/bad.py", "import datetime\nx = datetime.datetime.now()\n")
    _write(tmp_path, "iris/generator/bad2.py", "from time import time\n")
    _write(tmp_path, "iris/generator/bad3.py", "import time\ny = time.time()\n")
    _write(tmp_path, "iris/core/vclock.py", "from datetime import datetime\nz = datetime.now()\n")
    rules = sorted((v.path, v.rule) for v in check_tree(tmp_path))
    assert rules == [
        ("iris/generator/bad.py", "real-clock"),
        ("iris/generator/bad2.py", "real-clock"),
        ("iris/generator/bad3.py", "real-clock"),
    ]


def test_import_boundaries(tmp_path):
    _write(tmp_path, "iris/engine/model.py", "from iris.oracle.rules import x\nimport iris.generator.lanes\n")
    _write(tmp_path, "iris/oracle/rules.py", "from iris.engine import model\n")
    _write(tmp_path, "iris/generator/ok.py", "from iris.contracts import spec\n")
    found = sorted((v.path, v.detail) for v in check_tree(tmp_path))
    assert found == [
        ("iris/engine/model.py", "iris.engine.model imports iris.generator.lanes"),
        ("iris/engine/model.py", "iris.engine.model imports iris.oracle.rules"),
        ("iris/oracle/rules.py", "iris.oracle.rules imports iris.engine"),
    ]


def test_cli_seeds_and_spec():
    runner = CliRunner()
    res = runner.invoke(main, ["seeds", "derive", "--master", "20261102", "--override", "attack=42"])
    assert res.exit_code == 0, res.output
    out = json.loads(res.output)
    assert out["group_id"] == "grp-31f730e65d1b" and out["overridden"] == ["attack"]

    res = runner.invoke(main, ["spec", "validate", str(ROOT / "examples" / "golden_v0.spec.yaml")])
    assert res.exit_code == 0, res.output
    assert "group=grp-31f730e65d1b" in res.output


def test_cli_spec_validate_fails_on_bad_file(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("spec_version: '0.1.0'\n")
    res = CliRunner().invoke(main, ["spec", "validate", str(bad)])
    assert res.exit_code == 1 and "FAIL" in res.output


def test_cli_schema_export(tmp_path):
    res = CliRunner().invoke(main, ["schema", "export", "--out", str(tmp_path)])
    assert res.exit_code == 0, res.output
    assert (tmp_path / "engine.decision_record.schema.json").exists()


def test_cli_data_init(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_DATA", str(tmp_path / "data"))
    res = CliRunner().invoke(main, ["data", "init"])
    assert res.exit_code == 0
    assert (tmp_path / "data" / "references").is_dir()
