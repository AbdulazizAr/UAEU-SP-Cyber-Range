"""Shared helpers for spikes: Docker CLI calls, waiting, results recording."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from iris.core.vclock import iso_z, real_utc_now
from iris.settings import paths, repo_root


class SpikeError(RuntimeError):
    pass


@dataclass
class Check:
    name: str
    status: str  # pass | fail | skip | info
    value: Any = None
    detail: str = ""


@dataclass
class SpikeResult:
    spike: str
    started_at_real: str
    checks: list[Check] = field(default_factory=list)
    measurements: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def check(self, name: str, ok: bool | None, value: Any = None, detail: str = "") -> bool:
        status = "info" if ok is None else ("pass" if ok else "fail")
        self.checks.append(Check(name, status, value, detail))
        return bool(ok)

    def measure(self, name: str, value: Any) -> None:
        self.measurements[name] = value

    @property
    def passed(self) -> bool:
        return not self.errors and all(c.status != "fail" for c in self.checks)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["passed"] = self.passed
        return d


def new_run_dir(name: str) -> Path:
    stamp = iso_z(real_utc_now()).replace(":", "").replace("-", "")
    run_dir = paths().runs / "spikes" / f"{stamp}-{name}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def write_result(result: SpikeResult, run_dir: Path) -> Path:
    out = run_dir / "results.json"
    out.write_text(json.dumps(result.to_dict(), indent=2, default=str) + "\n", encoding="utf-8")
    return out


def sh(
    args: list[str],
    *,
    check: bool = True,
    timeout: float = 600,
    env: Mapping[str, str] | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    full_env = None
    if env is not None:
        import os

        full_env = {**os.environ, **env}
    proc = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=full_env,
        input=input_text,
        check=False,
    )
    if check and proc.returncode != 0:
        raise SpikeError(
            f"command failed ({proc.returncode}): {' '.join(args)}\n{proc.stderr.strip()[-2000:]}"
        )
    return proc


def require_docker() -> None:
    if shutil.which("docker") is None:
        raise SpikeError("docker CLI not found")
    proc = sh(["docker", "info", "--format", "{{.ServerVersion}}"], check=False, timeout=30)
    if proc.returncode != 0:
        raise SpikeError("docker daemon not reachable (is your user in the docker group?)")


def build_image(tag: str, context: Path) -> float:
    t0 = time.monotonic()
    sh(["docker", "build", "-t", tag, str(context)], timeout=1800)
    return round(time.monotonic() - t0, 1)


def image_exists(tag: str) -> bool:
    return sh(["docker", "image", "inspect", tag], check=False, timeout=30).returncode == 0


def docker_exec(container: str, cmd: str, timeout: float = 120, check: bool = True) -> str:
    return sh(["docker", "exec", container, "sh", "-c", cmd], timeout=timeout, check=check).stdout


def compose(project: str, file: Path, args: list[str], env: Mapping[str, str] | None = None) -> str:
    return sh(["docker", "compose", "-p", project, "-f", str(file), *args], env=env, timeout=900).stdout


_MEM = re.compile(r"^\s*([\d.]+)\s*([KMG]i?B)")
_UNITS = {"KiB": 1 / 1024, "KB": 1 / 1024, "MiB": 1, "MB": 1, "GiB": 1024, "GB": 1024}


def parse_mem_mib(text: str) -> float | None:
    """'123.4MiB / 14.77GiB' -> 123.4"""
    m = _MEM.match(text)
    if not m:
        return None
    return round(float(m.group(1)) * _UNITS[m.group(2)], 1)


def mem_mib(container: str) -> float | None:
    proc = sh(
        ["docker", "stats", "--no-stream", "--format", "{{.MemUsage}}", container], check=False, timeout=60
    )
    return parse_mem_mib(proc.stdout) if proc.returncode == 0 else None


def wait_until(predicate: Callable[[], bool], timeout: float, interval: float = 2.0) -> tuple[bool, float]:
    """Poll ``predicate`` until true or timeout; return (ok, seconds waited)."""
    t0 = time.monotonic()
    while True:
        try:
            if predicate():
                return True, round(time.monotonic() - t0, 1)
        except SpikeError:
            pass
        if time.monotonic() - t0 > timeout:
            return False, round(time.monotonic() - t0, 1)
        time.sleep(interval)


def spike_file(name: str) -> Path:
    return repo_root() / "spikes" / name


def images_dir() -> Path:
    return repo_root() / "images"
