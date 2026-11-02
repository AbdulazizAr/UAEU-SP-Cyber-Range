"""Run Trivy on lab machines: one offline scan per image, cached by image digest.

Hardening (the Trivy supply-chain compromise of March 2026 hit 0.69.4-0.69.6):
- Trivy is pinned to an exact version, and its image digest is recorded in every cache entry.
- Scans run with ``--network none`` and no Docker socket. The image under test is
  passed in as a ``docker save`` tarball and the DB is a pinned local snapshot.
- Only ``iris posture db`` has network access, to download that DB snapshot once.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from iris.generator.posture.trivy import cache_dir, cache_path, parse_trivy, safe_name
from iris.settings import paths

TRIVY_VERSION = "0.76.1"
TRIVY_IMAGE = f"aquasec/trivy:{TRIVY_VERSION}"


@dataclass(frozen=True)
class DbSnapshot:
    root: Path  # directory holding db/trivy.db and db/metadata.json
    updated_at: str | None
    sha256: str | None


def _run(cmd: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, check=True, text=True, capture_output=True, **kw)


def image_digest(image: str) -> str | None:
    try:
        out = _run(["docker", "image", "inspect", "--format", "{{.Id}}", image]).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return out or None


def trivy_tool_digest() -> str | None:
    try:
        out = _run(["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", TRIVY_IMAGE]).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    digests = json.loads(out or "[]")
    return digests[0] if digests else None


def download_db_cmd(cache: Path) -> list[str]:
    return [
        "docker", "run", "--rm",
        "-v", f"{cache}:/cache",
        TRIVY_IMAGE, "image", "--download-db-only", "--cache-dir", "/cache",
    ]  # fmt: skip


def scan_cmd(db_root: Path, tar_dir: Path, tar_name: str, out_dir: Path, out_name: str) -> list[str]:
    return [
        "docker", "run", "--rm", "--network", "none",
        "-v", f"{db_root}:/cache",
        "-v", f"{tar_dir}:/in:ro",
        "-v", f"{out_dir}:/out",
        TRIVY_IMAGE, "image",
        "--input", f"/in/{tar_name}",
        "--cache-dir", "/cache",
        "--skip-db-update", "--skip-java-db-update", "--offline-scan",
        "--scanners", "vuln", "--list-all-pkgs",
        "--format", "json", "--output", f"/out/{out_name}",
    ]  # fmt: skip


def make_db_snapshot(data_dir: Path | None = None) -> Path:
    """Download the current Trivy DB and pack it as the ``trivy-db`` reference tarball."""
    ref_dir = (data_dir or paths().references) / "trivy-db"
    ref_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        _run(download_db_cmd(Path(tmp)))
        target = ref_dir / "trivy-db.tar.gz"
        with tarfile.open(target, "w:gz") as tar:
            tar.add(Path(tmp) / "db", arcname="db")
    return target


def unpack_db(tarball: Path, sha256: str, data_dir: Path | None = None) -> DbSnapshot:
    root = (data_dir or paths().data) / "cache" / "trivy-db" / sha256[:16]
    if not (root / "db" / "trivy.db").exists():
        root.mkdir(parents=True, exist_ok=True)
        with tarfile.open(tarball, "r:gz") as tar:
            tar.extractall(root, filter="data")
    meta_file = root / "db" / "metadata.json"
    updated = json.loads(meta_file.read_text())["UpdatedAt"] if meta_file.exists() else None
    return DbSnapshot(root, updated, sha256)


def scan_image(image: str, db: DbSnapshot, data_dir: Path | None = None, force: bool = False) -> Path:
    """Scan one built image offline and store the cache entry. Returns the cache path."""
    target = cache_path(image, data_dir)
    digest = image_digest(image)
    if digest is None:
        raise RuntimeError(f"image {image} is not built on this machine")
    if target.exists() and not force:
        cached = json.loads(target.read_text())
        if cached.get("image_id") == digest and cached.get("db", {}).get("sha256") == db.sha256:
            return target
    cache_dir(data_dir).mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        tdir = Path(tmp)
        (tdir / "in").mkdir()
        (tdir / "out").mkdir()
        tar_name = f"{safe_name(image)}.tar"
        _run(["docker", "save", "-o", str(tdir / "in" / tar_name), image])
        _run(scan_cmd(db.root, tdir / "in", tar_name, tdir / "out", "report.json"))
        report = json.loads((tdir / "out" / "report.json").read_text())
    report.pop("CreatedAt", None)  # wall-clock time of the scan run: never part of a scenario
    rep = parse_trivy(report, image=image)
    wrapper = {
        "image": image,
        "image_id": digest,
        "scanner": {"name": "trivy", "version": TRIVY_VERSION, "tool_digest": trivy_tool_digest()},
        "db": {"sha256": db.sha256, "updated_at": db.updated_at},
        "summary": {"packages": len(rep.packages), "cves": len({v.cve_id for v in rep.vulns})},
        "report": report,
    }
    target.write_text(json.dumps(wrapper, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return target


def docker_available() -> bool:
    return shutil.which("docker") is not None
