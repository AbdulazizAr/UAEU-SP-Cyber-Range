"""Reference registry, lock file, fetch and verify.

* ``configs/references/registry.yaml`` declares what we use (in git).
* ``configs/references/lock.json`` pins the exact bytes by SHA-256 (in git).
* The files themselves live in ``$IRIS_DATA/references/<id>/`` (not in git).
"""

from __future__ import annotations

import json
import shutil
import urllib.request
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from iris.core.hashing import sha256_file
from iris.core.vclock import iso_z, real_utc_now
from iris.settings import paths, repo_root


class ReferenceError(RuntimeError):
    """A reference is missing, unpinned or does not match its lock."""


@dataclass(frozen=True)
class ReferenceSpec:
    id: str
    title: str
    version: str
    kind: str
    fetch: str  # "url" | "manual"
    filename: str
    license: str
    url: str | None = None
    url_verified: bool = True
    released: date | None = None
    notes: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def local_path(self, data_dir: Path | None = None) -> Path:
        base = data_dir if data_dir is not None else paths().references
        return base / self.id / self.filename


_KNOWN = {
    "id",
    "title",
    "version",
    "kind",
    "fetch",
    "filename",
    "license",
    "url",
    "url_verified",
    "released",
    "notes",
}


def default_registry_path() -> Path:
    return repo_root() / "configs" / "references" / "registry.yaml"


def default_lock_path() -> Path:
    return repo_root() / "configs" / "references" / "lock.json"


def _expand_series(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """A ``series_dates`` entry stands for one dated file per date (e.g. EPSS snapshots).

    ``{date}`` in id, url and filename is replaced; each file is pinned on its own.
    """
    out: list[dict[str, Any]] = []
    for entry in entries:
        dates = entry.get("series_dates")
        if not dates:
            out.append(entry)
            continue
        for d in dates:
            ds = str(d)
            e = {k: v for k, v in entry.items() if k != "series_dates"}
            for key in ("id", "url", "filename", "version", "title"):
                if isinstance(e.get(key), str):
                    e[key] = e[key].replace("{date}", ds)
            e["series"] = entry["id"].replace("-{date}", "").replace("{date}", "")
            e["series_date"] = ds
            out.append(e)
    return out


def load_registry(path: Path | None = None) -> dict[str, ReferenceSpec]:
    raw = yaml.safe_load((path or default_registry_path()).read_text(encoding="utf-8"))
    specs: dict[str, ReferenceSpec] = {}
    for entry in _expand_series(raw.get("references", [])):
        if entry["fetch"] not in {"url", "manual"}:
            raise ReferenceError(f"{entry['id']}: fetch must be 'url' or 'manual'")
        if entry["fetch"] == "url" and not entry.get("url"):
            raise ReferenceError(f"{entry['id']}: fetch=url needs a url")
        spec = ReferenceSpec(
            id=entry["id"],
            title=entry["title"],
            version=str(entry["version"]),
            kind=entry["kind"],
            fetch=entry["fetch"],
            filename=entry["filename"],
            license=entry["license"],
            url=entry.get("url"),
            url_verified=bool(entry.get("url_verified", True)),
            released=entry.get("released"),
            notes=entry.get("notes"),
            extra={k: v for k, v in entry.items() if k not in _KNOWN},
        )
        if spec.id in specs:
            raise ReferenceError(f"duplicate reference id {spec.id}")
        specs[spec.id] = spec
    return specs


def load_lock(path: Path | None = None) -> dict[str, dict[str, Any]]:
    p = path or default_lock_path()
    if not p.exists():
        return {}
    data: dict[str, dict[str, Any]] = json.loads(p.read_text(encoding="utf-8"))
    return data


def save_lock(lock: dict[str, dict[str, Any]], path: Path | None = None) -> None:
    p = path or default_lock_path()
    p.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _lock_entry(spec: ReferenceSpec, file: Path) -> dict[str, Any]:
    return {
        "version": spec.version,
        "filename": spec.filename,
        "sha256": sha256_file(file),
        "size_bytes": file.stat().st_size,
        "pinned_at": iso_z(real_utc_now()),  # real date: provenance only, never scenario content
        "source": spec.url or "manual",
    }


def fetch(
    spec: ReferenceSpec,
    data_dir: Path | None = None,
    lock: dict[str, dict[str, Any]] | None = None,
    timeout: float = 120.0,
) -> dict[str, Any]:
    """Download (or adopt a manually placed) reference file and return its lock entry.

    If the reference is already locked, the downloaded bytes must match the lock;
    a mismatch raises instead of silently re-pinning.
    """
    target = spec.local_path(data_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    if spec.fetch == "manual":
        if not target.exists():
            raise ReferenceError(
                f"{spec.id}: manual reference; place the file at {target}"
                + (f" (source: {spec.url})" if spec.url else "")
            )
    else:
        assert spec.url is not None
        tmp = target.with_suffix(target.suffix + ".part")
        try:
            req = urllib.request.Request(spec.url, headers={"User-Agent": "iris-references/0.1 (+research)"})
            with urllib.request.urlopen(req, timeout=timeout) as resp, tmp.open("wb") as out:
                shutil.copyfileobj(resp, out)
        except Exception as exc:  # network errors differ per platform; report them all the same way
            tmp.unlink(missing_ok=True)
            raise ReferenceError(f"{spec.id}: download failed from {spec.url}: {exc}") from exc
        tmp.replace(target)

    entry = _lock_entry(spec, target)
    if lock is not None and spec.id in lock and lock[spec.id]["sha256"] != entry["sha256"]:
        raise ReferenceError(
            f"{spec.id}: content changed upstream (lock {lock[spec.id]['sha256'][:12]}, "
            f"got {entry['sha256'][:12]}). Review the change, then re-pin with --repin."
        )
    return entry


@dataclass(frozen=True)
class VerifyResult:
    id: str
    status: str  # ok | missing | unpinned | mismatch
    detail: str = ""


def verify(
    specs: dict[str, ReferenceSpec],
    lock: dict[str, dict[str, Any]],
    data_dir: Path | None = None,
) -> list[VerifyResult]:
    results: list[VerifyResult] = []
    for ref_id, spec in sorted(specs.items()):
        file = spec.local_path(data_dir)
        if ref_id not in lock:
            results.append(VerifyResult(ref_id, "unpinned", "not in lock.json"))
        elif not file.exists():
            results.append(VerifyResult(ref_id, "missing", str(file)))
        else:
            got = sha256_file(file)
            want = lock[ref_id]["sha256"]
            status = "ok" if got == want else "mismatch"
            results.append(
                VerifyResult(ref_id, status, "" if status == "ok" else f"{got[:12]} != {want[:12]}")
            )
    return results


def require(ref_id: str, data_dir: Path | None = None) -> Path:
    """Path to a pinned, verified reference file, or a clear error."""
    specs = load_registry()
    if ref_id not in specs:
        raise ReferenceError(f"unknown reference {ref_id}")
    result = verify({ref_id: specs[ref_id]}, load_lock(), data_dir)[0]
    if result.status != "ok":
        raise ReferenceError(f"{ref_id}: {result.status} {result.detail}. Run `iris refs fetch {ref_id}`.")
    return specs[ref_id].local_path(data_dir)


def series(name: str, specs: dict[str, ReferenceSpec] | None = None) -> list[ReferenceSpec]:
    """Members of a dated series, oldest first."""
    specs = specs if specs is not None else load_registry()
    members = [s for s in specs.values() if s.extra.get("series") == name]
    return sorted(members, key=lambda s: str(s.extra["series_date"]))
