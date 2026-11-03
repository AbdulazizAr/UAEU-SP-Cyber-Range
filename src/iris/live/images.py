"""Build (or reuse) every image a compiled range needs. Tags are content names chosen by
the compiler; a tag that exists is reused unless ``force``."""

from __future__ import annotations

import time
from typing import Any

from iris.spikes.common import image_exists, images_dir, sh

PULLED = ("jasonish/suricata:8.0.6",)


def build_plan(meta: dict[str, Any]) -> dict[str, dict[str, Any]]:
    builds: dict[str, dict[str, Any]] = meta.get("builds", {})
    return builds


def ensure_images(meta: dict[str, Any], force: bool = False) -> dict[str, float | str]:
    """Returns image -> seconds spent (0.0 when reused, 'pulled' for upstream images)."""
    out: dict[str, float | str] = {}
    for image, spec in sorted(build_plan(meta).items()):
        if image_exists(image) and not force:
            out[image] = 0.0
            continue
        args = [x for k, v in sorted(spec.get("args", {}).items()) for x in ("--build-arg", f"{k}={v}")]
        t0 = time.monotonic()
        sh(["docker", "build", "-t", image, *args, str(images_dir() / spec["context"])], timeout=3600)
        out[image] = round(time.monotonic() - t0, 1)
    for image in meta.get("images", []):
        if image in PULLED and not image_exists(image):
            sh(["docker", "pull", image], timeout=1800)
            out[image] = "pulled"
    return out
