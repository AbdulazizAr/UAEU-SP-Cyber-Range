"""Export JSON Schemas for every contract model (shared with the Engine team)."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel

from iris.contracts.decisions import DecisionRecord
from iris.contracts.spec import ScenarioSpec
from iris.contracts.visible import VISIBLE_MODELS


def all_models() -> dict[str, type[BaseModel]]:
    models: dict[str, type[BaseModel]] = {
        "scenario_spec": ScenarioSpec,
        "engine.decision_record": DecisionRecord,
    }
    models.update({f"visible.{k}": v for k, v in VISIBLE_MODELS.items()})
    return models


def export_schemas(out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, model in sorted(all_models().items()):
        schema = model.model_json_schema(mode="serialization")
        schema["$id"] = f"iris:{name}"
        path = out_dir / f"{name}.schema.json"
        path.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        written.append(path)
    return written
