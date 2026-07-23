#!/usr/bin/env python3
"""Validate the seven-field Cuneo provenance contract."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from _common import ContractError, emit, load_structured, validate_bundle


SEVEN_FIELDS = [
    "sources_read",
    "source_versions",
    "sections_consulted",
    "material_not_used",
    "facts_extracted",
    "model_synthesis",
    "conflicts_gaps_limits",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--skill-root", type=Path)
    parser.add_argument("--allow-draft", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def contains_private_reasoning(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            str(key).lower().replace("-", "_") in {"chain_of_thought", "private_reasoning", "hidden_reasoning"}
            or contains_private_reasoning(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(contains_private_reasoning(item) for item in value)
    return False


def main() -> int:
    args = parse_args()
    manifest_path = args.manifest.resolve()
    skill_root = (args.skill_root or Path(__file__).resolve().parents[1]).resolve()
    errors: list[str] = []
    try:
        data = load_structured(manifest_path)
        validate_bundle(data, "provenanceManifest", skill_root)
        status = data.get("document_status")
        if status == "draft" and not args.allow_draft:
            errors.append("draft provenance requires --allow-draft")
        if status in {"ready", "approved"}:
            sources = data.get("sources_read", [])
            source_ids = {
                item.get("id") for item in sources if isinstance(item, dict) and item.get("id")
            }
            for index, item in enumerate(sources):
                if not isinstance(item, dict) or not item.get("id") or not item.get("locator"):
                    errors.append(f"sources_read[{index}] needs id and locator")
            for field in ("source_versions", "sections_consulted"):
                for index, item in enumerate(data.get(field, [])):
                    if not isinstance(item, dict) or item.get("source_id") not in source_ids:
                        errors.append(f"{field}[{index}] has no valid source_id")
            for index, fact in enumerate(data.get("facts_extracted", [])):
                refs = fact.get("source_ids", []) if isinstance(fact, dict) else []
                if not refs or not set(refs).issubset(source_ids):
                    errors.append(f"facts_extracted[{index}] needs valid source_ids")
            for index, item in enumerate(data.get("model_synthesis", [])):
                if not isinstance(item, dict) or not item.get("description") or not item.get("basis"):
                    errors.append(f"model_synthesis[{index}] needs description and basis")
            for field in ("material_not_used", "conflicts_gaps_limits"):
                for index, item in enumerate(data.get(field, [])):
                    if not isinstance(item, dict) or not item.get("reason", item.get("description")):
                        errors.append(f"{field}[{index}] needs an explicit reason or description")
        if contains_private_reasoning(data):
            errors.append("private chain-of-thought fields are forbidden")
    except (OSError, ContractError) as exc:
        errors.append(str(exc))

    populated = sum(bool(data.get(field)) for field in SEVEN_FIELDS) if "data" in locals() else 0
    payload = {
        "status": "pass" if not errors else "fail",
        "fields_present": f"{sum(field in data for field in SEVEN_FIELDS) if 'data' in locals() else 0}/7",
        "fields_populated": f"{populated}/7",
        "errors": errors,
    }
    emit(payload, args.json)
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
