#!/usr/bin/env python3
"""Score same-category candidates without emitting an automatic winner."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from _common import ContractError, emit, load_structured, validate_bundle


STATUS_VALUE = {"verified": 1.0, "partial": 0.5, "absent": 0.0, "unknown": None}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("catalog", type=Path)
    parser.add_argument("criteria", type=Path)
    parser.add_argument("--category", required=True)
    parser.add_argument("--skill-root", type=Path)
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def capability(candidate: dict[str, Any], key: str) -> dict[str, Any] | None:
    if key in {"durability", "hitl", "sandbox"}:
        return candidate.get(key)
    return candidate.get("capabilities", {}).get(key)


def score(candidate: dict[str, Any], criteria: list[dict[str, Any]]) -> dict[str, Any]:
    weighted = 0.0
    total = 0.0
    uncertainty = []
    disqualifiers = []
    evidence = []
    for item in criteria:
        key = item["capability"]
        weight = float(item["weight"])
        record = capability(candidate, key)
        status = record.get("status") if record else "unknown"
        value = STATUS_VALUE.get(status)
        evidence.append({"capability": key, "status": status, "weight": weight})
        if value is None:
            uncertainty.append(key)
            if item.get("required"):
                disqualifiers.append(f"required evidence unknown: {key}")
            continue
        if item.get("required") and value == 0.0:
            disqualifiers.append(f"required capability absent: {key}")
        weighted += weight * value
        total += weight
    return {
        "id": candidate["id"],
        "score": round(100 * weighted / total, 2) if total else None,
        "uncertainty": uncertainty,
        "disqualifiers": disqualifiers,
        "evidence": evidence,
    }


def ranking(options: list[dict[str, Any]]) -> list[str]:
    eligible = [item for item in options if not item["disqualifiers"] and item["score"] is not None]
    return [item["id"] for item in sorted(eligible, key=lambda item: (-item["score"], item["id"]))]


def main() -> int:
    args = parse_args()
    root = (args.skill_root or Path(__file__).resolve().parents[1]).resolve()
    errors: list[str] = []
    try:
        catalog = load_structured(args.catalog.resolve())
        validate_bundle(catalog, "frameworkCatalog", root)
        request = load_structured(args.criteria.resolve())
        criteria = request.get("criteria", [])
        if not criteria:
            raise ContractError("criteria list is empty")
        for index, item in enumerate(criteria):
            if not isinstance(item, dict) or not item.get("capability") or float(item.get("weight", 0)) <= 0:
                raise ContractError(f"invalid criterion at index {index}")
        candidates = [
            item for item in catalog["candidates"] if args.category in item["object_categories"]
        ]
        if not candidates:
            raise ContractError(f"no candidates in category: {args.category}")
        options = [score(item, criteria) for item in candidates]
        base_order = ranking(options)
        sensitivity = []
        for index, criterion in enumerate(criteria):
            for factor in (0.5, 2.0):
                adjusted = [dict(item) for item in criteria]
                adjusted[index]["weight"] = float(adjusted[index]["weight"]) * factor
                order = ranking([score(item, adjusted) for item in candidates])
                sensitivity.append(
                    {
                        "capability": criterion["capability"],
                        "factor": factor,
                        "ranking": order,
                        "changed": order != base_order,
                    }
                )
        payload = {
            "status": "pass",
            "category": args.category,
            "options": sorted(options, key=lambda item: item["id"]),
            "ranking": base_order,
            "sensitivity": sensitivity,
            "sensitive": any(item["changed"] for item in sensitivity),
            "decision": None,
            "decision_rule": "Human/ADR decision required; score is evidence, not authority.",
        }
    except (OSError, ValueError, ContractError) as exc:
        errors.append(str(exc))
        payload = {"status": "fail", "errors": errors, "decision": None}
    emit(payload, args.json)
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
