#!/usr/bin/env python3
"""Compare structured payloads at path, type, order, and value grain."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from _common import ContractError, emit, load_structured, sha256_bytes


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--structure-only", action="store_true")
    parser.add_argument("--allow-additions", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def inventory(value: Any, path: str = "$") -> dict[str, tuple[str, str]]:
    result: dict[str, tuple[str, str]] = {}
    if isinstance(value, dict):
        result[path] = ("object", str(len(value)))
        for key in sorted(value):
            result.update(inventory(value[key], f"{path}.{key}"))
    elif isinstance(value, list):
        result[path] = ("array", str(len(value)))
        for index, item in enumerate(value):
            result.update(inventory(item, f"{path}[{index}]"))
    else:
        encoded = json.dumps(value, sort_keys=True, ensure_ascii=False).encode("utf-8")
        result[path] = (type(value).__name__, sha256_bytes(encoded))
    return result


def main() -> int:
    args = parse_args()
    try:
        before = inventory(load_structured(args.source.resolve()))
        after = inventory(load_structured(args.candidate.resolve()))
    except (OSError, ContractError) as exc:
        emit({"status": "error", "error": str(exc)}, args.json)
        return 2

    before_paths, after_paths = set(before), set(after)
    missing = sorted(before_paths - after_paths)
    additions = sorted(after_paths - before_paths)
    type_changes = sorted(
        path for path in before_paths & after_paths if before[path][0] != after[path][0]
    )
    value_changes = []
    if not args.structure_only:
        value_changes = sorted(
            path
            for path in before_paths & after_paths
            if before[path][0] == after[path][0] and before[path][1] != after[path][1]
        )
    failures = len(missing) + len(type_changes) + len(value_changes)
    if additions and not args.allow_additions:
        failures += len(additions)
    payload = {
        "status": "pass" if failures == 0 else "fail",
        "source_paths": len(before_paths),
        "candidate_paths": len(after_paths),
        "processed_expected": f"{len(before_paths - set(missing))}/{len(before_paths)}",
        "missing": missing,
        "additions": additions,
        "type_changes": type_changes,
        "value_changes": value_changes,
        "structure_only": args.structure_only,
        "allow_additions": args.allow_additions,
    }
    emit(payload, args.json)
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
