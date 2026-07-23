#!/usr/bin/env python3
"""Verify named source mechanisms remain present after transformation."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from _common import ContractError, emit, load_structured, read_utf8


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("requirements", type=Path)
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def count_matches(root: Path, glob: str, pattern: re.Pattern[str]) -> tuple[int, int]:
    matches = 0
    files = 0
    for path in sorted(root.glob(glob)):
        if not path.is_file():
            continue
        files += 1
        matches += len(pattern.findall(read_utf8(path)))
    return matches, files


def main() -> int:
    args = parse_args()
    source = args.source.resolve()
    candidate = args.candidate.resolve()
    errors: list[str] = []
    results = []
    try:
        if not source.is_dir() or not candidate.is_dir():
            raise ContractError("source and candidate must be directories")
        spec = load_structured(args.requirements.resolve())
        requirements = spec.get("requirements", []) if isinstance(spec, dict) else []
        if not requirements:
            raise ContractError("retention requirements are empty")
        for index, item in enumerate(requirements):
            if not isinstance(item, dict) or not item.get("id") or not item.get("pattern"):
                raise ContractError(f"invalid retention requirement at index {index}")
            try:
                pattern = re.compile(item["pattern"], re.MULTILINE)
            except re.error as exc:
                raise ContractError(f"invalid regex for {item['id']}: {exc}") from exc
            source_count, source_files = count_matches(
                source, item.get("source_glob", "**/*"), pattern
            )
            candidate_count, candidate_files = count_matches(
                candidate, item.get("candidate_glob", "**/*"), pattern
            )
            minimum = int(item.get("minimum", 1))
            required_count = max(minimum, source_count) if item.get("preserve_source_count") else minimum
            passed = candidate_count >= required_count
            if not passed:
                errors.append(
                    f"{item['id']}: candidate {candidate_count}, required {required_count}"
                )
            results.append(
                {
                    "id": item["id"],
                    "source_count": source_count,
                    "candidate_count": candidate_count,
                    "required_count": required_count,
                    "source_files": source_files,
                    "candidate_files": candidate_files,
                    "status": "pass" if passed else "fail",
                }
            )
    except (OSError, ContractError, ValueError) as exc:
        errors.append(str(exc))
    passed_count = sum(item["status"] == "pass" for item in results)
    payload = {
        "status": "pass" if not errors else "fail",
        "processed_expected": f"{passed_count}/{len(results)}",
        "results": results,
        "errors": errors,
    }
    emit(payload, args.json)
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
