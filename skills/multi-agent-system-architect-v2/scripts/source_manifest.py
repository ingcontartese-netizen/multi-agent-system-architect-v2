#!/usr/bin/env python3
"""Build and verify a reproducible SHA-256 manifest for a source tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path


EXCLUDED_DIRS = frozenset({".git", ".pytest_cache", "__pycache__"})
EXCLUDED_SUFFIXES = frozenset({".pyc"})


@dataclass(frozen=True)
class FileRecord:
    path: str
    size: int
    sha256: str

    def manifest_line(self) -> str:
        return f"{self.path}\t{self.size}\t{self.sha256}\n"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def collect_records(root: Path) -> list[FileRecord]:
    records: list[FileRecord] = []
    for candidate in root.rglob("*"):
        relative_parts = candidate.relative_to(root).parts
        if any(part in EXCLUDED_DIRS for part in relative_parts):
            continue
        if candidate.is_symlink():
            raise ValueError(f"Symlinks are not supported: {candidate}")
        if not candidate.is_file() or candidate.suffix.lower() in EXCLUDED_SUFFIXES:
            continue
        data = candidate.read_bytes()
        records.append(
            FileRecord(
                path=candidate.relative_to(root).as_posix(),
                size=len(data),
                sha256=sha256_bytes(data),
            )
        )
    return sorted(records, key=lambda record: record.path)


def fingerprint(records: list[FileRecord]) -> tuple[bytes, str]:
    manifest = "".join(record.manifest_line() for record in records).encode("utf-8")
    return manifest, sha256_bytes(manifest)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Hash every source file and then hash the UTF-8 manifest. Each manifest "
            "record is relative_posix_path<TAB>bytes<TAB>uppercase_sha256<LF>."
        )
    )
    parser.add_argument("root", type=Path, help="Source-tree root")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument("--manifest-out", type=Path, help="Write the canonical manifest")
    parser.add_argument("--expect-files", type=int, help="Fail unless file count matches")
    parser.add_argument("--expect-tree", help="Fail unless tree SHA-256 matches")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    if not root.is_dir():
        print(f"ERROR: not a directory: {root}", file=sys.stderr)
        return 2

    try:
        records = collect_records(root)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    manifest, tree_sha256 = fingerprint(records)
    if args.manifest_out:
        args.manifest_out.parent.mkdir(parents=True, exist_ok=True)
        args.manifest_out.write_bytes(manifest)

    failures: list[str] = []
    if args.expect_files is not None and args.expect_files != len(records):
        failures.append(f"files: expected {args.expect_files}, got {len(records)}")
    if args.expect_tree and args.expect_tree.upper() != tree_sha256:
        failures.append(f"tree: expected {args.expect_tree.upper()}, got {tree_sha256}")

    payload = {
        "algorithm": "relative_posix_path<TAB>bytes<TAB>uppercase_sha256<LF>",
        "encoding": "UTF-8 without BOM",
        "errors": failures,
        "excluded_dirs": sorted(EXCLUDED_DIRS),
        "excluded_suffixes": sorted(EXCLUDED_SUFFIXES),
        "files": len(records),
        "records": [record.__dict__ for record in records],
        "root": str(root),
        "status": "fail" if failures else "pass",
        "tree_sha256": tree_sha256,
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"root: {root}")
        print(f"files: {len(records)}")
        print(f"tree_sha256: {tree_sha256}")
        for record in records:
            print(record.manifest_line(), end="")

    for failure in failures:
        print(f"MISMATCH: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
