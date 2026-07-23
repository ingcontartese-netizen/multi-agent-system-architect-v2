#!/usr/bin/env python3
"""Verify the fixed three-host adapter bundle against the canonical skill."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any

sys.dont_write_bytecode = True

from _common import (
    ContractError,
    REQUIRED_HOST_COUNT,
    REQUIRED_HOST_IDS,
    emit,
    is_relative_to,
    parse_project_version,
    parse_structured_text,
    validate_host_config,
    validate_host_contract,
)
from source_manifest import FileRecord, fingerprint, sha256_bytes


MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "canonical_name",
        "canonical_version",
        "canonical_files",
        "canonical_tree_sha256",
        "entries",
        "doctrine_forks",
    }
)
ENTRY_KEYS = frozenset(
    {"host", "relative_path", "files", "tree_sha256"}
)
SHA256_RE = re.compile(r"[0-9A-F]{64}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("canonical", type=Path)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def absolute_without_resolving(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def reparse_attributes(metadata: os.stat_result) -> tuple[int, int]:
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return attributes, reparse_flag


def require_informative_identity(metadata: os.stat_result, *, label: str) -> None:
    if int(metadata.st_dev) == 0 or int(metadata.st_ino) == 0:
        raise ContractError(f"{label} has a non-informative filesystem identity")


def directory_identity(path: Path, *, label: str) -> tuple[int, int, int, int]:
    metadata = os.lstat(path)
    attributes, reparse_flag = reparse_attributes(metadata)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or bool(attributes & reparse_flag)
    ):
        raise ContractError(f"{label} must be a plain directory, not a reparse point")
    require_informative_identity(metadata, label=label)
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        stat.S_IFMT(metadata.st_mode),
        attributes,
    )


def file_token(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    mtime_ns = getattr(metadata, "st_mtime_ns", None)
    ctime_ns = getattr(metadata, "st_ctime_ns", None)
    attributes, _ = reparse_attributes(metadata)
    return (
        stat.S_IFMT(metadata.st_mode),
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_nlink),
        int(metadata.st_size),
        int(metadata.st_mtime * 1_000_000_000 if mtime_ns is None else mtime_ns),
        int(metadata.st_ctime * 1_000_000_000 if ctime_ns is None else ctime_ns),
        attributes,
    )


def file_path_handle_token(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int, int]:
    """Comparable subset where Windows path/handle ctime semantics differ."""

    token = file_token(metadata)
    return (*token[:6], token[7])


def validate_plain_file_metadata(metadata: os.stat_result, *, label: str) -> None:
    attributes, reparse_flag = reparse_attributes(metadata)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or bool(attributes & reparse_flag)
    ):
        raise ContractError(f"{label} must be a plain regular file")
    require_informative_identity(metadata, label=label)
    if int(metadata.st_nlink) != 1:
        raise ContractError(f"{label} must not be hardlinked")


def physical_inventory(root: Path) -> tuple[set[str], set[str]]:
    """Enumerate every physical file and directory without hash exclusions."""

    root_identity = directory_identity(root, label="inventory root")
    inventory_files: set[str] = set()
    inventory_directories: set[str] = set()
    file_identities: dict[tuple[int, int], str] = {}

    def raise_walk_error(error: OSError) -> None:
        raise error

    for current, directories, files in os.walk(
        root,
        topdown=True,
        followlinks=False,
        onerror=raise_walk_error,
    ):
        current_path = Path(current)
        directories.sort()
        files.sort()
        for name in directories:
            candidate = current_path / name
            relative = candidate.relative_to(root).as_posix()
            directory_identity(candidate, label=f"inventory directory {relative}")
            inventory_directories.add(relative)
        for name in files:
            candidate = current_path / name
            relative = candidate.relative_to(root).as_posix()
            metadata = os.lstat(candidate)
            validate_plain_file_metadata(
                metadata,
                label=f"inventory file {relative}",
            )
            identity = (int(metadata.st_dev), int(metadata.st_ino))
            if identity in file_identities:
                raise ContractError(
                    f"duplicate physical file identity: {relative!r} and "
                    f"{file_identities[identity]!r}"
                )
            file_identities[identity] = relative
            inventory_files.add(relative)
    if directory_identity(root, label="inventory root") != root_identity:
        raise ContractError("inventory root identity changed during traversal")
    return inventory_files, inventory_directories


def stable_read_file(path: Path, *, label: str) -> bytes:
    """Read one file while binding path, handle, metadata, and bytes."""

    path_before = os.lstat(path)
    validate_plain_file_metadata(path_before, label=label)
    token_before = file_token(path_before)
    with path.open("rb") as stream:
        handle_before = os.fstat(stream.fileno())
        validate_plain_file_metadata(handle_before, label=label)
        if file_path_handle_token(handle_before) != file_path_handle_token(path_before):
            raise ContractError(f"{label} path/handle identity mismatch")
        data = stream.read()
        handle_after = os.fstat(stream.fileno())
    if file_token(handle_after) != file_token(handle_before):
        raise ContractError(f"{label} changed while being read")
    path_after = os.lstat(path)
    validate_plain_file_metadata(path_after, label=label)
    if file_token(path_after) != token_before:
        raise ContractError(f"{label} path changed after readback")
    if len(data) != int(path_after.st_size):
        raise ContractError(f"{label} byte-count drift")
    return data


def stable_tree_snapshot(
    root: Path,
) -> tuple[list[FileRecord], set[str], dict[str, bytes]]:
    """Take a stable, exclusion-free fingerprint and directory inventory."""

    root_identity = directory_identity(root, label="snapshot root")
    files_before, directories_before = physical_inventory(root)
    records: list[FileRecord] = []
    contents: dict[str, bytes] = {}
    for relative in sorted(files_before):
        candidate = root.joinpath(*PurePosixPath(relative).parts)
        data = stable_read_file(candidate, label=f"snapshot file {relative}")
        contents[relative] = data
        records.append(
            FileRecord(
                path=relative,
                size=len(data),
                sha256=sha256_bytes(data),
            )
        )
    files_after, directories_after = physical_inventory(root)
    if files_after != files_before or directories_after != directories_before:
        raise ContractError("tree inventory changed during snapshot")
    if directory_identity(root, label="snapshot root") != root_identity:
        raise ContractError("snapshot root identity changed")
    return records, directories_before, contents


def decode_snapshot_text(data: bytes, *, path: Path) -> str:
    if data.startswith(b"\xef\xbb\xbf"):
        raise ContractError(f"UTF-8 BOM is not allowed: {path}")
    if b"\r" in data:
        raise ContractError(f"Line endings must be LF: {path}")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError(f"invalid UTF-8 in {path}: {exc}") from exc


def parse_manifest_bytes(path: Path, data: bytes) -> dict[str, Any]:
    text = decode_snapshot_text(data, path=path)

    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ContractError(f"duplicate adapter manifest key: {key!r}")
            value[key] = item
        return value

    try:
        value = json.loads(text, object_pairs_hook=unique_pairs)
    except json.JSONDecodeError as exc:
        raise ContractError(f"invalid adapter manifest JSON: {exc}") from exc
    if type(value) is not dict:
        raise ContractError("adapter manifest must be a mapping")
    return value


def validate_manifest(value: Any) -> list[dict[str, Any]]:
    if type(value) is not dict:
        raise ContractError("adapter manifest must be a mapping")
    actual_keys = set(value)
    if actual_keys != MANIFEST_KEYS:
        raise ContractError(
            "adapter manifest keys mismatch: "
            f"missing={sorted(MANIFEST_KEYS - actual_keys)} "
            f"extra={sorted(actual_keys - MANIFEST_KEYS)}"
        )
    if type(value["schema_version"]) is not str:
        raise ContractError("manifest schema_version must be a string")
    if type(value["canonical_name"]) is not str or not value["canonical_name"]:
        raise ContractError("manifest canonical_name must be a nonblank string")
    canonical_version = value["canonical_version"]
    if type(canonical_version) is not str or re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+", canonical_version
    ) is None:
        raise ContractError("manifest canonical_version must be semantic x.y.z")
    if type(value["canonical_files"]) is not int or value["canonical_files"] < 0:
        raise ContractError("manifest canonical_files must be an integer")
    canonical_hash = value["canonical_tree_sha256"]
    if type(canonical_hash) is not str or SHA256_RE.fullmatch(canonical_hash) is None:
        raise ContractError(
            "manifest canonical_tree_sha256 must be uppercase SHA-256"
        )
    if type(value["doctrine_forks"]) is not bool:
        raise ContractError("manifest doctrine_forks must be boolean")
    entries = value["entries"]
    if type(entries) is not list:
        raise ContractError("adapter manifest entries must be a list")
    for index, entry in enumerate(entries):
        if type(entry) is not dict:
            raise ContractError(f"invalid manifest entry at index {index}")
        entry_keys = set(entry)
        if entry_keys != ENTRY_KEYS:
            raise ContractError(
                f"manifest entry {index} keys mismatch: "
                f"missing={sorted(ENTRY_KEYS - entry_keys)} "
                f"extra={sorted(entry_keys - ENTRY_KEYS)}"
            )
        if type(entry["files"]) is not int or entry["files"] < 0:
            raise ContractError(f"manifest entry {index} files must be an integer")
        tree_hash = entry["tree_sha256"]
        if type(tree_hash) is not str or SHA256_RE.fullmatch(tree_hash) is None:
            raise ContractError(
                f"manifest entry {index} tree_sha256 must be uppercase SHA-256"
            )
    return validate_host_contract(
        value,
        collection_key="entries",
        id_key="host",
        label="adapter manifest",
    )


def main() -> int:
    args = parse_args()
    canonical_requested = absolute_without_resolving(args.canonical)
    bundle_requested = absolute_without_resolving(args.bundle)
    errors: list[str] = []
    checked = 0
    try:
        if not canonical_requested.is_dir():
            raise ContractError(f"canonical is not a directory: {canonical_requested}")
        if not bundle_requested.is_dir():
            raise ContractError(f"bundle is not a directory: {bundle_requested}")
        canonical_identity = directory_identity(
            canonical_requested,
            label="canonical root",
        )
        bundle_identity = directory_identity(bundle_requested, label="bundle root")
        canonical = canonical_requested.resolve()
        bundle = bundle_requested.resolve()
        if not (canonical / "SKILL.md").is_file():
            raise ContractError(f"canonical is not a skill root: {canonical}")
        if is_relative_to(bundle, canonical) or is_relative_to(canonical, bundle):
            raise ContractError("canonical and bundle must be disjoint")

        (
            canonical_records,
            canonical_directories,
            canonical_contents,
        ) = stable_tree_snapshot(canonical)
        _, canonical_hash = fingerprint(canonical_records)
        config_relative = "adapters/host_generation.yaml"
        config_path = canonical / "adapters" / "host_generation.yaml"
        config_bytes = canonical_contents[config_relative]
        if stable_read_file(config_path, label="canonical host config") != config_bytes:
            raise ContractError("canonical host config drift after snapshot")
        canonical_config = validate_host_config(
            parse_structured_text(
                decode_snapshot_text(config_bytes, path=config_path),
                path=config_path,
            ),
            label="canonical host config",
        )
        if canonical_config["canonical_source"] != canonical.name:
            raise ContractError("canonical host config source-name mismatch")
        project_path = canonical / "pyproject.toml"
        project_bytes = canonical_contents["pyproject.toml"]
        if stable_read_file(project_path, label="project metadata") != project_bytes:
            raise ContractError("project metadata drift after snapshot")
        project_version = parse_project_version(
            decode_snapshot_text(project_bytes, path=project_path),
            path=project_path,
        )
        if canonical_config["canonical_version"] != project_version:
            raise ContractError("canonical host config/project version mismatch")
        expected_paths = {
            entry["id"]: entry["relative_path"]
            for entry in canonical_config["hosts"]
        }

        bundle_records, bundle_directories, bundle_contents = stable_tree_snapshot(bundle)
        manifest_path = bundle / "ADAPTER_MANIFEST.json"
        manifest_bytes = bundle_contents["ADAPTER_MANIFEST.json"]
        if stable_read_file(manifest_path, label="adapter manifest") != manifest_bytes:
            raise ContractError("adapter manifest drift after snapshot")
        manifest = parse_manifest_bytes(manifest_path, manifest_bytes)
        entries = validate_manifest(manifest)
        for entry in entries:
            if entry["relative_path"] != expected_paths[entry["host"]]:
                raise ContractError(
                    f"manifest path mismatch for {entry['host']}: "
                    f"expected {expected_paths[entry['host']]!r}"
                )

        if manifest["schema_version"] != "1.0":
            errors.append("manifest schema_version drift")
        if manifest["canonical_name"] != canonical.name:
            errors.append("manifest canonical-name drift")
        if manifest["canonical_version"] != canonical_config["canonical_version"]:
            errors.append("manifest canonical-version drift")
        if manifest["canonical_tree_sha256"] != canonical_hash:
            errors.append("canonical fingerprint drift")
        if manifest["canonical_files"] != len(canonical_records):
            errors.append("canonical file-count drift")
        if manifest["doctrine_forks"] is not False:
            errors.append("manifest must state doctrine_forks=false")

        expected_inventory_files = {"ADAPTER_MANIFEST.json"}
        expected_inventory_directories: set[str] = set()
        for host_id in REQUIRED_HOST_IDS:
            prefix = expected_paths[host_id]
            prefix_path = PurePosixPath(prefix)
            for length in range(1, len(prefix_path.parts) + 1):
                expected_inventory_directories.add(
                    PurePosixPath(*prefix_path.parts[:length]).as_posix()
                )
            expected_inventory_directories.update(
                f"{prefix}/{relative}" for relative in canonical_directories
            )
            expected_inventory_files.update(
                f"{prefix}/{record.path}" for record in canonical_records
            )
        actual_inventory_files = {record.path for record in bundle_records}
        if (
            actual_inventory_files != expected_inventory_files
            or bundle_directories != expected_inventory_directories
        ):
            missing_files = sorted(expected_inventory_files - actual_inventory_files)
            extra_files = sorted(actual_inventory_files - expected_inventory_files)
            missing_directories = sorted(
                expected_inventory_directories - bundle_directories
            )
            extra_directories = sorted(
                bundle_directories - expected_inventory_directories
            )
            errors.append(
                "bundle inventory mismatch: "
                f"expected={1 + REQUIRED_HOST_COUNT * len(canonical_records)} "
                f"actual={len(actual_inventory_files)} "
                f"missing_files={missing_files[:6]} extra_files={extra_files[:6]} "
                f"missing_directories={missing_directories[:6]} "
                f"extra_directories={extra_directories[:6]}"
            )

        initial_hosts: dict[
            str,
            tuple[list[FileRecord], set[str], dict[str, bytes]],
        ] = {}
        for entry in entries:
            host_id = entry["host"]
            relative = PurePosixPath(entry["relative_path"])
            target_requested = bundle.joinpath(*relative.parts)
            target = target_requested.resolve()
            if not is_relative_to(target, bundle) or not target.is_dir():
                errors.append(f"missing or escaping adapter: {host_id}")
                continue
            records, directories, contents = stable_tree_snapshot(target_requested)
            initial_hosts[host_id] = (records, directories, contents)
            _, tree_hash = fingerprint(records)
            checked += 1
            if len(records) != len(canonical_records):
                errors.append(f"file count mismatch: {host_id}")
            if directories != canonical_directories:
                errors.append(f"directory inventory mismatch: {host_id}")
            if entry["files"] != len(canonical_records):
                errors.append(f"manifest file count mismatch: {host_id}")
            if tree_hash != canonical_hash or tree_hash != entry["tree_sha256"]:
                errors.append(f"tree mismatch: {host_id}")

        (
            final_bundle_records,
            final_bundle_directories,
            final_bundle_contents,
        ) = stable_tree_snapshot(bundle)
        if (
            final_bundle_records != bundle_records
            or final_bundle_directories != bundle_directories
            or final_bundle_contents != bundle_contents
        ):
            errors.append("bundle final readback drift")
        final_manifest_bytes = final_bundle_contents.get("ADAPTER_MANIFEST.json")
        if final_manifest_bytes != manifest_bytes:
            errors.append("manifest final readback drift")

        (
            final_canonical_records,
            final_canonical_directories,
            final_canonical_contents,
        ) = stable_tree_snapshot(canonical)
        if (
            final_canonical_records != canonical_records
            or final_canonical_directories != canonical_directories
            or final_canonical_contents != canonical_contents
            or directory_identity(canonical_requested, label="canonical root")
            != canonical_identity
        ):
            errors.append("canonical final readback drift")

        for entry in entries:
            host_id = entry["host"]
            if host_id not in initial_hosts:
                continue
            relative = PurePosixPath(entry["relative_path"])
            target_requested = bundle.joinpath(*relative.parts)
            final_snapshot = stable_tree_snapshot(target_requested)
            final_records, _, _ = final_snapshot
            if final_snapshot != initial_hosts[host_id]:
                errors.append(f"adapter final readback drift: {host_id}")
            _, final_hash = fingerprint(final_records)
            if final_hash != canonical_hash:
                errors.append(f"adapter final tree mismatch: {host_id}")
        if directory_identity(bundle_requested, label="bundle root") != bundle_identity:
            errors.append("bundle root identity changed during validation")
    except Exception as exc:
        errors.append(str(exc))
    payload = {
        "status": "pass" if not errors else "fail",
        "processed_expected": f"{checked}/{REQUIRED_HOST_COUNT}",
        "errors": errors,
    }
    emit(payload, args.json)
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
