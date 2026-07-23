#!/usr/bin/env python3
"""Generate byte-parity host copies in staging; never install implicitly."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import stat
import sys
from pathlib import Path, PurePosixPath

sys.dont_write_bytecode = True

from _common import (
    ContractError,
    atomic_write,
    emit,
    is_windows_reserved_component,
    is_relative_to,
    load_project_version,
    load_structured,
    validate_host_config,
)
from source_manifest import collect_records, fingerprint


INSTALL_ROOT_MARKERS = (
    (".agents", "skills"),
    (".codex", "skills"),
    (".claude", "skills"),
    (".gemini", "skills"),
    (".gemini", "config", "skills"),
    (".config", "antigravity", "skills"),
)
OWNER_MARKER_NAME = ".adapter-output-owner.token"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path, help="Canonical skill root")
    parser.add_argument("config", type=Path, help="Host generation config")
    parser.add_argument("output", type=Path, help="Fresh staging directory")
    parser.add_argument("--commit", action="store_true", help="Write staging output")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def forbidden_install_roots() -> list[Path]:
    home = Path.home()
    return [
        home / ".agents" / "skills",
        home / ".codex" / "skills",
        home / ".claude" / "skills",
        home / ".gemini" / "skills",
        home / ".gemini" / "config" / "skills",
        home / ".config" / "antigravity" / "skills",
    ]


def paths_overlap(left: Path, right: Path) -> bool:
    """Return true for equal, ancestor, or descendant resolved paths."""

    return is_relative_to(left, right) or is_relative_to(right, left)


def overlaps_install_marker(path: Path) -> bool:
    """Recognize global and project-scoped install-root spellings."""

    parts = tuple(part.rstrip(" .").casefold() for part in path.parts)
    for marker in INSTALL_ROOT_MARKERS:
        for start in range(len(parts)):
            if parts[start : start + len(marker)] == marker:
                return True
        for prefix_length in range(1, len(marker) + 1):
            if parts[-prefix_length:] == marker[:prefix_length]:
                return True
    return False


def reject_install_overlap(path: Path) -> None:
    roots = forbidden_install_roots()
    if overlaps_install_marker(path) or any(
        paths_overlap(path, root) for root in roots
    ):
        raise ContractError("installed skill roots are forbidden outputs")


def reject_unsafe_output_spelling(path: Path) -> None:
    """Reject Win32 aliases before resolve can erase their spelling."""

    anchor = path.anchor
    for part in path.parts:
        if part == anchor:
            continue
        if (
            part in {".", ".."}
            or part.endswith((" ", "."))
            or ":" in part
            or is_windows_reserved_component(part)
        ):
            raise ContractError(f"unsafe output path spelling: {part!r}")


def directory_identity(path: Path) -> tuple[int, int, int, int]:
    """Attest one owned directory without following reparse aliases."""

    metadata = os.lstat(path)
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or bool(attributes & reparse_flag)
    ):
        raise ContractError(f"owned output identity is not a plain directory: {path}")
    if int(metadata.st_dev) == 0 or int(metadata.st_ino) == 0:
        raise ContractError("owned output has a non-informative filesystem identity")
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        stat.S_IFMT(metadata.st_mode),
        int(attributes),
    )


def create_owner_marker(output: Path) -> tuple[Path, bytes]:
    marker = output / OWNER_MARKER_NAME
    token = secrets.token_bytes(32)
    descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(token)
        stream.flush()
        os.fsync(stream.fileno())
    return marker, token


def owner_marker_matches(marker: Path, token: bytes) -> bool:
    try:
        metadata = os.lstat(marker)
    except OSError:
        return False
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or bool(attributes & reparse_flag)
        or metadata.st_nlink != 1
    ):
        return False
    try:
        return marker.read_bytes() == token
    except OSError:
        return False


def main() -> int:
    args = parse_args()
    source = args.source
    output = args.output.expanduser()
    errors: list[str] = []
    output_created_by_this_run = False
    owned_output_identity: tuple[int, int, int, int] | None = None
    owner_marker: Path | None = None
    owner_token: bytes | None = None
    cleanup_status = "not_needed"
    cleanup_path: Path | None = None
    try:
        reject_unsafe_output_spelling(output)
        source = source.resolve()
        output = output.resolve()
        if not (source / "SKILL.md").is_file():
            raise ContractError(f"source is not a skill root: {source}")
        reject_install_overlap(output)
        if is_relative_to(output, source) or is_relative_to(source, output):
            raise ContractError("source and output must be disjoint")
        if output.exists():
            raise ContractError("output must be a fresh staging directory")
        if args.commit and not output.parent.is_dir():
            raise ContractError("output parent must already exist")

        canonical_config_path = source / "adapters" / "host_generation.yaml"
        canonical_config = validate_host_config(
            load_structured(canonical_config_path),
            label="canonical host config",
        )
        if canonical_config["canonical_source"] != source.name:
            raise ContractError("canonical host config source-name mismatch")
        project_version = load_project_version(source)
        if canonical_config["canonical_version"] != project_version:
            raise ContractError("canonical host config/project version mismatch")
        supplied_config = validate_host_config(
            load_structured(args.config.resolve()),
            label="supplied host config",
        )
        if supplied_config != canonical_config:
            raise ContractError("supplied host config does not match canonical config")

        planned = []
        seen: set[str] = set()
        for host in canonical_config["hosts"]:
            host_id = host["id"]
            relative = PurePosixPath(host["relative_path"])
            target = output.joinpath(*relative.parts).resolve()
            reject_install_overlap(target)
            normalized_target = os.path.normcase(str(target)).casefold()
            if not is_relative_to(target, output) or normalized_target in seen:
                raise ContractError(f"duplicate or escaping target for {host_id}")
            seen.add(normalized_target)
            planned.append((host_id, relative, target))

        source_records = collect_records(source)
        _, source_hash = fingerprint(source_records)
        result_entries = []
        if args.commit:
            output.mkdir(mode=0o700)
            output_created_by_this_run = True
            owned_output_identity = directory_identity(output)
            owner_marker, owner_token = create_owner_marker(output)
            for host_id, relative, target in planned:
                shutil.copytree(
                    source,
                    target,
                    ignore=shutil.ignore_patterns(".git", ".pytest_cache", "__pycache__", "*.pyc"),
                )
                records = collect_records(target)
                _, copied_hash = fingerprint(records)
                if copied_hash != source_hash or len(records) != len(source_records):
                    raise ContractError(f"readback parity failed for {host_id}")
                result_entries.append(
                    {
                        "host": host_id,
                        "relative_path": relative.as_posix(),
                        "files": len(records),
                        "tree_sha256": copied_hash,
                    }
                )
            manifest = {
                "schema_version": "1.0",
                "canonical_name": source.name,
                "canonical_version": canonical_config["canonical_version"],
                "canonical_files": len(source_records),
                "canonical_tree_sha256": source_hash,
                "entries": result_entries,
                "doctrine_forks": False,
            }
            atomic_write(
                output / "ADAPTER_MANIFEST.json",
                (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"),
            )
        payload = {
            "status": "pass",
            "mode": "commit" if args.commit else "dry_run",
            "canonical_version": canonical_config["canonical_version"],
            "canonical_files": len(source_records),
            "canonical_tree_sha256": source_hash,
            "planned_hosts": [item[0] for item in planned],
            "written_hosts": [item["host"] for item in result_entries],
            "output": str(output),
        }
        if args.commit:
            if owner_marker is None or owner_token is None:
                raise ContractError("owned output marker was not established")
            if not owner_marker_matches(owner_marker, owner_token):
                raise ContractError("owned output marker changed before commit")
            owner_marker.unlink()
            owner_marker = None
            owner_token = None
    except Exception as exc:
        errors.append(str(exc))
        if args.commit and output_created_by_this_run:
            try:
                current_identity = directory_identity(output)
                marker_is_current = (
                    owner_marker is not None
                    and owner_token is not None
                    and owner_marker_matches(owner_marker, owner_token)
                )
                if (
                    owned_output_identity is None
                    or current_identity != owned_output_identity
                    or not marker_is_current
                ):
                    cleanup_status = "ownership_lost"
                    errors.append(
                        "owned output identity or marker changed; cleanup refused"
                    )
                else:
                    cleanup_path = output.with_name(
                        f".{output.name}.owned-cleanup-{secrets.token_hex(8)}"
                    )
                    output.rename(cleanup_path)
                    quarantined_marker = cleanup_path / OWNER_MARKER_NAME
                    if (
                        directory_identity(cleanup_path) != owned_output_identity
                        or not owner_marker_matches(
                            quarantined_marker,
                            owner_token,
                        )
                    ):
                        cleanup_status = "ownership_lost"
                        errors.append(
                            "owned output identity or marker changed after quarantine; "
                            "cleanup refused"
                        )
                    else:
                        shutil.rmtree(cleanup_path)
                        cleanup_status = "owned_output_removed"
            except FileNotFoundError:
                cleanup_status = "owned_output_missing"
            except Exception as cleanup_exc:
                cleanup_status = "owned_output_cleanup_failed"
                errors.append(f"owned output cleanup failed: {cleanup_exc}")
        elif args.commit:
            cleanup_status = "not_owned"
        payload = {
            "status": "fail",
            "errors": errors,
            "output": str(output),
            "output_created_by_this_run": output_created_by_this_run,
            "cleanup_status": cleanup_status,
            "cleanup_path": str(cleanup_path) if cleanup_path is not None else None,
        }
    emit(payload, args.json)
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
