#!/usr/bin/env python3
"""Safety and orchestration primitives for the governed 2.1 release QA runner."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time
import unicodedata
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


sys.dont_write_bytecode = True

from _common import (  # noqa: E402
    CONFUSABLE_PATH_SEPARATORS,
    WINDOWS_FORBIDDEN_COMPONENT_CHARS,
    ContractError,
    canonical_relative_posix_path as common_canonical_relative_posix_path,
    is_windows_reserved_component,
    load_project_version,
)
from quick_validate import PUBLIC_ONLY_FILE_SET  # noqa: E402


SCHEMA_VERSION = "2.1"
RUNNER_VERSION = "2.1.2"
PHYSICAL_TREE_ALGORITHM = "release-physical-tree-v1"
SOURCE_MANIFEST_ALGORITHM = (
    "relative_posix_path<TAB>bytes<TAB>uppercase_sha256<LF>"
)
EXPECTED_PUBLIC_FILES = 70
OWNER_MARKER = ".release-qa-owner.json"
LEASE_OWNER = "owner.json"
MAX_CHILD_OUTPUT_BYTES = 8 * 1024 * 1024
SHA256_RE = re.compile(r"[0-9A-F]{64}")
REQUIRED_HOST_IDS = ("codex", "claude", "antigravity")
# Frozen full-suite collection denominator. Update only with an intentional
# test-inventory change and a matching drift test.
EXPECTED_PYTEST_ITEMS = 164
EXPECTED_SECRET_POLICY_VERSION = "2.1.0"
EXPECTED_SECRET_CONFIG_SHA256 = (
    "1389EC0C507F999934C9BB98D888970BC6EF498D4375B41EF10CB468463CF646"
)
EXPECTED_SECRET_PATTERNS = 15
EXPECTED_SECRET_ENTROPY_DETECTORS = (
    "entropy_bare_base64",
    "entropy_bare_hex",
    "entropy_native_netrc",
    "entropy_native_npmrc",
    "entropy_native_pgpass",
    "entropy_semantic_assignment",
)
EXPECTED_SECRET_REGEX_DETECTORS = (
    "openai_key",
    "anthropic_key",
    "google_key",
    "github_token",
    "github_fine_grained_token",
    "gitlab_token",
    "stripe_secret_key",
    "slack_token",
    "aws_access_key",
    "private_key",
    "jwt",
    "database_url",
    "azure_storage_connection",
    "bearer_token",
    "generic_secret",
)
EXPECTED_SECRET_LAYERS = (
    "carrier_selection",
    "bounded_utf8",
    "regex_signatures",
    "context_gated_entropy",
    "redacted_reporting",
)
EXPECTED_SECRET_LIMITS = {
    "max_file_bytes": 4 * 1024 * 1024,
    "max_files": 10_000,
    "max_total_bytes": 64 * 1024 * 1024,
}
SECRET_TEXT_SUFFIXES = frozenset(
    {
        ".bash",
        ".bat",
        ".cfg",
        ".cmd",
        ".conf",
        ".env",
        ".ini",
        ".json",
        ".key",
        ".md",
        ".pem",
        ".properties",
        ".ps1",
        ".py",
        ".sh",
        ".toml",
        ".txt",
        ".xml",
        ".yaml",
        ".yml",
        ".zsh",
    }
)
SECRET_EXTENSIONLESS_NAMES = frozenset(
    {
        ".envrc",
        ".git-credentials",
        ".netrc",
        ".npmrc",
        ".pgpass",
        ".pypirc",
        "brewfile",
        "config",
        "containerfile",
        "credentials",
        "dockerfile",
        "gemfile",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
        "jenkinsfile",
        "makefile",
        "procfile",
        "rakefile",
        "secrets",
        "vagrantfile",
    }
)
SECURITY_DENOMINATORS = {
    "generator_negative": "95/95",
    "parity_negative": "111/111",
    "negative_total": "206/206",
    "scanner_compatibility": "17/17",
    "scanner_entropy_precision": "12/12",
    "portable_properties": "58/58",
    "total": "293/293",
}
SECURITY_CASE_COUNTS = {
    "generator": 95,
    "parity": 111,
    "scanner": 17,
    "scanner_entropy_precision": 12,
    "portable_properties": 58,
}
SECURITY_PRESERVATION = {
    "typed_inputs": "206/206",
    "portable_inputs": "58/58",
    "scanner_inputs_and_outputs": "17/17",
    "entropy_inputs_and_outputs": "12/12",
    "source_unchanged": True,
}
SECURITY_RESOURCES = {
    "case_cap": 300,
    "fixture_bytes_cap": 4096,
    "subprocess_timeout_seconds": 5.0,
    "temp_file_cap": 32,
    "total_timeout_seconds": 120.0,
}
SECURITY_SUITE_SEED = 210001
SECURITY_ALL_CASE_IDS_SHA256 = (
    "A745EAE420DEB88722812F8B11D56713171FB2865E999B61D5DFBC2BCADC675B"
)
SECURITY_FUZZ_CORPUS_SHA256 = (
    "ECFAE319FFD59158AB707EC8D10CEDB0F12F03B778AD9DEE39A8D71383733FEA"
)
SECURITY_DECLARED_LIMITS = {
    "linux_case_sensitivity": "modeled_not_live_verified",
    "macos_normalization_and_firmlink": "modeled_not_live_verified",
    "posix_permissions": "not_exercised",
    "finite_fuzz_scope": {
        "cases": 12,
        "corpus_sha256": SECURITY_FUZZ_CORPUS_SHA256,
        "derivation": "SHA-256",
        "invariant": "no_crash_and_repeatable_outcome",
        "max_path_codepoints": 48,
    },
}
SECRET_PAYLOAD_KEYS = frozenset(
    {
        "config_sha256",
        "detectors",
        "eligible_bytes",
        "eligible_files",
        "entropy_findings",
        "findings",
        "layers",
        "limits",
        "patterns",
        "policy_version",
        "scanned_bytes",
        "scanned_files",
        "skipped_files",
        "status",
    }
)
SECURITY_PAYLOAD_KEYS = frozenset(
    {
        "case_ids",
        "declared_limits",
        "denominators",
        "digests",
        "errors",
        "platform_evidence",
        "preservation",
        "resources",
        "seed",
        "source_readback",
        "status",
        "suite_version",
    }
)
SOURCE_MANIFEST_KEYS = frozenset(
    {
        "algorithm",
        "encoding",
        "errors",
        "excluded_dirs",
        "excluded_suffixes",
        "files",
        "records",
        "root",
        "status",
        "tree_sha256",
    }
)
SOURCE_RECORD_KEYS = frozenset({"path", "size", "sha256"})
ADAPTER_MANIFEST_KEYS = frozenset(
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
ADAPTER_ENTRY_KEYS = frozenset(
    {"host", "relative_path", "files", "tree_sha256"}
)
INSTALL_ROOT_MARKERS = (
    (".agents", "skills"),
    (".codex", "skills"),
    (".claude", "skills"),
    (".gemini", "skills"),
    (".gemini", "config", "skills"),
    (".config", "antigravity", "skills"),
)
@dataclass(frozen=True)
class ValidatorSpec:
    identifier: str
    script: str
    arguments: tuple[str, ...]
    semantic: str


VALIDATOR_SPECS = (
    ValidatorSpec(
        "quick_validate",
        "quick_validate.py",
        ("{root}", "--profile", "public-only", "--json"),
        "quick",
    ),
    ValidatorSpec(
        "source_manifest",
        "source_manifest.py",
        ("{root}", "--json"),
        "source",
    ),
    ValidatorSpec(
        "secret_scan",
        "secret_scan.py",
        ("{root}", "--entropy", "--json"),
        "secret",
    ),
    ValidatorSpec(
        "contract_bundle",
        "contract_bundle_check.py",
        ("{root}", "--json"),
        "contract",
    ),
    ValidatorSpec(
        "eval_corpus_v2",
        "eval_corpus_check.py",
        ("{root}", "--profile", "v2", "--json"),
        "eval",
    ),
    ValidatorSpec(
        "security_matrix",
        "security_matrix.py",
        ("{root}", "--json"),
        "security",
    ),
)


class ReleaseQaError(RuntimeError):
    """Typed, path-free error returned by the public runner."""

    exit_code = 2

    def __init__(
        self,
        code: str,
        *,
        step: str,
        detail: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.step = step
        self.detail = detail or {}

    def payload(self) -> dict[str, Any]:
        value: dict[str, Any] = {"code": self.code, "step": self.step}
        if self.detail:
            value["detail"] = self.detail
        return value


class QaFailure(ReleaseQaError):
    exit_code = 1


class RunnerError(ReleaseQaError):
    exit_code = 2


class BlockedError(ReleaseQaError):
    exit_code = 3


def status_for_exit(exit_code: int) -> str:
    return {0: "pass", 1: "fail", 2: "error", 3: "blocked"}.get(
        exit_code, "error"
    )


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def canonical_json_hash(value: Any) -> str:
    data = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return sha256_bytes(data)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise RunnerError(
                "JSON_DUPLICATE_KEY",
                step="json",
                detail={"key": key},
            )
        value[key] = item
    return value


def parse_json_bytes(data: bytes, *, step: str) -> Any:
    if len(data) > MAX_CHILD_OUTPUT_BYTES:
        raise RunnerError("JSON_OUTPUT_TOO_LARGE", step=step)
    if data.startswith(b"\xef\xbb\xbf"):
        raise RunnerError("JSON_ENCODING_INVALID", step=step)
    normalized = data.replace(b"\r\n", b"\n")
    if b"\r" in normalized:
        raise RunnerError("JSON_ENCODING_INVALID", step=step)
    try:
        text = normalized.decode("utf-8", errors="strict")
        return json.loads(text, object_pairs_hook=_unique_pairs)
    except ReleaseQaError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RunnerError(
            "JSON_INVALID",
            step=step,
            detail={"reason": type(exc).__name__},
        ) from exc


def _reparse_attributes(metadata: os.stat_result) -> tuple[int, int]:
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return attributes, flag


def _require_identity(metadata: os.stat_result, *, step: str) -> None:
    if int(metadata.st_dev) == 0 or int(metadata.st_ino) == 0:
        raise RunnerError("IDENTITY_UNAVAILABLE", step=step)


def directory_identity(path: Path, *, step: str) -> tuple[int, int, int, int]:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise RunnerError(
            "DIRECTORY_UNAVAILABLE",
            step=step,
            detail={"errno": exc.errno},
        ) from exc
    attributes, reparse = _reparse_attributes(metadata)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or bool(attributes & reparse)
    ):
        raise RunnerError("DIRECTORY_NOT_PLAIN", step=step)
    _require_identity(metadata, step=step)
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        stat.S_IFMT(metadata.st_mode),
        attributes,
    )


def _file_token(metadata: os.stat_result) -> tuple[int, ...]:
    mtime_ns = getattr(metadata, "st_mtime_ns", None)
    ctime_ns = getattr(metadata, "st_ctime_ns", None)
    attributes, _ = _reparse_attributes(metadata)
    return (
        stat.S_IFMT(metadata.st_mode),
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_nlink),
        int(metadata.st_size),
        int(
            metadata.st_mtime * 1_000_000_000
            if mtime_ns is None
            else mtime_ns
        ),
        int(
            metadata.st_ctime * 1_000_000_000
            if ctime_ns is None
            else ctime_ns
        ),
        attributes,
    )


def _path_handle_token(metadata: os.stat_result) -> tuple[int, ...]:
    token = _file_token(metadata)
    return (*token[:6], token[7])


def _path_handle_token_from_token(token: tuple[int, ...]) -> tuple[int, ...]:
    return (*token[:6], token[7])


def _validate_plain_file(metadata: os.stat_result, *, step: str) -> None:
    attributes, reparse = _reparse_attributes(metadata)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or bool(attributes & reparse)
    ):
        raise RunnerError("FILE_NOT_PLAIN", step=step)
    _require_identity(metadata, step=step)
    if int(metadata.st_nlink) != 1:
        raise RunnerError("FILE_HARDLINKED", step=step)


def stable_read(path: Path, *, step: str) -> bytes:
    try:
        before = os.lstat(path)
        _validate_plain_file(before, step=step)
        before_token = _file_token(before)
        flags = os.O_RDONLY
        for name in ("O_BINARY", "O_CLOEXEC", "O_NOINHERIT", "O_NOFOLLOW"):
            flags |= int(getattr(os, name, 0))
        descriptor = os.open(path, flags)
        try:
            handle_before = os.fstat(descriptor)
            _validate_plain_file(handle_before, step=step)
            if _path_handle_token(before) != _path_handle_token(handle_before):
                raise RunnerError("FILE_PATH_HANDLE_DRIFT", step=step)
            chunks: list[bytes] = []
            while True:
                block = os.read(descriptor, 128 * 1024)
                if not block:
                    break
                chunks.append(block)
            handle_after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if _file_token(handle_before) != _file_token(handle_after):
            raise RunnerError("FILE_CHANGED_DURING_READ", step=step)
        after = os.lstat(path)
        _validate_plain_file(after, step=step)
        if _file_token(after) != before_token:
            raise RunnerError("FILE_CHANGED_AFTER_READ", step=step)
        data = b"".join(chunks)
        if len(data) != int(after.st_size):
            raise RunnerError("FILE_BYTE_COUNT_DRIFT", step=step)
        return data
    except ReleaseQaError:
        raise
    except OSError as exc:
        raise RunnerError(
            "FILE_READ_ERROR",
            step=step,
            detail={"errno": exc.errno},
        ) from exc


def _physical_inventory(root: Path) -> tuple[tuple[str, ...], tuple[str, ...]]:
    root_identity = directory_identity(root, step="snapshot")
    files: list[str] = []
    directories: list[str] = []
    identities: dict[tuple[int, int], str] = {}

    def walk_error(error: OSError) -> None:
        raise error

    try:
        for current, child_directories, child_files in os.walk(
            root,
            topdown=True,
            followlinks=False,
            onerror=walk_error,
        ):
            current_path = Path(current)
            child_directories.sort()
            child_files.sort()
            for name in child_directories:
                candidate = current_path / name
                relative = candidate.relative_to(root).as_posix()
                directory_identity(candidate, step="snapshot")
                directories.append(relative)
            for name in child_files:
                candidate = current_path / name
                relative = candidate.relative_to(root).as_posix()
                metadata = os.lstat(candidate)
                _validate_plain_file(metadata, step="snapshot")
                identity = (int(metadata.st_dev), int(metadata.st_ino))
                if identity in identities:
                    raise RunnerError(
                        "DUPLICATE_FILE_IDENTITY",
                        step="snapshot",
                    )
                identities[identity] = relative
                files.append(relative)
    except ReleaseQaError:
        raise
    except OSError as exc:
        raise RunnerError(
            "SNAPSHOT_INVENTORY_ERROR",
            step="snapshot",
            detail={"errno": exc.errno},
        ) from exc
    if directory_identity(root, step="snapshot") != root_identity:
        raise RunnerError("SNAPSHOT_ROOT_DRIFT", step="snapshot")
    return tuple(sorted(files)), tuple(sorted(directories))


@dataclass(frozen=True)
class TreeSnapshot:
    algorithm: str
    files: int
    directories: int
    tree_sha256: str
    records: tuple[tuple[str, int, str], ...]
    directory_records: tuple[str, ...]

    def public_payload(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "directories": self.directories,
            "files": self.files,
            "tree_sha256": self.tree_sha256,
        }


def snapshot_tree(
    root: Path,
    *,
    expected_files: frozenset[str] | None = None,
) -> TreeSnapshot:
    root = Path(root)
    root_identity = directory_identity(root, step="snapshot")
    files_before, directories_before = _physical_inventory(root)
    if expected_files is not None and frozenset(files_before) != expected_files:
        raise QaFailure(
            "SOURCE_PUBLIC_INVENTORY_DRIFT",
            step="snapshot",
            detail={
                "actual_files": len(files_before),
                "expected_files": len(expected_files),
            },
        )
    records: list[tuple[str, int, str]] = []
    for relative in files_before:
        candidate = root.joinpath(*PurePosixPath(relative).parts)
        data = stable_read(candidate, step="snapshot")
        records.append((relative, len(data), sha256_bytes(data)))
    files_after, directories_after = _physical_inventory(root)
    if files_before != files_after or directories_before != directories_after:
        raise RunnerError("SNAPSHOT_INVENTORY_DRIFT", step="snapshot")
    if directory_identity(root, step="snapshot") != root_identity:
        raise RunnerError("SNAPSHOT_ROOT_DRIFT", step="snapshot")
    digest = hashlib.sha256()
    digest.update(f"{PHYSICAL_TREE_ALGORITHM}\n".encode("ascii"))
    for relative in directories_before:
        digest.update(b"D\x00")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\n")
    for relative, size, file_hash in records:
        digest.update(b"F\x00")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(str(size).encode("ascii"))
        digest.update(b"\x00")
        digest.update(file_hash.encode("ascii"))
        digest.update(b"\n")
    return TreeSnapshot(
        algorithm=PHYSICAL_TREE_ALGORITHM,
        files=len(records),
        directories=len(directories_before),
        tree_sha256=digest.hexdigest().upper(),
        records=tuple(records),
        directory_records=directories_before,
    )


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def _paths_overlap(left: Path, right: Path) -> bool:
    return _is_relative_to(left, right) or _is_relative_to(right, left)


def _reserved_component(value: str) -> bool:
    return is_windows_reserved_component(value)


def _portable_component(value: str, *, step: str) -> None:
    if (
        not value
        or unicodedata.normalize("NFC", value) != value
        or value.endswith((" ", "."))
        or _reserved_component(value)
        or any(
            character in WINDOWS_FORBIDDEN_COMPONENT_CHARS or character == "/"
            for character in value
        )
        or any(character in CONFUSABLE_PATH_SEPARATORS for character in value)
        or any(
            ord(character) < 32
            or ord(character) == 127
            or unicodedata.category(character) in {"Cf", "Cs"}
            for character in value
        )
    ):
        raise RunnerError("PATH_SPELLING_UNSAFE", step=step)


def _reject_unsafe_spelling(path: Path, *, step: str) -> None:
    anchor = path.anchor
    for raw_part in path.parts:
        if raw_part == anchor:
            continue
        if raw_part in {".", ".."}:
            raise RunnerError("PATH_SPELLING_UNSAFE", step=step)
        _portable_component(raw_part, step=step)


def _canonical_relative_posix_path(value: Any, *, step: str) -> str:
    try:
        return common_canonical_relative_posix_path(value, label=step)
    except ContractError as exc:
        raise QaFailure("RELATIVE_PATH_INVALID", step=step) from exc


def _overlaps_install_marker(path: Path) -> bool:
    parts = tuple(part.rstrip(" .").casefold() for part in path.parts)
    for marker in INSTALL_ROOT_MARKERS:
        for start in range(len(parts)):
            if parts[start : start + len(marker)] == marker:
                return True
        for length in range(1, len(marker) + 1):
            if parts[-length:] == marker[:length]:
                return True
    return False


def validate_source(source: Path) -> Path:
    requested = Path(os.path.abspath(os.fspath(source.expanduser())))
    _reject_unsafe_spelling(requested, step="preflight")
    directory_identity(requested, step="preflight")
    resolved = requested.resolve()
    if _overlaps_install_marker(resolved):
        raise RunnerError("SOURCE_INSTALL_ROOT_FORBIDDEN", step="preflight")
    if not (resolved / "SKILL.md").is_file():
        raise RunnerError("SOURCE_NOT_SKILL", step="preflight")
    return resolved


def assert_source_identity(
    source: Path,
    expected: tuple[int, int, int, int],
    *,
    step: str,
) -> None:
    if directory_identity(source, step=step) != expected:
        raise QaFailure("SOURCE_IDENTITY_DRIFT", step=step)


def validate_release_version(source: Path) -> str:
    try:
        version = load_project_version(source)
    except (OSError, ContractError) as exc:
        raise RunnerError("PROJECT_VERSION_INVALID", step="preflight") from exc
    if version != RUNNER_VERSION:
        raise QaFailure(
            "RUNNER_VERSION_MISMATCH",
            step="preflight",
            detail={"project_version": version, "runner_version": RUNNER_VERSION},
        )
    return version


def _lexists(path: Path) -> bool:
    return os.path.lexists(os.fspath(path))


def validate_work_root(source: Path, work_root: Path) -> Path:
    requested = Path(os.path.abspath(os.fspath(work_root.expanduser())))
    _reject_unsafe_spelling(requested, step="preflight")
    if _lexists(requested):
        raise RunnerError("WORK_ROOT_MUST_BE_ABSENT", step="preflight")
    parent = requested.parent
    directory_identity(parent, step="preflight")
    resolved_parent = parent.resolve()
    candidate = resolved_parent / requested.name
    if _paths_overlap(candidate, source):
        raise RunnerError("WORK_ROOT_SOURCE_OVERLAP", step="preflight")
    if _overlaps_install_marker(candidate):
        raise RunnerError("WORK_ROOT_INSTALL_ROOT_FORBIDDEN", step="preflight")
    return candidate


def validate_seal_path(
    source: Path,
    work_root: Path,
    seal_out: Path | None,
) -> Path | None:
    if seal_out is None:
        return None
    requested = Path(os.path.abspath(os.fspath(seal_out.expanduser())))
    _reject_unsafe_spelling(requested, step="preflight")
    if _lexists(requested):
        raise RunnerError("SEAL_EXISTS", step="preflight")
    directory_identity(requested.parent, step="preflight")
    candidate = requested.parent.resolve() / requested.name
    if _paths_overlap(candidate, source) or _is_relative_to(candidate, work_root):
        raise RunnerError("SEAL_NOT_EXTERNAL", step="preflight")
    if _overlaps_install_marker(candidate):
        raise RunnerError("SEAL_INSTALL_ROOT_FORBIDDEN", step="preflight")
    return candidate


def lease_path_for(source: Path) -> Path:
    return source.with_name(f".{source.name}.release-qa.lease")


def _write_new_file(path: Path, data: bytes, *, step: str) -> tuple[int, ...]:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= int(getattr(os, "O_BINARY", 0))
    try:
        descriptor = os.open(path, flags, 0o600)
        try:
            written = 0
            while written < len(data):
                count = os.write(descriptor, data[written:])
                if count <= 0:
                    raise OSError("short write")
                written += count
            os.fsync(descriptor)
            metadata = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        _validate_plain_file(metadata, step=step)
        return _file_token(metadata)
    except ReleaseQaError:
        raise
    except FileExistsError as exc:
        raise BlockedError("CREATE_ONCE_EXISTS", step=step) from exc
    except OSError as exc:
        raise RunnerError(
            "CREATE_ONCE_FAILED",
            step=step,
            detail={"errno": exc.errno},
        ) from exc


def _read_json_file(path: Path, *, step: str) -> dict[str, Any]:
    value = parse_json_bytes(stable_read(path, step=step), step=step)
    if type(value) is not dict:
        raise RunnerError("JSON_OBJECT_REQUIRED", step=step)
    return value


def _source_identity(source: Path) -> dict[str, int]:
    identity = directory_identity(source, step="lease")
    return {"dev": identity[0], "ino": identity[1]}


@dataclass
class CooperativeLease:
    source: Path
    path: Path
    identity: tuple[int, int, int, int]
    token_hash: str
    owner_identity: str
    created_epoch: int
    lease_seconds: int

    @classmethod
    def acquire(cls, source: Path, lease_seconds: int) -> "CooperativeLease":
        path = lease_path_for(source)
        token = secrets.token_bytes(32)
        token_hash = sha256_bytes(token)
        source_identity = _source_identity(source)
        owner_material = (
            f"{os.getpid()}:{source_identity['dev']}:{source_identity['ino']}:"
            f"{token_hash}"
        ).encode("ascii")
        owner_identity = sha256_bytes(owner_material)
        try:
            os.mkdir(path, 0o700)
        except FileExistsError as exc:
            raise BlockedError("LEASE_HELD", step="lease") from exc
        except OSError as exc:
            raise RunnerError(
                "LEASE_CREATE_FAILED",
                step="lease",
                detail={"errno": exc.errno},
            ) from exc
        identity: tuple[int, int, int, int] | None = None
        try:
            identity = directory_identity(path, step="lease")
            now = int(time.time())
            payload = {
                "schema_version": SCHEMA_VERSION,
                "created_epoch": now,
                "expires_epoch": now + lease_seconds,
                "lease_seconds": lease_seconds,
                "owner_identity": owner_identity,
                "source_identity": source_identity,
                "token_sha256": token_hash,
            }
            _write_new_file(path / LEASE_OWNER, _json_bytes(payload), step="lease")
            return cls(
                source=source,
                path=path,
                identity=identity,
                token_hash=token_hash,
                owner_identity=owner_identity,
                created_epoch=now,
                lease_seconds=lease_seconds,
            )
        except Exception:
            try:
                if identity is not None and directory_identity(path, step="lease") == identity:
                    marker = path / LEASE_OWNER
                    if marker.exists():
                        marker.unlink()
                    path.rmdir()
            except Exception:
                pass
            raise

    def _expected_owner(self, *, expires_epoch: int) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "created_epoch": self.created_epoch,
            "expires_epoch": expires_epoch,
            "lease_seconds": self.lease_seconds,
            "owner_identity": self.owner_identity,
            "source_identity": _source_identity(self.source),
            "token_sha256": self.token_hash,
        }

    def assert_owned(self) -> dict[str, Any]:
        try:
            if directory_identity(self.path, step="lease") != self.identity:
                raise BlockedError("LEASE_IDENTITY_LOST", step="lease")
            owner = _read_json_file(self.path / LEASE_OWNER, step="lease")
        except BlockedError:
            raise
        except ReleaseQaError as exc:
            raise BlockedError("LEASE_OWNERSHIP_LOST", step="lease") from exc
        if (
            owner.get("token_sha256") != self.token_hash
            or owner.get("owner_identity") != self.owner_identity
            or owner.get("source_identity") != _source_identity(self.source)
        ):
            raise BlockedError("LEASE_OWNERSHIP_LOST", step="lease")
        return owner

    def renew(self) -> None:
        self.assert_owned()
        expires = int(time.time()) + self.lease_seconds
        payload = self._expected_owner(expires_epoch=expires)
        temporary = self.path / f".{LEASE_OWNER}.{self.token_hash[:16]}.tmp"
        if _lexists(temporary):
            raise BlockedError("LEASE_TEMP_COLLISION", step="lease")
        _write_new_file(temporary, _json_bytes(payload), step="lease")
        try:
            os.replace(temporary, self.path / LEASE_OWNER)
        except OSError as exc:
            raise BlockedError(
                "LEASE_RENEW_FAILED",
                step="lease",
                detail={"errno": exc.errno},
            ) from exc
        self.assert_owned()

    def release(self) -> None:
        self.assert_owned()
        quarantine = self.path.with_name(
            f"{self.path.name}.release-{self.token_hash[:16]}"
        )
        if _lexists(quarantine):
            raise BlockedError("LEASE_RELEASE_COLLISION", step="lease")
        try:
            os.rename(self.path, quarantine)
        except OSError as exc:
            raise BlockedError(
                "LEASE_RELEASE_FAILED",
                step="lease",
                detail={"errno": exc.errno},
            ) from exc
        try:
            if directory_identity(quarantine, step="lease") != self.identity:
                raise BlockedError("LEASE_IDENTITY_LOST", step="lease")
            owner = _read_json_file(quarantine / LEASE_OWNER, step="lease")
            if (
                owner.get("token_sha256") != self.token_hash
                or owner.get("owner_identity") != self.owner_identity
            ):
                raise BlockedError("LEASE_OWNERSHIP_LOST", step="lease")
            entries = sorted(item.name for item in quarantine.iterdir())
            if entries != [LEASE_OWNER]:
                raise BlockedError("LEASE_HAS_UNOWNED_CONTENT", step="lease")
            (quarantine / LEASE_OWNER).unlink()
            quarantine.rmdir()
        except ReleaseQaError:
            raise
        except OSError as exc:
            raise BlockedError(
                "LEASE_RELEASE_FAILED",
                step="lease",
                detail={"errno": exc.errno},
            ) from exc


def inspect_lease(source: Path) -> tuple[dict[str, Any], int]:
    path = lease_path_for(source)
    if not _lexists(path):
        return {"state": "absent"}, 0
    try:
        directory_identity(path, step="lease-status")
        owner = _read_json_file(path / LEASE_OWNER, step="lease-status")
        required = {
            "schema_version",
            "created_epoch",
            "expires_epoch",
            "lease_seconds",
            "owner_identity",
            "source_identity",
            "token_sha256",
        }
        if set(owner) != required:
            raise RunnerError("LEASE_RECORD_INVALID", step="lease-status")
        if (
            owner["schema_version"] != SCHEMA_VERSION
            or type(owner["created_epoch"]) is not int
            or type(owner["expires_epoch"]) is not int
            or type(owner["lease_seconds"]) is not int
            or type(owner["owner_identity"]) is not str
            or SHA256_RE.fullmatch(owner["owner_identity"]) is None
            or type(owner["token_sha256"]) is not str
            or SHA256_RE.fullmatch(owner["token_sha256"]) is None
            or owner["source_identity"] != _source_identity(source)
        ):
            raise RunnerError("LEASE_RECORD_INVALID", step="lease-status")
        state = "active" if owner["expires_epoch"] >= int(time.time()) else "expired"
        return {
            "state": state,
            "created_epoch": owner["created_epoch"],
            "expires_epoch": owner["expires_epoch"],
            "lease_seconds": owner["lease_seconds"],
            "owner_identity": owner["owner_identity"],
            "token_sha256": owner["token_sha256"],
        }, 3
    except ReleaseQaError as exc:
        return {"state": "invalid", "error": exc.code}, 3


@dataclass
class OwnedWork:
    path: Path
    identity: tuple[int, int, int, int]
    token_hash: str
    source_identity: dict[str, int]

    @classmethod
    def create(cls, path: Path, source: Path) -> "OwnedWork":
        token_hash = sha256_bytes(secrets.token_bytes(32))
        source_identity = _source_identity(source)
        try:
            os.mkdir(path, 0o700)
        except FileExistsError as exc:
            raise RunnerError("WORK_ROOT_MUST_BE_ABSENT", step="work") from exc
        except OSError as exc:
            raise RunnerError(
                "WORK_CREATE_FAILED",
                step="work",
                detail={"errno": exc.errno},
            ) from exc
        identity: tuple[int, int, int, int] | None = None
        try:
            identity = directory_identity(path, step="work")
            marker = {
                "schema_version": SCHEMA_VERSION,
                "source_identity": source_identity,
                "token_sha256": token_hash,
            }
            _write_new_file(path / OWNER_MARKER, _json_bytes(marker), step="work")
            return cls(path, identity, token_hash, source_identity)
        except Exception:
            try:
                if identity is not None and directory_identity(path, step="work") == identity:
                    marker_path = path / OWNER_MARKER
                    if marker_path.exists():
                        marker_path.unlink()
                    path.rmdir()
            except Exception:
                pass
            raise

    def assert_owned(self) -> None:
        try:
            if directory_identity(self.path, step="work") != self.identity:
                raise BlockedError("WORK_IDENTITY_LOST", step="work")
            marker = _read_json_file(self.path / OWNER_MARKER, step="work")
        except BlockedError:
            raise
        except ReleaseQaError as exc:
            raise BlockedError("WORK_OWNERSHIP_LOST", step="work") from exc
        if (
            marker.get("schema_version") != SCHEMA_VERSION
            or marker.get("token_sha256") != self.token_hash
            or marker.get("source_identity") != self.source_identity
        ):
            raise BlockedError("WORK_OWNERSHIP_LOST", step="work")

    def cleanup(self) -> None:
        self.assert_owned()
        quarantine = self.path.with_name(
            f".{self.path.name}.owned-cleanup-{self.token_hash[:16]}"
        )
        if _lexists(quarantine):
            raise BlockedError("WORK_CLEANUP_COLLISION", step="cleanup")
        try:
            os.rename(self.path, quarantine)
        except OSError as exc:
            raise BlockedError(
                "WORK_CLEANUP_RENAME_FAILED",
                step="cleanup",
                detail={"errno": exc.errno},
            ) from exc
        try:
            if directory_identity(quarantine, step="cleanup") != self.identity:
                raise BlockedError("WORK_IDENTITY_LOST", step="cleanup")
            marker = _read_json_file(quarantine / OWNER_MARKER, step="cleanup")
            if marker.get("token_sha256") != self.token_hash:
                raise BlockedError("WORK_OWNERSHIP_LOST", step="cleanup")
            shutil.rmtree(quarantine)
        except ReleaseQaError:
            raise
        except OSError as exc:
            raise BlockedError(
                "WORK_CLEANUP_FAILED",
                step="cleanup",
                detail={"errno": exc.errno},
            ) from exc


def _fixed_environment(*, pytest_mode: bool = False) -> dict[str, str]:
    environment = dict(os.environ)
    for name in (
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PYTHONINSPECT",
        "PYTHONWARNINGS",
        "PYTHONPYCACHEPREFIX",
        "PYTEST_ADDOPTS",
        "PYTEST_PLUGINS",
    ):
        environment.pop(name, None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONUTF8"] = "1"
    environment["PYTHONIOENCODING"] = "utf-8"
    if pytest_mode:
        environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    return environment


@dataclass(frozen=True)
class ChildResult:
    returncode: int
    stdout: bytes
    stderr: bytes


def run_child(
    arguments: list[str],
    *,
    cwd: Path,
    timeout_seconds: int,
    step: str,
    pytest_mode: bool = False,
) -> ChildResult:
    try:
        completed = subprocess.run(
            arguments,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
            shell=False,
            env=_fixed_environment(pytest_mode=pytest_mode),
        )
    except subprocess.TimeoutExpired as exc:
        raise RunnerError("CHILD_TIMEOUT", step=step) from exc
    except OSError as exc:
        raise RunnerError(
            "CHILD_START_FAILED",
            step=step,
            detail={"errno": exc.errno},
        ) from exc
    stdout = completed.stdout or b""
    stderr = completed.stderr or b""
    if len(stdout) > MAX_CHILD_OUTPUT_BYTES or len(stderr) > MAX_CHILD_OUTPUT_BYTES:
        raise RunnerError("CHILD_OUTPUT_TOO_LARGE", step=step)
    return ChildResult(completed.returncode, stdout, stderr)


def _run_json_script(
    root: Path,
    script_name: str,
    arguments: Iterable[str],
    *,
    timeout_seconds: int,
    step: str,
) -> tuple[ChildResult, dict[str, Any]]:
    script = root / "scripts" / script_name
    if not script.is_file():
        raise RunnerError(
            "COMPONENT_MISSING",
            step=step,
            detail={"component": script_name},
        )
    child = run_child(
        [sys.executable, "-B", str(script), *arguments],
        cwd=root,
        timeout_seconds=timeout_seconds,
        step=step,
    )
    try:
        value = parse_json_bytes(child.stdout, step=step)
    except RunnerError:
        if child.returncode != 0:
            raise QaFailure(
                "CHILD_FAILED_WITHOUT_JSON",
                step=step,
                detail={"returncode": child.returncode},
            )
        raise
    if type(value) is not dict:
        raise RunnerError("JSON_OBJECT_REQUIRED", step=step)
    return child, value


def _require_pass_payload(
    child: ChildResult,
    payload: dict[str, Any],
    *,
    step: str,
) -> None:
    if child.returncode != 0 or payload.get("status") != "pass":
        raise QaFailure(
            "SEMANTIC_STATUS_FAILED",
            step=step,
            detail={
                "returncode": child.returncode,
                "status": payload.get("status"),
            },
        )
    if payload.get("errors") not in (None, []):
        raise QaFailure("SEMANTIC_ERRORS_PRESENT", step=step)


def _parse_denominator(value: Any, *, step: str) -> tuple[int, int]:
    if type(value) is not str or re.fullmatch(r"[0-9]+/[0-9]+", value) is None:
        raise QaFailure("DENOMINATOR_INVALID", step=step)
    numerator, denominator = (int(item) for item in value.split("/", 1))
    if denominator <= 0 or numerator != denominator:
        raise QaFailure(
            "DENOMINATOR_INCOMPLETE",
            step=step,
            detail={"value": value},
        )
    return numerator, denominator


def validate_quick_payload(
    child: ChildResult,
    payload: dict[str, Any],
    *,
    step: str,
) -> dict[str, Any]:
    _require_pass_payload(child, payload, step=step)
    if payload.get("errors") != [] or payload.get("profile") != "public-only":
        raise QaFailure("QUICK_PROFILE_INVALID", step=step)
    checks = payload.get("checks")
    readback = payload.get("input_readback")
    if type(checks) is not dict or type(readback) is not dict:
        raise QaFailure("QUICK_EVIDENCE_MISSING", step=step)
    exact_inventory = f"{EXPECTED_PUBLIC_FILES}/{EXPECTED_PUBLIC_FILES}"
    if any(
        checks.get(key) != exact_inventory
        for key in (
            "public_inventory",
            "stable_text_reads",
            "final_public_inventory",
            "final_stable_text_reads",
            "final_readback",
        )
    ):
        raise QaFailure("QUICK_EVIDENCE_MISSING", step=step)
    _, denominator = _parse_denominator(checks.get("public_inventory"), step=step)
    _, final_denominator = _parse_denominator(
        checks.get("final_readback"), step=step
    )
    if (
        denominator != EXPECTED_PUBLIC_FILES
        or payload.get("expected_public_files") != EXPECTED_PUBLIC_FILES
        or payload.get("observed_public_files") != EXPECTED_PUBLIC_FILES
        or payload.get("validated_public_files") != EXPECTED_PUBLIC_FILES
        or payload.get("checked_units") != EXPECTED_PUBLIC_FILES
        or denominator != final_denominator
        or readback.get("unchanged") is not True
        or readback.get("inventory_unchanged") is not True
        or readback.get("protected_names_unchanged") is not True
        or readback.get("token_set_complete") is not True
        or readback.get("digest_set_complete") is not True
        or readback.get("tree_unchanged") is not True
        or payload.get("network_access") != "disabled"
        or payload.get("subprocesses_started") != 0
        or payload.get("warnings") != []
    ):
        raise QaFailure("QUICK_READBACK_FAILED", step=step)
    tree_hash = payload.get("public_tree_sha256")
    if type(tree_hash) is not str or SHA256_RE.fullmatch(tree_hash) is None:
        raise QaFailure("QUICK_HASH_INVALID", step=step)
    if (
        readback.get("initial_tree_sha256") != tree_hash
        or readback.get("final_tree_sha256") != tree_hash
    ):
        raise QaFailure("QUICK_HASH_INVALID", step=step)
    return {"files": denominator, "public_tree_sha256": tree_hash}


def validate_source_payload(
    child: ChildResult,
    payload: dict[str, Any],
    *,
    step: str,
    expected_root: Path | None = None,
) -> dict[str, Any]:
    if (
        child.returncode != 0
        or payload.get("status") != "pass"
        or payload.get("errors") != []
    ):
        raise QaFailure(
            "SOURCE_MANIFEST_FAILED",
            step=step,
            detail={
                "returncode": child.returncode,
                "status": payload.get("status"),
            },
        )
    if set(payload) != SOURCE_MANIFEST_KEYS:
        raise QaFailure("SOURCE_MANIFEST_SCHEMA_INVALID", step=step)
    if (
        payload.get("algorithm") != SOURCE_MANIFEST_ALGORITHM
        or payload.get("encoding") != "UTF-8 without BOM"
        or payload.get("excluded_dirs")
        != [".git", ".pytest_cache", "__pycache__"]
        or payload.get("excluded_suffixes") != [".pyc"]
    ):
        raise QaFailure("SOURCE_MANIFEST_POLICY_INVALID", step=step)
    if expected_root is not None:
        raw_root = payload.get("root")
        if type(raw_root) is not str:
            raise QaFailure("SOURCE_MANIFEST_ROOT_INVALID", step=step)
        try:
            received_root = Path(raw_root).resolve()
        except OSError as exc:
            raise QaFailure("SOURCE_MANIFEST_ROOT_INVALID", step=step) from exc
        if received_root != expected_root.resolve():
            raise QaFailure("SOURCE_MANIFEST_ROOT_INVALID", step=step)
    files = payload.get("files")
    tree_hash = payload.get("tree_sha256")
    records = payload.get("records")
    if (
        type(files) is not int
        or files <= 0
        or type(tree_hash) is not str
        or SHA256_RE.fullmatch(tree_hash) is None
        or type(records) is not list
        or len(records) != files
    ):
        raise QaFailure("SOURCE_MANIFEST_INVALID", step=step)
    canonical_records: list[tuple[str, int, str]] = []
    for raw_record in records:
        if type(raw_record) is not dict or set(raw_record) != SOURCE_RECORD_KEYS:
            raise QaFailure("SOURCE_RECORD_SCHEMA_INVALID", step=step)
        path = _canonical_relative_posix_path(raw_record.get("path"), step=step)
        size = raw_record.get("size")
        file_hash = raw_record.get("sha256")
        if (
            type(size) is not int
            or size < 0
            or type(file_hash) is not str
            or SHA256_RE.fullmatch(file_hash) is None
        ):
            raise QaFailure("SOURCE_RECORD_SCHEMA_INVALID", step=step)
        canonical_records.append((path, size, file_hash))
    paths = [item[0] for item in canonical_records]
    if paths != sorted(paths) or len(set(paths)) != files:
        raise QaFailure("SOURCE_RECORDS_INVALID", step=step)
    manifest = "".join(
        f"{path}\t{size}\t{file_hash}\n"
        for path, size, file_hash in canonical_records
    ).encode("utf-8")
    recomputed = sha256_bytes(manifest)
    if recomputed != tree_hash:
        raise QaFailure("SOURCE_TREE_RECOMPUTE_MISMATCH", step=step)
    return {
        "files": files,
        "manifest_sha256": recomputed,
        "tree_sha256": tree_hash,
        "_records": tuple(canonical_records),
    }


def public_source_evidence(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "manifest_algorithm": SOURCE_MANIFEST_ALGORITHM,
        "files": value["files"],
        "manifest_sha256": value["manifest_sha256"],
    }


def _secret_scannable(relative: str) -> bool:
    path = PurePosixPath(relative)
    name = path.name.casefold()
    suffix = Path(name).suffix.casefold()
    return (
        suffix in SECRET_TEXT_SUFFIXES
        or name in SECRET_EXTENSIONLESS_NAMES
        or name == ".env"
        or name.startswith(".env.")
    )


def expected_secret_counts(source_manifest: dict[str, Any]) -> dict[str, int]:
    eligible = 0
    skipped = 0
    eligible_bytes = 0
    for relative, size, _file_hash in source_manifest["_records"]:
        if relative == "scripts/secret_scan.py" or not _secret_scannable(relative):
            skipped += 1
        else:
            eligible += 1
            eligible_bytes += size
    return {
        "eligible_files": eligible,
        "scanned_files": eligible,
        "skipped_files": skipped,
        "eligible_bytes": eligible_bytes,
        "scanned_bytes": eligible_bytes,
    }


def validate_secret_payload(
    child: ChildResult,
    payload: dict[str, Any],
    *,
    step: str,
    source_manifest: dict[str, Any],
) -> dict[str, Any]:
    _require_pass_payload(child, payload, step=step)
    if set(payload) != SECRET_PAYLOAD_KEYS:
        raise QaFailure("SECRET_SCHEMA_INVALID", step=step)
    if payload.get("findings") != [] or payload.get("entropy_findings") != []:
        raise QaFailure("SECRET_FINDINGS_PRESENT", step=step)
    detectors = payload.get("detectors")
    if (
        payload.get("policy_version") != EXPECTED_SECRET_POLICY_VERSION
        or payload.get("config_sha256") != EXPECTED_SECRET_CONFIG_SHA256
        or payload.get("patterns") != EXPECTED_SECRET_PATTERNS
        or payload.get("layers") != list(EXPECTED_SECRET_LAYERS)
        or payload.get("limits") != EXPECTED_SECRET_LIMITS
        or type(detectors) is not dict
        or set(detectors) != {"context_entropy", "entropy_enabled", "regex"}
        or detectors.get("context_entropy")
        != list(EXPECTED_SECRET_ENTROPY_DETECTORS)
        or detectors.get("entropy_enabled") is not True
        or detectors.get("regex") != list(EXPECTED_SECRET_REGEX_DETECTORS)
    ):
        raise QaFailure("SECRET_POLICY_DRIFT", step=step)
    try:
        expected_counts = expected_secret_counts(source_manifest)
    except (KeyError, TypeError, ValueError) as exc:
        raise RunnerError("SOURCE_MANIFEST_INTERNAL_INVALID", step=step) from exc
    if any(payload.get(key) != value for key, value in expected_counts.items()):
        raise QaFailure(
            "SECRET_DENOMINATOR_INVALID",
            step=step,
            detail={"expected": expected_counts},
        )
    if expected_counts["scanned_files"] <= 0:
        raise QaFailure("SECRET_DENOMINATOR_INVALID", step=step)
    return {
        "config_sha256": EXPECTED_SECRET_CONFIG_SHA256,
        "eligible_bytes": expected_counts["eligible_bytes"],
        "eligible_files": expected_counts["eligible_files"],
        "entropy_enabled": True,
        "patterns": EXPECTED_SECRET_PATTERNS,
        "scanned_bytes": expected_counts["scanned_bytes"],
        "scanned_files": expected_counts["scanned_files"],
        "skipped_files": expected_counts["skipped_files"],
    }


def validate_contract_payload(
    child: ChildResult,
    payload: dict[str, Any],
    *,
    step: str,
) -> dict[str, Any]:
    _require_pass_payload(child, payload, step=step)
    if payload.get("errors") != []:
        raise QaFailure("CONTRACT_EVIDENCE_MISSING", step=step)
    checks = payload.get("checks")
    if type(checks) is not dict:
        raise QaFailure("CONTRACT_EVIDENCE_MISSING", step=step)
    if checks.get("artifacts") != "9/9":
        raise QaFailure("CONTRACT_DENOMINATOR_DRIFT", step=step)
    return {"artifacts": "9/9"}


def validate_eval_payload(
    child: ChildResult,
    payload: dict[str, Any],
    *,
    step: str,
) -> dict[str, Any]:
    _require_pass_payload(child, payload, step=step)
    if payload.get("errors") != []:
        raise QaFailure("EVAL_EVIDENCE_MISSING", step=step)
    expected = {
        "cases": 36,
        "hard_check_ids": 108,
        "fault_scenarios": 47,
        "mutants": 32,
    }
    if any(payload.get(key) != value for key, value in expected.items()):
        raise QaFailure("EVAL_DENOMINATOR_DRIFT", step=step)
    return expected


def validate_security_payload(
    child: ChildResult,
    payload: dict[str, Any],
    *,
    step: str,
    source_manifest: dict[str, Any],
) -> dict[str, Any]:
    _require_pass_payload(child, payload, step=step)
    if set(payload) != SECURITY_PAYLOAD_KEYS:
        raise QaFailure("SECURITY_SCHEMA_INVALID", step=step)
    if payload.get("errors") != []:
        raise QaFailure("SECURITY_EVIDENCE_MISSING", step=step)
    denominators = payload.get("denominators")
    digests = payload.get("digests")
    preservation = payload.get("preservation")
    platform = payload.get("platform_evidence")
    if denominators != SECURITY_DENOMINATORS:
        raise QaFailure("SECURITY_DENOMINATOR_DRIFT", step=step)
    case_ids = payload.get("case_ids")
    if type(case_ids) is not dict or set(case_ids) != set(SECURITY_CASE_COUNTS):
        raise QaFailure("SECURITY_CASE_IDS_INVALID", step=step)
    ordered: list[str] = []
    for group, expected_count in SECURITY_CASE_COUNTS.items():
        values = case_ids.get(group)
        if (
            type(values) is not list
            or len(values) != expected_count
            or any(type(value) is not str or not value for value in values)
            or len(set(values)) != expected_count
        ):
            raise QaFailure("SECURITY_CASE_IDS_INVALID", step=step)
        ordered.extend(values)
    if len(set(ordered)) != sum(SECURITY_CASE_COUNTS.values()):
        raise QaFailure("SECURITY_CASE_IDS_INVALID", step=step)

    def ids_digest(values: list[str]) -> str:
        return sha256_bytes("\n".join(values).encode("utf-8"))

    expected_digests = {
        group: ids_digest(case_ids[group]) for group in SECURITY_CASE_COUNTS
    }
    expected_digests["negative_ordered"] = ids_digest(
        case_ids["generator"] + case_ids["parity"]
    )
    expected_digests["all_ordered"] = ids_digest(ordered)
    if (
        digests != expected_digests
        or expected_digests["all_ordered"] != SECURITY_ALL_CASE_IDS_SHA256
    ):
        raise QaFailure("SECURITY_DIGEST_DRIFT", step=step)
    expected_platform = {
        "windows": "live" if sys.platform == "win32" else "modeled_not_live_verified",
        "linux": (
            "live"
            if sys.platform.startswith("linux")
            else "modeled_not_live_verified"
        ),
        "macos": "live" if sys.platform == "darwin" else "modeled_not_live_verified",
    }
    source_files = source_manifest.get("files")
    source_hash = source_manifest.get("tree_sha256")
    if (
        type(source_files) is not int
        or source_files <= 0
        or type(source_hash) is not str
        or SHA256_RE.fullmatch(source_hash) is None
    ):
        raise RunnerError("SOURCE_MANIFEST_INTERNAL_INVALID", step=step)
    source_readback = payload.get("source_readback")
    expected_source_readback = {
        "files_before": source_files,
        "files_after": source_files,
        "sha256_before": source_hash,
        "sha256_after": source_hash,
    }
    if (
        payload.get("suite_version") != RUNNER_VERSION
        or payload.get("seed") != SECURITY_SUITE_SEED
        or payload.get("declared_limits") != SECURITY_DECLARED_LIMITS
        or preservation != SECURITY_PRESERVATION
        or payload.get("resources") != SECURITY_RESOURCES
        or platform != expected_platform
        or source_readback != expected_source_readback
    ):
        raise QaFailure("SECURITY_EVIDENCE_MISSING", step=step)
    return {
        "declared_limits": SECURITY_DECLARED_LIMITS,
        "denominators": SECURITY_DENOMINATORS,
        "digests": expected_digests,
        "platform_evidence": expected_platform,
        "preservation": SECURITY_PRESERVATION,
        "resources": SECURITY_RESOURCES,
        "seed": SECURITY_SUITE_SEED,
        "source_readback": expected_source_readback,
        "suite_version": RUNNER_VERSION,
    }


def _run_public_source_gate(
    source: Path, *, timeout_seconds: int
) -> dict[str, Any]:
    child, payload = _run_json_script(
        source,
        "quick_validate.py",
        (str(source), "--profile", "public-only", "--json"),
        timeout_seconds=timeout_seconds,
        step="source-public-gate",
    )
    return validate_quick_payload(child, payload, step="source-public-gate")


def component_inventory(source: Path) -> list[dict[str, Any]]:
    scripts = source / "scripts"
    items = [
        {
            "id": spec.identifier,
            "kind": "validator",
            "script": f"scripts/{spec.script}",
            "available": (scripts / spec.script).is_file(),
        }
        for spec in VALIDATOR_SPECS
    ]
    for identifier, script, kind in (
        ("pytest", None, "test"),
        ("generate_host_adapters", "generate_host_adapters.py", "adapter"),
        ("adapter_parity", "adapter_parity_check.py", "adapter"),
    ):
        items.append(
            {
                "id": identifier,
                "kind": kind,
                "script": None if script is None else f"scripts/{script}",
                "available": True if script is None else (scripts / script).is_file(),
            }
        )
    return items


def list_command(source_arg: Path) -> tuple[dict[str, Any], int]:
    try:
        source = validate_source(source_arg)
        source_identity = directory_identity(source, step="list")
        before = snapshot_tree(source, expected_files=PUBLIC_ONLY_FILE_SET)
        assert_source_identity(source, source_identity, step="list")
        source_public = _run_public_source_gate(source, timeout_seconds=60)
        assert_source_identity(source, source_identity, step="list")
        snapshot = snapshot_tree(source, expected_files=PUBLIC_ONLY_FILE_SET)
        assert_source_identity(source, source_identity, step="list")
        if snapshot != before:
            raise QaFailure("SOURCE_DRIFT", step="list")
        if source_public["files"] != snapshot.files:
            raise QaFailure("SOURCE_PUBLIC_INVENTORY_DRIFT", step="list")
        components = component_inventory(source)
        payload = {
            "schema_version": SCHEMA_VERSION,
            "command": "list",
            "status": "pass",
            "source_snapshot": snapshot.public_payload(),
            "components": components,
            "available": sum(item["available"] for item in components),
            "required": len(components),
            "adapter_bundles": 2,
            "payload_readbacks": 6,
            "errors": [],
        }
        return payload, 0
    except ReleaseQaError as exc:
        return {
            "schema_version": SCHEMA_VERSION,
            "command": "list",
            "status": status_for_exit(exc.exit_code),
            "components": [],
            "errors": [exc.payload()],
        }, exc.exit_code


def lease_status_command(source_arg: Path) -> tuple[dict[str, Any], int]:
    try:
        source = validate_source(source_arg)
        lease, exit_code = inspect_lease(source)
        return {
            "schema_version": SCHEMA_VERSION,
            "command": "lease-status",
            "status": status_for_exit(exit_code),
            "lease": lease,
            "errors": [],
        }, exit_code
    except ReleaseQaError as exc:
        return {
            "schema_version": SCHEMA_VERSION,
            "command": "lease-status",
            "status": status_for_exit(exc.exit_code),
            "lease": {"state": "unknown"},
            "errors": [exc.payload()],
        }, exc.exit_code


def _run_validator_profile(
    cold: Path,
    *,
    timeout_seconds: int,
    lease: CooperativeLease,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    evidence: dict[str, Any] = {}
    raw_quick: dict[str, Any] | None = None
    raw_source: dict[str, Any] | None = None
    for spec in VALIDATOR_SPECS:
        lease.renew()
        arguments = tuple(item.format(root=str(cold)) for item in spec.arguments)
        child, payload = _run_json_script(
            cold,
            spec.script,
            arguments,
            timeout_seconds=timeout_seconds,
            step=spec.identifier,
        )
        if spec.semantic == "quick":
            raw_quick = validate_quick_payload(
                child, payload, step=spec.identifier
            )
            evidence[spec.identifier] = raw_quick
        elif spec.semantic == "source":
            raw_source = validate_source_payload(
                child,
                payload,
                step=spec.identifier,
                expected_root=cold,
            )
            evidence[spec.identifier] = public_source_evidence(raw_source)
        elif spec.semantic == "secret":
            if raw_source is None:
                raise RunnerError(
                    "VALIDATOR_PROFILE_ORDER_INVALID", step=spec.identifier
                )
            evidence[spec.identifier] = validate_secret_payload(
                child,
                payload,
                step=spec.identifier,
                source_manifest=raw_source,
            )
        elif spec.semantic == "contract":
            evidence[spec.identifier] = validate_contract_payload(
                child, payload, step=spec.identifier
            )
        elif spec.semantic == "eval":
            evidence[spec.identifier] = validate_eval_payload(
                child, payload, step=spec.identifier
            )
        elif spec.semantic == "security":
            if raw_source is None:
                raise RunnerError(
                    "VALIDATOR_PROFILE_ORDER_INVALID", step=spec.identifier
                )
            evidence[spec.identifier] = validate_security_payload(
                child,
                payload,
                step=spec.identifier,
                source_manifest=raw_source,
            )
        else:
            raise RunnerError("VALIDATOR_PROFILE_UNKNOWN", step=spec.identifier)
    if raw_quick is None or raw_source is None:
        raise RunnerError("VALIDATOR_PROFILE_INCOMPLETE", step="validators")
    return evidence, raw_quick, raw_source


def _xml_local_name(element: ET.Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def validate_pytest_junit(
    data: bytes,
    *,
    returncode: int,
    expected_items: int,
) -> dict[str, Any]:
    if type(expected_items) is not int or expected_items <= 0:
        raise RunnerError("PYTEST_EXPECTATION_INVALID", step="pytest")
    try:
        root = ET.fromstring(data)
        root_name = _xml_local_name(root)
        if root_name == "testsuite":
            suites = [root]
        elif root_name == "testsuites":
            suites = [
                element
                for element in list(root)
                if _xml_local_name(element) == "testsuite"
            ]
            if not suites or len(suites) != len(list(root)):
                raise ValueError("unexpected JUnit root children")
        else:
            raise ValueError("unexpected JUnit root")

        declared = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
        cases: list[ET.Element] = []
        for suite in suites:
            if any(
                _xml_local_name(element) == "testsuite"
                for element in list(suite)
            ):
                raise ValueError("nested JUnit suites are unsupported")
            for key in declared:
                raw = suite.attrib.get(key)
                if raw is None:
                    raise ValueError(f"missing JUnit {key}")
                count = int(raw)
                if count < 0:
                    raise ValueError(f"negative JUnit {key}")
                declared[key] += count
            cases.extend(
                element
                for element in list(suite)
                if _xml_local_name(element) == "testcase"
            )
    except (ET.ParseError, TypeError, ValueError) as exc:
        raise RunnerError("PYTEST_JUNIT_INVALID", step="pytest") from exc

    outcomes = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    records: list[tuple[str, str]] = []
    seen: set[str] = set()
    for case in cases:
        classname = case.attrib.get("classname")
        name = case.attrib.get("name")
        if (
            type(classname) is not str
            or not classname
            or type(name) is not str
            or not name
            or unicodedata.normalize("NFC", classname) != classname
            or unicodedata.normalize("NFC", name) != name
            or any(
                character in "\r\n\t"
                or unicodedata.category(character).startswith("C")
                for character in f"{classname}{name}"
            )
        ):
            raise RunnerError("PYTEST_NODE_ID_INVALID", step="pytest")
        node_id = f"{classname}::{name}"
        if node_id in seen:
            raise RunnerError("PYTEST_NODE_ID_DUPLICATE", step="pytest")
        seen.add(node_id)
        markers = [
            _xml_local_name(element)
            for element in list(case)
            if _xml_local_name(element) in {"failure", "error", "skipped"}
        ]
        if len(markers) > 1:
            raise RunnerError("PYTEST_OUTCOME_INVALID", step="pytest")
        outcome = (
            {"failure": "failed", "error": "errors", "skipped": "skipped"}[
                markers[0]
            ]
            if markers
            else "passed"
        )
        outcomes[outcome] += 1
        records.append((node_id, outcome))

    collected = len(records)
    result: dict[str, Any] = {
        "collected": collected,
        "passed": outcomes["passed"],
        "failed": outcomes["failed"],
        "errors": outcomes["errors"],
        "skipped": outcomes["skipped"],
        "node_ids_sha256": sha256_bytes(
            "".join(
                f"{node_id}\t{outcome}\n"
                for node_id, outcome in sorted(records)
            ).encode("utf-8")
        ),
    }
    if (
        declared["tests"] != collected
        or declared["failures"] != outcomes["failed"]
        or declared["errors"] != outcomes["errors"]
        or declared["skipped"] != outcomes["skipped"]
    ):
        raise RunnerError("PYTEST_JUNIT_TALLY_DRIFT", step="pytest")
    if collected != expected_items:
        raise QaFailure(
            "PYTEST_DENOMINATOR_DRIFT",
            step="pytest",
            detail={"actual": collected, "expected": expected_items},
        )
    if (
        returncode != 0
        or outcomes["passed"] != expected_items
        or outcomes["failed"] != 0
        or outcomes["errors"] != 0
        or outcomes["skipped"] != 0
    ):
        raise QaFailure("PYTEST_FAILED", step="pytest", detail=result)
    return result


def _run_pytest(
    cold: Path,
    work: Path,
    *,
    timeout_seconds: int,
) -> dict[str, Any]:
    evidence_dir = work / "evidence"
    evidence_dir.mkdir()
    junit = evidence_dir / "pytest.xml"
    base_temp = work / "pytest-tmp"
    child = run_child(
        [
            sys.executable,
            "-B",
            "-m",
            "pytest",
            str(cold / "tests"),
            "-q",
            "-p",
            "no:cacheprovider",
            "--basetemp",
            str(base_temp),
            "--junitxml",
            str(junit),
        ],
        cwd=cold,
        timeout_seconds=timeout_seconds,
        step="pytest",
        pytest_mode=True,
    )
    if not junit.is_file():
        if child.returncode != 0:
            raise QaFailure(
                "PYTEST_FAILED_WITHOUT_JUNIT",
                step="pytest",
                detail={"returncode": child.returncode},
            )
        raise RunnerError("PYTEST_JUNIT_MISSING", step="pytest")
    return validate_pytest_junit(
        stable_read(junit, step="pytest"),
        returncode=child.returncode,
        expected_items=EXPECTED_PYTEST_ITEMS,
    )


def _validate_generator_payload(
    child: ChildResult,
    payload: dict[str, Any],
    source_manifest: dict[str, Any],
    *,
    step: str,
    bundle: Path,
) -> None:
    _require_pass_payload(child, payload, step=step)
    if (
        set(payload)
        != {
            "canonical_files",
            "canonical_tree_sha256",
            "canonical_version",
            "mode",
            "output",
            "planned_hosts",
            "status",
            "written_hosts",
        }
        or payload.get("mode") != "commit"
        or payload.get("canonical_version") != RUNNER_VERSION
        or payload.get("planned_hosts") != list(REQUIRED_HOST_IDS)
        or payload.get("written_hosts") != list(REQUIRED_HOST_IDS)
        or payload.get("canonical_files") != source_manifest["files"]
        or payload.get("canonical_tree_sha256")
        != source_manifest["tree_sha256"]
        or type(payload.get("output")) is not str
        or Path(payload["output"]).resolve() != bundle.resolve()
    ):
        raise QaFailure("ADAPTER_GENERATION_INVALID", step=step)


def _manifest_entries(
    bundle: Path,
    *,
    canonical_name: str,
    canonical_version: str,
    source_manifest: dict[str, Any],
) -> tuple[bytes, list[dict[str, Any]]]:
    manifest_path = bundle / "ADAPTER_MANIFEST.json"
    data = stable_read(manifest_path, step="adapters")
    value = parse_json_bytes(data, step="adapters")
    if type(value) is not dict or set(value) != ADAPTER_MANIFEST_KEYS:
        raise QaFailure("ADAPTER_MANIFEST_INVALID", step="adapters")
    entries = value.get("entries")
    if type(entries) is not list or len(entries) != len(REQUIRED_HOST_IDS):
        raise QaFailure("ADAPTER_MANIFEST_INVALID", step="adapters")
    if [item.get("host") if type(item) is dict else None for item in entries] != list(
        REQUIRED_HOST_IDS
    ):
        raise QaFailure("ADAPTER_HOST_SET_INVALID", step="adapters")
    if (
        value.get("schema_version") != "1.0"
        or value.get("canonical_name") != canonical_name
        or value.get("canonical_version") != canonical_version
        or value.get("canonical_files") != source_manifest["files"]
        or value.get("canonical_tree_sha256")
        != source_manifest["tree_sha256"]
        or value.get("doctrine_forks") is not False
    ):
        raise QaFailure("ADAPTER_MANIFEST_INVALID", step="adapters")
    normalized_paths: set[str] = set()
    for entry in entries:
        if type(entry) is not dict or set(entry) != ADAPTER_ENTRY_KEYS:
            raise QaFailure("ADAPTER_ENTRY_INVALID", step="adapters")
        relative = _canonical_relative_posix_path(
            entry.get("relative_path"), step="adapters"
        )
        normalized = os.path.normcase(relative).casefold()
        if normalized in normalized_paths:
            raise QaFailure("ADAPTER_PATH_DUPLICATE", step="adapters")
        normalized_paths.add(normalized)
        if (
            entry.get("files") != source_manifest["files"]
            or entry.get("tree_sha256") != source_manifest["tree_sha256"]
        ):
            raise QaFailure("ADAPTER_ENTRY_INVALID", step="adapters")
    return data, entries


def _safe_payload_target(bundle: Path, entry: dict[str, Any]) -> Path:
    raw = _canonical_relative_posix_path(
        entry.get("relative_path"), step="payload-readback"
    )
    parsed = PurePosixPath(raw)
    target = bundle.joinpath(*parsed.parts)
    if not _is_relative_to(target, bundle):
        raise QaFailure("ADAPTER_PATH_ESCAPES", step="payload-readback")
    return target


def _assert_independent_payload(
    cold: Path,
    target: Path,
    cold_snapshot: TreeSnapshot,
) -> None:
    if _paths_overlap(cold, target):
        raise QaFailure("PAYLOAD_SOURCE_OVERLAP", step="payload-readback")
    if directory_identity(cold, step="payload-readback") == directory_identity(
        target, step="payload-readback"
    ):
        raise QaFailure("PAYLOAD_IDENTITY_REUSED", step="payload-readback")
    if snapshot_tree(target) != cold_snapshot:
        raise QaFailure("PAYLOAD_PHYSICAL_DRIFT", step="payload-readback")
    for relative, _size, _file_hash in cold_snapshot.records:
        parts = PurePosixPath(relative).parts
        source_metadata = os.lstat(cold.joinpath(*parts))
        target_metadata = os.lstat(target.joinpath(*parts))
        _validate_plain_file(source_metadata, step="payload-readback")
        _validate_plain_file(target_metadata, step="payload-readback")
        if (
            int(source_metadata.st_dev),
            int(source_metadata.st_ino),
        ) == (
            int(target_metadata.st_dev),
            int(target_metadata.st_ino),
        ):
            raise QaFailure("PAYLOAD_IDENTITY_REUSED", step="payload-readback")


def _run_adapters(
    cold: Path,
    work: Path,
    *,
    timeout_seconds: int,
    lease: CooperativeLease,
    canonical_quick: dict[str, Any],
    canonical_source: dict[str, Any],
    cold_snapshot: TreeSnapshot,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    bundles = [work / "adapter-bundle-a", work / "adapter-bundle-b"]
    manifest_bytes: list[bytes] = []
    bundle_entries: list[list[dict[str, Any]]] = []
    for index, bundle in enumerate(bundles, start=1):
        lease.renew()
        step = f"adapter-generate-{index}"
        child, payload = _run_json_script(
            cold,
            "generate_host_adapters.py",
            (
                str(cold),
                str(cold / "adapters" / "host_generation.yaml"),
                str(bundle),
                "--commit",
                "--json",
            ),
            timeout_seconds=timeout_seconds,
            step=step,
        )
        _validate_generator_payload(
            child,
            payload,
            canonical_source,
            step=step,
            bundle=bundle,
        )
        manifest, entries = _manifest_entries(
            bundle,
            canonical_name=cold.name,
            canonical_version=RUNNER_VERSION,
            source_manifest=canonical_source,
        )
        manifest_bytes.append(manifest)
        bundle_entries.append(entries)
        parity_child, parity_payload = _run_json_script(
            cold,
            "adapter_parity_check.py",
            (str(cold), str(bundle), "--json"),
            timeout_seconds=timeout_seconds,
            step=f"adapter-parity-{index}",
        )
        _require_pass_payload(
            parity_child,
            parity_payload,
            step=f"adapter-parity-{index}",
        )
        if (
            set(parity_payload) != {"status", "processed_expected", "errors"}
            or parity_payload.get("processed_expected") != "3/3"
            or parity_payload.get("errors") != []
        ):
            raise QaFailure("ADAPTER_PARITY_DENOMINATOR", step=f"adapter-parity-{index}")
    if manifest_bytes[0] != manifest_bytes[1]:
        raise QaFailure("ADAPTER_MANIFEST_NONDETERMINISTIC", step="adapters")

    readbacks: list[dict[str, Any]] = []
    for bundle_index, (bundle, entries) in enumerate(
        zip(bundles, bundle_entries), start=1
    ):
        for entry in entries:
            lease.renew()
            host = entry["host"]
            target = _safe_payload_target(bundle, entry)
            _assert_independent_payload(cold, target, cold_snapshot)
            quick_child, quick_payload = _run_json_script(
                target,
                "quick_validate.py",
                (str(target), "--profile", "public-only", "--json"),
                timeout_seconds=timeout_seconds,
                step="payload-readback",
            )
            quick = validate_quick_payload(
                quick_child,
                quick_payload,
                step="payload-readback",
            )
            source_child, source_payload = _run_json_script(
                target,
                "source_manifest.py",
                (str(target), "--json"),
                timeout_seconds=timeout_seconds,
                step="payload-readback",
            )
            source = validate_source_payload(
                source_child,
                source_payload,
                step="payload-readback",
                expected_root=target,
            )
            if (
                quick != canonical_quick
                or public_source_evidence(source)
                != public_source_evidence(canonical_source)
                or source["_records"] != canonical_source["_records"]
            ):
                raise QaFailure("PAYLOAD_READBACK_DRIFT", step="payload-readback")
            readbacks.append(
                {
                    "bundle": bundle_index,
                    "host": host,
                    "status": "pass",
                }
            )
    if len(readbacks) != 6:
        raise QaFailure("PAYLOAD_DENOMINATOR_DRIFT", step="payload-readback")
    return {
        "bundles": "2/2",
        "parity": "2/2",
        "manifest_deterministic": True,
        "manifest_sha256": sha256_bytes(manifest_bytes[0]),
        "payload_readbacks": "6/6",
    }, readbacks


def write_seal_once(path: Path, payload: dict[str, Any]) -> None:
    data = _json_bytes(payload)
    try:
        token = _write_new_file(path, data, step="seal")
        final = os.lstat(path)
        _validate_plain_file(final, step="seal")
        if (
            _path_handle_token(final) != _path_handle_token_from_token(token)
            or stable_read(path, step="seal") != data
        ):
            raise RunnerError("SEAL_READBACK_FAILED", step="seal")
    except BlockedError as exc:
        raise RunnerError("SEAL_EXISTS", step="seal") from exc


def _seal_payload(
    source_snapshot: TreeSnapshot,
    validators: dict[str, Any],
    pytest_result: dict[str, Any],
    adapters: dict[str, Any],
) -> dict[str, Any]:
    evidence = {
        "adapters": adapters,
        "pytest": pytest_result,
        "source_snapshot": source_snapshot.public_payload(),
        "validators": validators,
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "runner_version": RUNNER_VERSION,
        "status": "pass",
        "evidence_sha256": canonical_json_hash(evidence),
        **evidence,
    }


def _step(
    steps: list[dict[str, Any]],
    identifier: str,
    status: str,
    evidence: dict[str, Any] | None = None,
) -> None:
    item: dict[str, Any] = {"id": identifier, "status": status}
    if evidence is not None:
        item["evidence"] = evidence
    steps.append(item)


def _required_components_available(source: Path) -> None:
    missing = [
        item["id"]
        for item in component_inventory(source)
        if not item["available"]
    ]
    if missing:
        raise RunnerError(
            "COMPONENTS_MISSING",
            step="preflight",
            detail={"components": sorted(missing)},
        )


def run_command(
    source_arg: Path,
    work_arg: Path,
    *,
    timeout_seconds: int,
    lease_seconds: int,
    expect_files: int | None,
    expect_tree: str | None,
    seal_out: Path | None,
) -> tuple[dict[str, Any], int]:
    steps: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    lease: CooperativeLease | None = None
    owned_work: OwnedWork | None = None
    source: Path | None = None
    source_identity: tuple[int, int, int, int] | None = None
    work: Path | None = None
    cold: Path | None = None
    pre_snapshot: TreeSnapshot | None = None
    cold_snapshot: TreeSnapshot | None = None
    validators: dict[str, Any] = {}
    pytest_result: dict[str, Any] = {}
    adapters: dict[str, Any] = {}
    readbacks: list[dict[str, Any]] = []
    seal_status = "not_requested" if seal_out is None else "pending"
    work_status = "not_created"
    expectation_evidence: dict[str, Any] | None = None
    exit_code = 0
    current_step = "preflight"

    try:
        if timeout_seconds <= 0 or lease_seconds <= 0:
            raise RunnerError("DURATION_INVALID", step="preflight")
        if expect_files is None or expect_tree is None:
            raise RunnerError("EXPECTATION_REQUIRED", step="preflight")
        if type(expect_files) is not int or expect_files <= 0:
            raise RunnerError("EXPECT_FILES_INVALID", step="preflight")
        if type(expect_tree) is not str:
            raise RunnerError("EXPECT_TREE_INVALID", step="preflight")
        normalized_tree = expect_tree.upper()
        if SHA256_RE.fullmatch(normalized_tree) is None:
            raise RunnerError("EXPECT_TREE_INVALID", step="preflight")
        expectation_evidence = {
            "algorithm": PHYSICAL_TREE_ALGORITHM,
            "files": expect_files,
            "tree_sha256": normalized_tree,
        }

        source = validate_source(source_arg)
        source_identity = directory_identity(source, step="preflight")
        validate_release_version(source)
        assert_source_identity(source, source_identity, step="preflight")
        work = validate_work_root(source, work_arg)
        seal_path = validate_seal_path(source, work, seal_out)
        _required_components_available(source)
        _step(
            steps,
            "preflight",
            "pass",
            {"components": len(component_inventory(source)), "version": RUNNER_VERSION},
        )

        current_step = "lease"
        assert_source_identity(source, source_identity, step=current_step)
        lease = CooperativeLease.acquire(source, lease_seconds)
        assert_source_identity(source, source_identity, step=current_step)
        _step(steps, "lease", "pass", {"state": "acquired"})

        current_step = "source-public-gate"
        assert_source_identity(source, source_identity, step=current_step)
        source_public = _run_public_source_gate(
            source, timeout_seconds=timeout_seconds
        )
        assert_source_identity(source, source_identity, step=current_step)
        pre_snapshot = snapshot_tree(source)
        assert_source_identity(source, source_identity, step=current_step)
        if source_public["files"] != pre_snapshot.files:
            raise QaFailure("SOURCE_PUBLIC_INVENTORY_DRIFT", step=current_step)
        if pre_snapshot.files != expect_files:
            raise QaFailure(
                "EXPECT_FILES_MISMATCH",
                step=current_step,
                detail={"actual": pre_snapshot.files, "expected": expect_files},
            )
        if pre_snapshot.tree_sha256 != normalized_tree:
            raise QaFailure(
                "EXPECT_TREE_MISMATCH",
                step=current_step,
                detail={
                    "actual": pre_snapshot.tree_sha256,
                    "algorithm": PHYSICAL_TREE_ALGORITHM,
                    "expected": normalized_tree,
                },
            )
        _step(steps, current_step, "pass", pre_snapshot.public_payload())

        current_step = "work"
        owned_work = OwnedWork.create(work, source)
        work_status = "owned"
        _step(steps, "work", "pass", {"ownership": "attested"})

        current_step = "cold-copy"
        lease.renew()
        assert_source_identity(source, source_identity, step=current_step)
        cold = work / source.name
        shutil.copytree(
            source,
            cold,
            symlinks=True,
            copy_function=shutil.copyfile,
        )
        cold_snapshot = snapshot_tree(cold)
        assert_source_identity(source, source_identity, step=current_step)
        if cold_snapshot != pre_snapshot:
            raise QaFailure("COLD_COPY_DRIFT", step="cold-copy")
        _step(steps, "cold-copy", "pass", cold_snapshot.public_payload())

        current_step = "validators"
        validators, canonical_quick, canonical_source = _run_validator_profile(
            cold,
            timeout_seconds=timeout_seconds,
            lease=lease,
        )
        if canonical_quick["files"] != canonical_source["files"]:
            raise QaFailure("VALIDATOR_INVENTORY_DRIFT", step="validators")
        if canonical_source.get("_records") != cold_snapshot.records:
            raise QaFailure("VALIDATOR_SOURCE_READBACK_DRIFT", step="validators")
        _step(
            steps,
            "validators",
            "pass",
            {"passed": f"{len(validators)}/{len(VALIDATOR_SPECS)}"},
        )

        current_step = "pytest"
        lease.renew()
        pytest_result = _run_pytest(
            cold,
            work,
            timeout_seconds=timeout_seconds,
        )
        _step(steps, "pytest", "pass", pytest_result)

        current_step = "adapters"
        adapters, readbacks = _run_adapters(
            cold,
            work,
            timeout_seconds=timeout_seconds,
            lease=lease,
            canonical_quick=canonical_quick,
            canonical_source=canonical_source,
            cold_snapshot=cold_snapshot,
        )
        _step(steps, "adapters", "pass", adapters)

        current_step = "final-readback"
        lease.renew()
        assert_source_identity(source, source_identity, step=current_step)
        final_cold = snapshot_tree(cold)
        final_source = snapshot_tree(source)
        assert_source_identity(source, source_identity, step=current_step)
        if final_cold != cold_snapshot:
            raise QaFailure("COLD_SOURCE_DRIFT", step="final-readback")
        if final_source != pre_snapshot:
            raise QaFailure("SOURCE_DRIFT", step="final-readback")
        _step(
            steps,
            "final-readback",
            "pass",
            {"cold_unchanged": True, "source_unchanged": True},
        )

        current_step = "lease-release"
        lease.release()
        lease = None
        _step(steps, current_step, "pass", {"state": "released"})

        current_step = "cleanup"
        owned_work.cleanup()
        owned_work = None
        work_status = "owned_output_removed"
        _step(steps, "cleanup", "pass", {"status": work_status})

        current_step = "postconditions"
        assert_source_identity(source, source_identity, step=current_step)
        final_after_cleanup = snapshot_tree(source)
        assert_source_identity(source, source_identity, step=current_step)
        if final_after_cleanup != pre_snapshot:
            raise QaFailure("SOURCE_DRIFT", step=current_step)
        _step(
            steps,
            current_step,
            "pass",
            {"source_unchanged": True},
        )

        current_step = "seal"
        if seal_path is not None:
            write_seal_once(
                seal_path,
                _seal_payload(pre_snapshot, validators, pytest_result, adapters),
            )
            seal_status = "created"
        else:
            seal_status = "not_requested"
        _step(steps, "seal", "pass", {"status": seal_status})
    except ReleaseQaError as exc:
        exit_code = exc.exit_code
        errors.append(exc.payload())
        if not steps or steps[-1].get("id") != current_step:
            _step(steps, current_step, "fail", {"code": exc.code})
        if owned_work is not None:
            work_status = "retained"
        if seal_status == "pending":
            seal_status = "not_created"
    except (OSError, shutil.Error) as exc:
        exit_code = 2
        error = RunnerError(
            "RUNNER_IO_ERROR",
            step=current_step,
            detail={"errno": getattr(exc, "errno", None)},
        )
        errors.append(error.payload())
        _step(steps, current_step, "fail", {"code": error.code})
        if owned_work is not None:
            work_status = "retained"
        if seal_status == "pending":
            seal_status = "not_created"

    if lease is not None:
        try:
            lease.release()
            lease = None
        except ReleaseQaError as exc:
            errors.append(exc.payload())
            exit_code = 3

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "runner_version": RUNNER_VERSION,
        "command": "run",
        "status": status_for_exit(exit_code),
        "steps": steps,
        "expectation": expectation_evidence,
        "source_snapshot": (
            None if pre_snapshot is None else pre_snapshot.public_payload()
        ),
        "cold_snapshot": (
            None if cold_snapshot is None else cold_snapshot.public_payload()
        ),
        "validators": validators,
        "pytest": pytest_result,
        "adapters": adapters,
        "payload_readbacks": readbacks,
        "work": {"status": work_status},
        "seal": {"status": seal_status},
        "errors": errors,
    }
    return payload, exit_code


__all__ = [
    "BlockedError",
    "CooperativeLease",
    "OwnedWork",
    "QaFailure",
    "ReleaseQaError",
    "RunnerError",
    "SCHEMA_VERSION",
    "TreeSnapshot",
    "VALIDATOR_SPECS",
    "component_inventory",
    "inspect_lease",
    "lease_path_for",
    "lease_status_command",
    "list_command",
    "run_command",
    "snapshot_tree",
    "status_for_exit",
    "validate_seal_path",
    "validate_source",
    "validate_work_root",
    "write_seal_once",
]
