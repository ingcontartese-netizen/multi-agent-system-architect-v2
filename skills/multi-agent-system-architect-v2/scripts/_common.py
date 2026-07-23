#!/usr/bin/env python3
"""Shared deterministic I/O helpers for bundled validation scripts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import unicodedata
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any


class ContractError(ValueError):
    """Raised when a governed artifact cannot be parsed or validated."""


REQUIRED_HOST_IDS = ("codex", "claude", "antigravity")
REQUIRED_HOST_COUNT = len(REQUIRED_HOST_IDS)
HOST_CONFIG_KEYS = frozenset(
    {
        "schema_version",
        "canonical_source",
        "canonical_version",
        "doctrine_forks",
        "installation",
        "hosts",
    }
)
HOST_ENTRY_KEYS = frozenset({"id", "relative_path"})
WINDOWS_RESERVED_BASENAMES = frozenset(
    {
        "con",
        "prn",
        "aux",
        "nul",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
)
WINDOWS_FORBIDDEN_COMPONENT_CHARS = frozenset('<>:"\\|?*')
CONFUSABLE_PATH_SEPARATORS = frozenset({"\u2044", "\u2215", "\u2216", "\u29f8", "\uff0f", "\uff3c"})


def read_utf8(path: Path) -> str:
    data = path.read_bytes()
    if data.startswith(b"\xef\xbb\xbf"):
        raise ContractError(f"UTF-8 BOM is not allowed: {path}")
    if b"\r" in data:
        raise ContractError(f"Line endings must be LF: {path}")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError(f"Invalid UTF-8 in {path}: {exc}") from exc


def parse_structured_text(text: str, *, path: Path) -> Any:
    """Parse already-attested UTF-8 JSON/YAML with unique mapping keys."""

    if text.startswith("\ufeff"):
        raise ContractError(f"UTF-8 BOM is not allowed: {path}")
    if "\r" in text:
        raise ContractError(f"Line endings must be LF: {path}")
    def unique_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ContractError(f"duplicate JSON key in {path}: {key!r}")
            value[key] = item
        return value

    if path.suffix.lower() == ".json":
        try:
            return json.loads(text, object_pairs_hook=unique_json_pairs)
        except json.JSONDecodeError as exc:
            raise ContractError(f"Invalid JSON in {path}: {exc}") from exc
    try:
        import yaml
    except ImportError:
        try:
            return json.loads(text, object_pairs_hook=unique_json_pairs)
        except json.JSONDecodeError as exc:
            raise ContractError(
                f"PyYAML is required for non-JSON YAML input: {path}"
            ) from exc

    class UniqueSafeLoader(yaml.SafeLoader):
        pass

    def construct_mapping(
        loader: UniqueSafeLoader, node: Any, deep: bool = False
    ) -> dict[Any, Any]:
        loader.flatten_mapping(node)
        value: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            try:
                duplicate = key in value
            except TypeError as exc:
                raise ContractError(
                    f"unhashable YAML mapping key in {path}"
                ) from exc
            if duplicate:
                raise ContractError(f"duplicate YAML key in {path}: {key!r}")
            value[key] = loader.construct_object(value_node, deep=deep)
        return value

    UniqueSafeLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        construct_mapping,
    )
    try:
        return yaml.load(text, Loader=UniqueSafeLoader)
    except ContractError:
        raise
    except yaml.YAMLError as exc:
        raise ContractError(f"Invalid YAML in {path}: {exc}") from exc


def load_structured(path: Path) -> Any:
    return parse_structured_text(read_utf8(path), path=path)


def canonical_relative_posix_path(value: Any, *, label: str) -> str:
    """Return one portable relative path or fail closed on aliases/escapes."""

    if type(value) is not str or not value or value.strip() != value:
        raise ContractError(f"{label} must be a nonblank canonical string")
    if unicodedata.normalize("NFC", value) != value:
        raise ContractError(f"{label} must use NFC-normalized Unicode")
    if (
        "\\" in value
        or ":" in value
        or any(
            ord(character) < 32
            or ord(character) == 127
            or unicodedata.category(character) in {"Cf", "Cs"}
            or character in CONFUSABLE_PATH_SEPARATORS
            for character in value
        )
    ):
        raise ContractError(f"{label} must use canonical POSIX separators")
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or bool(windows.drive)
        or not posix.parts
        or posix.as_posix() == "."
        or posix.as_posix() != value
        or any(part in {"", ".", ".."} for part in posix.parts)
        or any(
            part.endswith((" ", "."))
            or is_windows_reserved_component(part)
            or any(
                character in WINDOWS_FORBIDDEN_COMPONENT_CHARS
                for character in part
            )
            for part in posix.parts
        )
    ):
        raise ContractError(f"unsafe or non-canonical {label}: {value!r}")
    return posix.as_posix()


def is_windows_reserved_component(value: str) -> bool:
    """Detect portable Windows device-name aliases without platform APIs."""

    normalized = value.rstrip(" .")
    if not normalized:
        return True
    basename = normalized.split(".", 1)[0].casefold()
    return basename in WINDOWS_RESERVED_BASENAMES


def parse_project_version(text: str, *, path: Path) -> str:
    """Parse the single governed version scalar from pyproject [project]."""

    if text.startswith("\ufeff"):
        raise ContractError(f"UTF-8 BOM is not allowed: {path}")
    if "\r" in text:
        raise ContractError(f"Line endings must be LF: {path}")
    in_project = False
    versions: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            in_project = line == "[project]"
            continue
        if not in_project or not line or line.startswith("#"):
            continue
        match = re.fullmatch(r'version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"', line)
        if match:
            versions.append(match.group(1))
        elif line.startswith("version"):
            raise ContractError(f"invalid project version declaration in {path}")
    if len(versions) != 1:
        raise ContractError(
            f"expected exactly one [project] version in {path}, got {len(versions)}"
        )
    return versions[0]


def load_project_version(skill_root: Path) -> str:
    """Read the single governed version scalar from pyproject [project]."""

    path = skill_root / "pyproject.toml"
    return parse_project_version(read_utf8(path), path=path)


def validate_host_contract(
    value: Any,
    *,
    collection_key: str,
    id_key: str,
    path_key: str = "relative_path",
    label: str,
) -> list[dict[str, Any]]:
    """Validate the fixed three-host contract and return canonical host order."""

    if type(value) is not dict:
        raise ContractError(f"{label} must be a mapping")
    if collection_key not in value:
        raise ContractError(f"{label} is missing {collection_key!r}")
    entries = value[collection_key]
    if type(entries) is not list:
        raise ContractError(f"{label}.{collection_key} must be a list")
    if len(entries) != REQUIRED_HOST_COUNT:
        raise ContractError(
            f"{label}.{collection_key} must contain exactly "
            f"{REQUIRED_HOST_COUNT} entries"
        )

    by_id: dict[str, dict[str, Any]] = {}
    normalized_paths: dict[str, str] = {}
    received_order: list[str] = []
    for index, raw_entry in enumerate(entries):
        if type(raw_entry) is not dict:
            raise ContractError(f"invalid {label} entry at index {index}")
        host_id = raw_entry.get(id_key)
        if type(host_id) is not str or not host_id or host_id.strip() != host_id:
            raise ContractError(f"invalid host id at {label}[{index}]")
        if host_id not in REQUIRED_HOST_IDS:
            raise ContractError(f"unknown host id in {label}: {host_id!r}")
        if host_id in by_id:
            raise ContractError(f"duplicate host id in {label}: {host_id!r}")
        relative = canonical_relative_posix_path(
            raw_entry.get(path_key),
            label=f"{label}[{index}].{path_key}",
        )
        normalized = relative.casefold()
        if normalized in normalized_paths:
            raise ContractError(
                f"duplicate normalized relative_path in {label}: "
                f"{relative!r} conflicts with {normalized_paths[normalized]!r}"
            )
        normalized_paths[normalized] = relative
        entry = dict(raw_entry)
        entry[path_key] = relative
        by_id[host_id] = entry
        received_order.append(host_id)

    if set(by_id) != set(REQUIRED_HOST_IDS):
        missing = sorted(set(REQUIRED_HOST_IDS) - set(by_id))
        extra = sorted(set(by_id) - set(REQUIRED_HOST_IDS))
        raise ContractError(
            f"{label} host set mismatch: missing={missing} extra={extra}"
        )
    if tuple(received_order) != REQUIRED_HOST_IDS:
        raise ContractError(
            f"{label} host order must be {list(REQUIRED_HOST_IDS)!r}"
        )
    return [by_id[host_id] for host_id in REQUIRED_HOST_IDS]


def validate_host_config(value: Any, *, label: str) -> dict[str, Any]:
    """Validate and normalize the canonical adapter-generation configuration."""

    if type(value) is not dict:
        raise ContractError(f"{label} must be a mapping")
    actual_keys = set(value)
    if actual_keys != HOST_CONFIG_KEYS:
        raise ContractError(
            f"{label} keys mismatch: "
            f"missing={sorted(HOST_CONFIG_KEYS - actual_keys)} "
            f"extra={sorted(actual_keys - HOST_CONFIG_KEYS)}"
        )
    if value["schema_version"] != "1.0":
        raise ContractError(f"{label}.schema_version must be '1.0'")
    canonical_source = value["canonical_source"]
    if (
        type(canonical_source) is not str
        or not canonical_source
        or canonical_source.strip() != canonical_source
    ):
        raise ContractError(f"{label}.canonical_source must be a nonblank string")
    canonical_version = value["canonical_version"]
    if type(canonical_version) is not str or re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+", canonical_version
    ) is None:
        raise ContractError(f"{label}.canonical_version must be semantic x.y.z")
    if value["doctrine_forks"] is not False:
        raise ContractError(f"{label}.doctrine_forks must be false")
    if value["installation"] != "forbidden-before-pm-gate":
        raise ContractError(
            f"{label}.installation must be 'forbidden-before-pm-gate'"
        )
    raw_hosts = value["hosts"]
    if type(raw_hosts) is list:
        for index, entry in enumerate(raw_hosts):
            if type(entry) is not dict:
                continue
            entry_keys = set(entry)
            if entry_keys != HOST_ENTRY_KEYS:
                raise ContractError(
                    f"{label}.hosts[{index}] keys mismatch: "
                    f"missing={sorted(HOST_ENTRY_KEYS - entry_keys)} "
                    f"extra={sorted(entry_keys - HOST_ENTRY_KEYS)}"
                )
    hosts = validate_host_contract(
        value,
        collection_key="hosts",
        id_key="id",
        label=label,
    )
    return {
        "schema_version": "1.0",
        "canonical_source": canonical_source,
        "canonical_version": canonical_version,
        "doctrine_forks": False,
        "installation": "forbidden-before-pm-gate",
        "hosts": [
            {"id": entry["id"], "relative_path": entry["relative_path"]}
            for entry in hosts
        ],
    }


def validate_bundle(data: Any, definition: str, skill_root: Path) -> None:
    try:
        import jsonschema
    except ImportError as exc:
        raise ContractError("jsonschema is required for contract validation") from exc
    schema_path = skill_root / "assets" / "schemas" / "contracts.schema.json"
    bundle = load_structured(schema_path)
    if definition not in bundle.get("$defs", {}):
        raise ContractError(f"Unknown schema definition: {definition}")
    wrapper = {
        "$schema": bundle["$schema"],
        "$ref": f"#/$defs/{definition}",
        "$defs": bundle["$defs"],
    }
    validator = jsonschema.Draft202012Validator(
        wrapper, format_checker=jsonschema.FormatChecker()
    )
    errors = sorted(validator.iter_errors(data), key=lambda item: list(item.path))
    if errors:
        details = "; ".join(
            f"{'/'.join(str(part) for part in error.path) or '$'}: {error.message}"
            for error in errors[:12]
        )
        raise ContractError(f"Schema {definition} failed: {details}")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def emit(payload: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    print(f"status: {payload.get('status', 'unknown')}")
    for key in sorted(payload):
        if key == "status":
            continue
        value = payload[key]
        if isinstance(value, (list, dict)):
            print(f"{key}: {json.dumps(value, sort_keys=True)}")
        else:
            print(f"{key}: {value}")
