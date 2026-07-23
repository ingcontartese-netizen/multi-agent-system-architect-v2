#!/usr/bin/env python3
"""Verify the public repository, Skill payload, and optional release assets."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import unicodedata
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath


EXCLUDED_DIRS = {".git", ".pytest_cache", "__pycache__"}
EXCLUDED_SUFFIXES = {".pyc"}
TEXT_SUFFIXES = {".md", ".py", ".json", ".yaml", ".yml", ".toml", ".txt", ".cff", ""}
SAFE_ASSET_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}
FIXED_DIST_NAMES = {
    "PUBLIC_RELEASE_MANIFEST.json",
    "RELEASE_EVIDENCE.md",
    "SHA256SUMS.txt",
}
FORBIDDEN_PUBLIC_FRAGMENTS = (
    "C:" + "\\Users\\",
    "C:/" + "Users/",
    "tmp/" + "control_plane",
    "tmp\\" + "control_plane",
    "codex_to_" + "claude_",
    "claude_to_" + "codex_",
    "PTE" + "100X",
    "GC-" + "EVID",
)
CONTROLLED_PUBLIC_BRAND = "Metodo" + " GC"
FORBIDDEN_FILE_TOKENS = ("answer_key", "truth_map", "behavioral_rubric", "scorer")
EXPECTED_ARCHIVE_RUNTIMES = ["CPython 3.12.13", "CPython 3.14.3"]
PINNED_CI_DEPENDENCIES = ("PyYAML==6.0.3", "jsonschema==4.26.0", "pytest==9.0.3")


class VerificationError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--dist", type=Path)
    parser.add_argument("--quick", action="store_true", help="skip pytest and the 293-case matrix")
    return parser.parse_args()


def run_json(command: list[str], cwd: Path) -> dict:
    completed = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUTF8": "1"},
        timeout=900,
        check=False,
    )
    if completed.returncode != 0:
        raise VerificationError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"{completed.stdout}\n{completed.stderr}"
        )
    output = completed.stdout.strip()
    try:
        result = json.loads(output)
    except json.JSONDecodeError as exc:
        raise VerificationError(
            f"command did not return one JSON object: {' '.join(command)}\n{output}"
        ) from exc
    if not isinstance(result, dict) or result.get("status") != "pass":
        raise VerificationError(
            f"command reported non-pass status: {' '.join(command)}\n{output}"
        )
    return result


def run_pytest(command: list[str], cwd: Path, expected_passed: int) -> dict:
    completed = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUTF8": "1"},
        timeout=900,
        check=False,
    )
    output = (completed.stdout + "\n" + completed.stderr).strip()
    if completed.returncode != 0:
        raise VerificationError(
            f"pytest failed ({completed.returncode}): {' '.join(command)}\n{output}"
        )
    matches = re.findall(r"(?m)(\d+) passed(?:,| in)", output)
    if not matches or int(matches[-1]) != expected_passed:
        raise VerificationError(
            f"pytest denominator mismatch: expected {expected_passed}, output was:\n{output}"
        )
    if re.search(r"(?m)\b(?:failed|error|errors|xfailed|xpassed)\b", output, re.IGNORECASE):
        raise VerificationError(f"pytest output contains a non-clean outcome:\n{output}")
    return {"status": "pass", "passed": expected_passed}


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VerificationError(f"invalid JSON {path}: {exc}") from exc


def inventory(root: Path) -> list[Path]:
    if not root.is_dir():
        raise VerificationError(f"directory is missing: {root}")
    files: list[Path] = []
    directories = [root]
    path_keys: set[str] = set()
    while directories:
        directory = directories.pop()
        with os.scandir(directory) as entries:
            ordered = sorted(entries, key=lambda item: item.name.encode("utf-8"))
        for entry in ordered:
            path = Path(entry.path)
            relative = path.relative_to(root)
            if any(part in EXCLUDED_DIRS for part in relative.parts):
                continue
            # On Windows/Python 3.14, DirEntry.stat(...).st_nlink can report 0
            # for hardlinks while Path.lstat() reports the authoritative count.
            stat_result = path.lstat()
            reparse = bool(
                getattr(stat_result, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            )
            if entry.is_symlink() or reparse:
                raise VerificationError(f"link/reparse entry is forbidden: {relative.as_posix()}")
            key = unicodedata.normalize("NFC", relative.as_posix()).casefold()
            if key in path_keys:
                raise VerificationError(f"case/Unicode-colliding path: {relative.as_posix()}")
            path_keys.add(key)
            if entry.is_dir(follow_symlinks=False):
                directories.append(path)
            elif entry.is_file(follow_symlinks=False):
                if getattr(stat_result, "st_nlink", 1) > 1:
                    raise VerificationError(f"hard-linked file is forbidden: {relative.as_posix()}")
                if path.suffix.lower() not in EXCLUDED_SUFFIXES:
                    files.append(path)
            else:
                raise VerificationError(f"special entry is forbidden: {relative.as_posix()}")
    return sorted(files, key=lambda p: p.relative_to(root).as_posix().encode("utf-8"))


def source_tree(root: Path, files: list[Path]) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    for path in files:
        relative = path.relative_to(root).as_posix()
        data = path.read_bytes()
        total += len(data)
        digest.update(
            f"{relative}\t{len(data)}\t{hashlib.sha256(data).hexdigest().upper()}\n".encode("utf-8")
        )
    return digest.hexdigest().upper(), total


def physical_tree(root: Path) -> tuple[str, str, int, int]:
    """Recompute the Skill's file-and-directory identity independently."""

    def collect() -> tuple[tuple[str, ...], tuple[str, ...]]:
        files: list[str] = []
        directories: list[str] = []
        path_keys: set[str] = set()
        file_identities: set[tuple[int, int]] = set()
        for current, child_directories, child_files in os.walk(
            root, topdown=True, followlinks=False
        ):
            current_path = Path(current)
            child_directories.sort()
            child_files.sort()
            for name, expect_directory in (
                *((value, True) for value in child_directories),
                *((value, False) for value in child_files),
            ):
                path = current_path / name
                relative = path.relative_to(root).as_posix()
                metadata = path.lstat()
                reparse = bool(
                    getattr(metadata, "st_file_attributes", 0)
                    & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
                )
                if path.is_symlink() or reparse:
                    raise VerificationError(f"link/reparse entry is forbidden: {relative}")
                key = unicodedata.normalize("NFC", relative).casefold()
                if key in path_keys:
                    raise VerificationError(f"case/Unicode-colliding path: {relative}")
                path_keys.add(key)
                if expect_directory:
                    if not stat.S_ISDIR(metadata.st_mode):
                        raise VerificationError(f"non-directory in directory inventory: {relative}")
                    directories.append(relative)
                else:
                    if not stat.S_ISREG(metadata.st_mode):
                        raise VerificationError(f"special entry is forbidden: {relative}")
                    if getattr(metadata, "st_nlink", 1) > 1:
                        raise VerificationError(f"hard-linked file is forbidden: {relative}")
                    identity = (int(metadata.st_dev), int(metadata.st_ino))
                    if identity in file_identities:
                        raise VerificationError(f"duplicate file identity: {relative}")
                    file_identities.add(identity)
                    files.append(relative)
        return tuple(sorted(files)), tuple(sorted(directories))

    files_before, directories_before = collect()
    records: list[tuple[str, int, str]] = []
    for relative in files_before:
        data = root.joinpath(*PurePosixPath(relative).parts).read_bytes()
        records.append((relative, len(data), hashlib.sha256(data).hexdigest().upper()))
    files_after, directories_after = collect()
    if files_before != files_after or directories_before != directories_after:
        raise VerificationError("physical tree changed during verification")

    algorithm = "release-physical-tree-v1"
    digest = hashlib.sha256()
    digest.update(f"{algorithm}\n".encode("ascii"))
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
    return algorithm, digest.hexdigest().upper(), len(files_before), len(directories_before)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def asset_name(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise VerificationError("release asset filename must be a non-empty string")
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    stem = value.split(".", 1)[0].upper()
    if (
        not SAFE_ASSET_RE.fullmatch(value)
        or "/" in value
        or "\\" in value
        or posix.is_absolute()
        or len(posix.parts) != 1
        or windows.is_absolute()
        or bool(windows.drive)
        or value.endswith((".", " "))
        or stem in WINDOWS_RESERVED_NAMES
    ):
        raise VerificationError(f"unsafe release asset filename: {value!r}")
    return value


def portable_component(value: str) -> bool:
    normalized = unicodedata.normalize("NFC", value)
    stem = value.split(".", 1)[0].upper()
    return not (
        value != normalized
        or value in {"", ".", ".."}
        or "\\" in value
        or ":" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or value.endswith((".", " "))
        or stem in WINDOWS_RESERVED_NAMES
    )


def require_fields(value: dict, required: dict[str, object], label: str) -> None:
    for key, expected in required.items():
        if value.get(key) != expected:
            raise VerificationError(
                f"{label} field {key!r} mismatch: {value.get(key)!r} != {expected!r}"
            )


def parse_payload_version(skill: Path) -> str:
    project_text = (skill / "pyproject.toml").read_text(encoding="utf-8")
    project_match = re.search(r"(?ms)^\[project\]\s*$\n(.*?)(?=^\[|\Z)", project_text)
    if not project_match:
        raise VerificationError("pyproject.toml has no [project] table")
    versions = re.findall(
        r"(?m)^version\s*=\s*['\"]([^'\"]+)['\"]\s*$",
        project_match.group(1),
    )
    if len(versions) != 1:
        raise VerificationError("pyproject.toml must declare exactly one project version")
    host_text = (skill / "adapters" / "host_generation.yaml").read_text(encoding="utf-8")
    host_versions = re.findall(r'(?m)^canonical_version:\s*["\']([^"\']+)["\']\s*$', host_text)
    if host_versions != versions:
        raise VerificationError("host-generation canonical version disagrees with pyproject.toml")
    return versions[0]


def validate_zip_asset_contract(manifest: dict, skill_name: str) -> dict:
    try:
        value = manifest["assets"]["skill_zip"]
    except (KeyError, TypeError) as exc:
        raise VerificationError("public manifest has no Skill ZIP contract") from exc
    if not isinstance(value, dict):
        raise VerificationError("Skill ZIP contract must be an object")
    filename = asset_name(value.get("filename"))
    required = {
        "filename": filename,
        "format": "deterministic-zip-stored",
        "root_directory": skill_name,
    }
    require_fields(value, required, "Skill ZIP contract")
    digest = value.get("sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9A-F]{64}", digest):
        raise VerificationError("Skill ZIP contract requires an uppercase SHA-256")
    return value


def verify_zip_info_metadata(info: zipfile.ZipInfo, raw: str) -> None:
    """Require the complete, versioned metadata profile for one stored ZIP entry."""
    if info.date_time != (1980, 1, 1, 0, 0, 0):
        raise VerificationError(f"non-deterministic ZIP timestamp: {raw}")
    if info.compress_type != zipfile.ZIP_STORED:
        raise VerificationError(f"unexpected ZIP compression method: {raw}")
    if info.create_system != 3:
        raise VerificationError(f"unexpected ZIP creator system: {raw}")
    if info.create_version != 20 or info.extract_version != 20:
        raise VerificationError(f"unexpected ZIP version fields: {raw}")
    if info.flag_bits != 0:
        raise VerificationError(f"unexpected ZIP flags: {raw}")
    if info.internal_attr != 0:
        raise VerificationError(f"unexpected ZIP internal attributes: {raw}")
    if info.external_attr != (stat.S_IFREG | 0o644) << 16:
        raise VerificationError(f"unexpected ZIP file mode: {raw}")
    if info.extra or info.comment:
        raise VerificationError(f"ZIP entry metadata is not canonical: {raw}")
    if info.compress_size != info.file_size:
        raise VerificationError(f"stored ZIP entry changed byte length: {raw}")


def contained_file(directory: Path, name: str) -> Path:
    candidate = (directory / name).resolve()
    try:
        candidate.relative_to(directory)
    except ValueError as exc:
        raise VerificationError(f"release asset escapes directory: {name!r}") from exc
    if candidate.parent != directory:
        raise VerificationError(f"release asset is not a direct child: {name!r}")
    return candidate


def verify_plugin_contracts(repo: Path, manifest: dict) -> None:
    version = manifest["release"]["version"]
    tag = manifest["release"]["tag"]
    name = manifest["skill"]["name"]
    repository = "ingcontartese-netizen/multi-agent-system-architect-v2"

    codex_plugin = load_json(repo / ".codex-plugin" / "plugin.json")
    require_fields(
        codex_plugin,
        {"name": name, "version": version, "license": "Apache-2.0", "skills": "./skills/"},
        "Codex plugin manifest",
    )
    if not isinstance(codex_plugin.get("interface", {}).get("displayName"), str):
        raise VerificationError("Codex plugin displayName is missing")

    codex_marketplace = load_json(repo / ".agents" / "plugins" / "marketplace.json")
    codex_entries = codex_marketplace.get("plugins")
    if not isinstance(codex_entries, list) or len(codex_entries) != 1:
        raise VerificationError("Codex marketplace must contain exactly one plugin")
    codex_entry = codex_entries[0]
    require_fields(codex_entry, {"name": name}, "Codex marketplace entry")
    if codex_entry.get("source") != {"source": "local", "path": "./"}:
        raise VerificationError("Codex marketplace entry must use the documented local repo source")

    claude_plugin = load_json(repo / ".claude-plugin" / "plugin.json")
    require_fields(
        claude_plugin,
        {"name": name, "version": version, "license": "Apache-2.0"},
        "Claude plugin manifest",
    )
    if not isinstance(claude_plugin.get("displayName"), str):
        raise VerificationError("Claude plugin displayName is missing")

    claude_marketplace = load_json(repo / ".claude-plugin" / "marketplace.json")
    claude_entries = claude_marketplace.get("plugins")
    if not isinstance(claude_entries, list) or len(claude_entries) != 1:
        raise VerificationError("Claude marketplace must contain exactly one plugin")
    claude_entry = claude_entries[0]
    require_fields(claude_entry, {"name": name}, "Claude marketplace entry")
    if "version" in claude_entry:
        raise VerificationError("Claude marketplace must not duplicate the plugin version")
    if claude_entry.get("source") != {
        "source": "github",
        "repo": repository,
        "ref": tag,
    }:
        raise VerificationError("Claude marketplace source must pin the release tag")

    antigravity_plugin = load_json(repo / "plugin.json")
    require_fields(antigravity_plugin, {"name": name}, "Antigravity plugin manifest")


def verify_evidence(repo: Path, manifest: dict) -> None:
    evidence = (repo / "docs" / "RELEASE_EVIDENCE.md").read_text(encoding="utf-8")
    required_values = [
        manifest["release"]["version"],
        manifest["release"]["tag"],
        str(manifest["skill"]["files"]),
        str(manifest["skill"]["bytes"]),
        manifest["skill"]["source_tree_sha256"],
        manifest["skill"]["public_tree_sha256"],
        manifest["skill"]["physical_tree_algorithm"],
        manifest["skill"]["physical_tree_sha256"],
        manifest["assets"]["skill_zip"]["sha256"],
        manifest["assets"]["skill_zip"]["format"],
        manifest["assets"]["skill_zip"]["root_directory"],
        str(manifest["qualification"]["pytest_passed"]),
        str(manifest["qualification"]["release_tool_tests"]),
        str(manifest["qualification"]["security_matrix_cases"]),
        *manifest["qualification"]["archive_reproducibility_runtimes"],
    ]
    missing = [value for value in required_values if value not in evidence]
    if missing:
        raise VerificationError(f"release evidence omits manifest-bound values: {missing}")


def verify_wrapper(repo: Path, manifest: dict) -> None:
    required = (
        "README.md",
        "LICENSE",
        "NOTICE",
        "SECURITY.md",
        "CONTRIBUTING.md",
        ".codex-plugin/plugin.json",
        ".claude-plugin/plugin.json",
        ".claude-plugin/marketplace.json",
        ".agents/plugins/marketplace.json",
        ".github/workflows/validate.yml",
        "plugin.json",
    )
    missing = [item for item in required if not (repo / item).is_file()]
    if missing:
        raise VerificationError(f"missing repository files: {missing}")
    verify_plugin_contracts(repo, manifest)
    verify_evidence(repo, manifest)
    runtimes = manifest.get("qualification", {}).get("archive_reproducibility_runtimes")
    if runtimes != EXPECTED_ARCHIVE_RUNTIMES:
        raise VerificationError(
            f"archive runtime contract mismatch: {runtimes!r} != {EXPECTED_ARCHIVE_RUNTIMES!r}"
        )
    workflow = (repo / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
    if re.search(r"(?m)^\s*run:\s+.*pip install.*(?:\s-e\s|--editable)", workflow):
        raise VerificationError("CI must not editable-install the non-package Skill payload")
    install_lines = [
        line.strip()
        for line in workflow.splitlines()
        if re.match(r"^\s*run:\s+.*pip install", line)
    ]
    if len(install_lines) != 3:
        raise VerificationError("CI must declare exactly three dependency bootstrap steps")
    for dependency in PINNED_CI_DEPENDENCIES:
        quoted = f'"{dependency}"'
        if any(line.count(quoted) != 1 for line in install_lines):
            raise VerificationError(f"CI dependency is not exactly pinned in every bootstrap: {dependency}")
    for runtime in ("3.12.13", "3.14.3"):
        if workflow.count(f'python-version: "{runtime}"') != 1:
            raise VerificationError(f"release-smoke must pin Python {runtime} exactly once")
        if f"expected = ({runtime.replace('.', ', ')})" not in workflow:
            raise VerificationError(f"release-smoke must assert Python {runtime} at runtime")

    brand_occurrences: list[str] = []
    for path in inventory(repo):
        relative = path.relative_to(repo).as_posix()
        lowered = relative.lower()
        if any(token in lowered for token in FORBIDDEN_FILE_TOKENS):
            raise VerificationError(f"protected or private filename in public repository: {relative}")
        data = path.read_bytes()
        lowered_data = data.lower()
        for fragment in FORBIDDEN_PUBLIC_FRAGMENTS:
            if fragment.encode("utf-8").lower() in lowered_data:
                raise VerificationError(f"private/internal fragment {fragment!r} in {relative}")
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {"LICENSE", "NOTICE"}:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise VerificationError(f"declared text file is not UTF-8: {relative}")
        for fragment in FORBIDDEN_PUBLIC_FRAGMENTS:
            if fragment.lower() in text.lower():
                raise VerificationError(f"private/internal fragment {fragment!r} in {relative}")
        if CONTROLLED_PUBLIC_BRAND.lower() in text.lower():
            if relative != "README.md" or text.lower().count(CONTROLLED_PUBLIC_BRAND.lower()) != 1:
                raise VerificationError(f"uncontrolled public brand reference in {relative}")
            brand_occurrences.append(relative)
    if brand_occurrences != ["README.md"]:
        raise VerificationError("README must contain exactly one controlled origin-brand reference")


def verify_zip(
    zip_path: Path,
    expected_root: str,
    expected_files: int,
    expected_bytes: int,
    expected_tree: str,
) -> dict:
    if not zip_path.is_file():
        raise VerificationError(f"release ZIP missing: {zip_path}")
    seen: set[str] = set()
    casefold: set[str] = set()
    records: list[tuple[str, bytes]] = []
    with zipfile.ZipFile(zip_path) as archive:
        if archive.comment:
            raise VerificationError("ZIP archive comment is forbidden")
        infos = archive.infolist()
        if len(infos) != expected_files:
            raise VerificationError(f"unexpected ZIP entry count: {len(infos)}")
        if sum(info.file_size for info in infos) != expected_bytes:
            raise VerificationError("unexpected ZIP uncompressed byte count")
        if any(info.file_size > 4 * 1024 * 1024 for info in infos):
            raise VerificationError("ZIP entry exceeds per-file limit")
        if sum(info.file_size for info in infos) > 64 * 1024 * 1024:
            raise VerificationError("ZIP exceeds total uncompressed limit")
        archive_order = [info.filename for info in infos]
        if archive_order != sorted(archive_order, key=lambda item: item.encode("utf-8")):
            raise VerificationError("ZIP entries are not deterministically ordered")
        for info in infos:
            raw = info.filename
            path = PurePosixPath(raw)
            if path.is_absolute() or ".." in path.parts or not path.parts:
                raise VerificationError(f"unsafe ZIP entry: {raw}")
            if any(not portable_component(part) for part in path.parts):
                raise VerificationError(f"non-portable ZIP entry: {raw}")
            if path.parts[0] != expected_root or len(path.parts) < 2:
                raise VerificationError(f"unexpected ZIP root: {raw}")
            normalized = path.as_posix()
            collision_key = unicodedata.normalize("NFC", normalized).casefold()
            if normalized in seen or collision_key in casefold:
                raise VerificationError(f"duplicate/case-colliding ZIP entry: {raw}")
            seen.add(normalized)
            casefold.add(collision_key)
            verify_zip_info_metadata(info, raw)
            relative = PurePosixPath(*path.parts[1:]).as_posix()
            records.append((relative, archive.read(info)))

    digest = hashlib.sha256()
    total = 0
    for relative, data in sorted(records, key=lambda item: item[0].encode("utf-8")):
        total += len(data)
        digest.update(
            f"{relative}\t{len(data)}\t{hashlib.sha256(data).hexdigest().upper()}\n".encode("utf-8")
        )
    tree = digest.hexdigest().upper()
    if tree != expected_tree or total != expected_bytes:
        raise VerificationError(f"ZIP payload mismatch: bytes={total} tree={tree}")
    return {"sha256": sha256_file(zip_path), "files": expected_files, "tree": tree, "bytes": total}


def verify_checksums(dist: Path, required_names: set[str]) -> None:
    checksum_file = dist / "SHA256SUMS.txt"
    if not checksum_file.is_file():
        raise VerificationError("SHA256SUMS.txt is missing")
    lines = checksum_file.read_text(encoding="utf-8").splitlines()
    if not lines:
        raise VerificationError("SHA256SUMS.txt is empty")
    observed: set[str] = set()
    parsed: list[tuple[str, str]] = []
    for line in lines:
        match = re.fullmatch(r"([0-9A-F]{64})  ([^/\\]+)", line)
        if not match:
            raise VerificationError(f"malformed checksum line: {line!r}")
        digest, name = match.groups()
        name = asset_name(name)
        if name in observed:
            raise VerificationError(f"duplicate checksum entry: {name}")
        observed.add(name)
        parsed.append((digest, name))
    if observed != required_names:
        raise VerificationError(
            f"checksum inventory mismatch: observed={sorted(observed)} required={sorted(required_names)}"
        )
    for digest, name in parsed:
        target = contained_file(dist, name)
        if not target.is_file() or sha256_file(target) != digest:
            raise VerificationError(f"checksum mismatch: {name}")


def main() -> int:
    args = parse_args()
    repo = args.repo.resolve()
    manifest = load_json(repo / "release" / "PUBLIC_RELEASE_MANIFEST.json")
    skill_meta = manifest["skill"]
    skill = (repo / skill_meta["path"]).resolve()
    try:
        skill.relative_to(repo)
    except ValueError as exc:
        raise VerificationError("skill path escapes repository") from exc
    if parse_payload_version(skill) != manifest["release"]["version"]:
        raise VerificationError("payload version disagrees with public release manifest")
    zip_meta = validate_zip_asset_contract(manifest, skill.name)

    verify_wrapper(repo, manifest)
    files = inventory(skill)
    tree, total = source_tree(skill, files)
    if len(files) != skill_meta["files"]:
        raise VerificationError(f"file count mismatch: {len(files)}")
    if total != skill_meta["bytes"]:
        raise VerificationError(f"byte count mismatch: {total}")
    if tree != skill_meta["source_tree_sha256"]:
        raise VerificationError(f"tree mismatch: {tree}")
    physical_algorithm, physical_sha, physical_files, physical_directories = physical_tree(skill)
    if physical_algorithm != skill_meta["physical_tree_algorithm"]:
        raise VerificationError(f"physical tree algorithm mismatch: {physical_algorithm}")
    if physical_sha != skill_meta["physical_tree_sha256"]:
        raise VerificationError(f"physical tree mismatch: {physical_sha}")
    if physical_files != skill_meta["files"]:
        raise VerificationError(f"physical file count mismatch: {physical_files}")

    python = sys.executable
    qualification = manifest["qualification"]
    results = {
        "source_manifest": run_json(
            [
                python,
                "-B",
                "scripts/source_manifest.py",
                ".",
                "--expect-files",
                str(skill_meta["files"]),
                "--expect-tree",
                skill_meta["source_tree_sha256"],
                "--json",
            ],
            skill,
        ),
        "quick_validate": run_json(
            [python, "-B", "scripts/quick_validate.py", ".", "--profile", "public-only", "--json"],
            skill,
        ),
        "secret_scan": run_json(
            [python, "-B", "scripts/secret_scan.py", ".", "--json"], skill
        ),
        "secret_scan_entropy": run_json(
            [python, "-B", "scripts/secret_scan.py", ".", "--entropy", "--json"], skill
        ),
        "repository_secret_scan": run_json(
            [python, "-B", "scripts/secret_scan.py", str(repo), "--json"], skill
        ),
        "repository_secret_scan_entropy": run_json(
            [python, "-B", "scripts/secret_scan.py", str(repo), "--entropy", "--json"], skill
        ),
    }

    source_result = results["source_manifest"]
    if (
        source_result.get("files") != skill_meta["files"]
        or source_result.get("tree_sha256") != skill_meta["source_tree_sha256"]
    ):
        raise VerificationError("source_manifest returned the wrong identity")
    quick_result = results["quick_validate"]
    if (
        quick_result.get("expected_public_files") != skill_meta["files"]
        or quick_result.get("observed_public_files") != skill_meta["files"]
        or quick_result.get("validated_public_files") != skill_meta["files"]
        or quick_result.get("public_tree_sha256") != skill_meta["public_tree_sha256"]
        or quick_result.get("opaque_protected_names_seen") != []
        or quick_result.get("input_readback", {}).get("unchanged") is not True
    ):
        raise VerificationError("quick_validate returned incomplete or mismatched evidence")
    for label in (
        "secret_scan",
        "secret_scan_entropy",
        "repository_secret_scan",
        "repository_secret_scan_entropy",
    ):
        result = results[label]
        if result.get("findings") != []:
            raise VerificationError(f"{label} returned findings")
    if results["secret_scan"].get("patterns") != qualification["secret_scan_patterns"]:
        raise VerificationError("secret scanner pattern denominator mismatch")
    if results["secret_scan"].get("detectors", {}).get("entropy_enabled") is not False:
        raise VerificationError("baseline secret scan unexpectedly enabled entropy")
    if results["secret_scan_entropy"].get("detectors", {}).get("entropy_enabled") is not True:
        raise VerificationError("entropy-enabled secret scan did not enable entropy")
    if (
        results["repository_secret_scan"].get("detectors", {}).get("entropy_enabled") is not False
        or results["repository_secret_scan_entropy"].get("detectors", {}).get("entropy_enabled")
        is not True
    ):
        raise VerificationError("repository secret-scan entropy modes are inconsistent")

    if not args.quick:
        results["security_matrix"] = run_json(
            [python, "-B", "scripts/security_matrix.py", ".", "--json"], skill
        )
        expected_matrix = qualification["security_matrix_cases"]
        if results["security_matrix"].get("denominators", {}).get("total") != (
            f"{expected_matrix}/{expected_matrix}"
        ):
            raise VerificationError("security matrix denominator mismatch")
        results["pytest"] = run_pytest(
            [python, "-B", "-m", "pytest", "-q"],
            skill,
            qualification["pytest_passed"],
        )
        results["release_tool_tests"] = run_pytest(
            [python, "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tools/tests"],
            repo,
            qualification["release_tool_tests"],
        )

    dist_result = None
    if args.dist:
        dist = args.dist.resolve()
        zip_filename = zip_meta["filename"]
        if zip_filename.casefold() in {name.casefold() for name in FIXED_DIST_NAMES}:
            raise VerificationError("release ZIP filename collides with a fixed release asset")
        required_names = {
            zip_filename,
            "PUBLIC_RELEASE_MANIFEST.json",
            "RELEASE_EVIDENCE.md",
        }
        observed_dist = {
            path.relative_to(dist).as_posix()
            for path in inventory(dist)
        }
        expected_dist = required_names | {"SHA256SUMS.txt"}
        if observed_dist != expected_dist:
            raise VerificationError(
                f"dist inventory mismatch: observed={sorted(observed_dist)} "
                f"expected={sorted(expected_dist)}"
            )
        verify_checksums(dist, required_names)
        dist_result = verify_zip(
            dist / zip_filename,
            skill.name,
            skill_meta["files"],
            skill_meta["bytes"],
            skill_meta["source_tree_sha256"],
        )
        manifest_copy = dist / "PUBLIC_RELEASE_MANIFEST.json"
        if manifest_copy.read_bytes() != (repo / "release" / "PUBLIC_RELEASE_MANIFEST.json").read_bytes():
            raise VerificationError("dist manifest is not byte-identical to repository manifest")
        evidence_copy = dist / "RELEASE_EVIDENCE.md"
        if evidence_copy.read_bytes() != (repo / "docs" / "RELEASE_EVIDENCE.md").read_bytes():
            raise VerificationError("dist evidence is not byte-identical to repository evidence")
        if dist_result["sha256"] != zip_meta["sha256"]:
            raise VerificationError("release ZIP checksum disagrees with public manifest")

    output = {
        "status": "partial" if args.quick else "pass",
        "release": manifest["release"],
        "skill": {
            "files": len(files),
            "bytes": total,
            "source_tree_sha256": tree,
            "physical_tree_sha256": physical_sha,
            "physical_directories": physical_directories,
        },
        "checks": sorted(results),
        "dist": dist_result,
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, OSError, VerificationError, zipfile.BadZipFile) as exc:
        print(json.dumps({"status": "fail", "error": str(exc)}, indent=2), file=sys.stderr)
        raise SystemExit(1)
