#!/usr/bin/env python3
"""Build deterministic, create-once public release assets."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import unicodedata
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath


EXCLUDED_DIRS = {".git", ".pytest_cache", "__pycache__"}
EXCLUDED_SUFFIXES = {".pyc"}
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
RESERVED_ASSET_NAMES = {
    "PUBLIC_RELEASE_MANIFEST.json",
    "RELEASE_EVIDENCE.md",
    "SHA256SUMS.txt",
}
SAFE_ASSET_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}


class ReleaseError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--out", type=Path, required=True)
    return parser.parse_args()


def read_regular_bytes(path: Path) -> bytes:
    try:
        stat_result = path.lstat()
    except OSError as exc:
        raise ReleaseError(f"cannot stat required input {path}: {exc}") from exc
    reparse = bool(
        getattr(stat_result, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )
    if not stat.S_ISREG(stat_result.st_mode) or path.is_symlink() or reparse:
        raise ReleaseError(f"required input must be a regular non-link file: {path}")
    if getattr(stat_result, "st_nlink", 1) > 1:
        raise ReleaseError(f"hard-linked required input is forbidden: {path}")
    return path.read_bytes()


def load_manifest(repo: Path) -> tuple[dict, bytes]:
    path = repo / "release" / "PUBLIC_RELEASE_MANIFEST.json"
    try:
        data = read_regular_bytes(path)
        return json.loads(data.decode("utf-8")), data
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError(f"cannot read public release manifest: {exc}") from exc


def inventory(root: Path) -> list[Path]:
    if not root.is_dir():
        raise ReleaseError(f"skill root is missing: {root}")
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
                raise ReleaseError(f"link/reparse entry is forbidden: {relative.as_posix()}")
            key = unicodedata.normalize("NFC", relative.as_posix()).casefold()
            if key in path_keys:
                raise ReleaseError(f"case/Unicode-colliding path: {relative.as_posix()}")
            path_keys.add(key)
            if entry.is_dir(follow_symlinks=False):
                directories.append(path)
            elif entry.is_file(follow_symlinks=False):
                if getattr(stat_result, "st_nlink", 1) > 1:
                    raise ReleaseError(f"hard-linked file is forbidden: {relative.as_posix()}")
                if path.suffix.lower() not in EXCLUDED_SUFFIXES:
                    files.append(path)
            else:
                raise ReleaseError(f"special entry is forbidden: {relative.as_posix()}")
    return sorted(files, key=lambda p: p.relative_to(root).as_posix().encode("utf-8"))


def source_tree(root: Path, files: list[Path]) -> tuple[str, int]:
    digest = hashlib.sha256()
    total_bytes = 0
    for path in files:
        relative = path.relative_to(root).as_posix()
        data = path.read_bytes()
        total_bytes += len(data)
        record = f"{relative}\t{len(data)}\t{hashlib.sha256(data).hexdigest().upper()}\n"
        digest.update(record.encode("utf-8"))
    return digest.hexdigest().upper(), total_bytes


def safe_arcname(root_name: str, relative: str) -> str:
    candidate = PurePosixPath(root_name, relative)
    if candidate.is_absolute() or ".." in candidate.parts or "" in candidate.parts:
        raise ReleaseError(f"unsafe archive path: {candidate.as_posix()}")
    for part in candidate.parts:
        normalized = unicodedata.normalize("NFC", part)
        stem = part.split(".", 1)[0].upper()
        if (
            part != normalized
            or part in {".", ".."}
            or "\\" in part
            or ":" in part
            or any(ord(character) < 32 or ord(character) == 127 for character in part)
            or part.endswith((".", " "))
            or stem in WINDOWS_RESERVED_NAMES
        ):
            raise ReleaseError(f"non-portable archive component: {part!r}")
    return candidate.as_posix()


def snapshot(skill_root: Path, files: list[Path]) -> list[tuple[str, bytes]]:
    return [(path.relative_to(skill_root).as_posix(), path.read_bytes()) for path in files]


def snapshot_tree(items: list[tuple[str, bytes]]) -> tuple[str, int]:
    digest = hashlib.sha256()
    total_bytes = 0
    for relative, data in items:
        total_bytes += len(data)
        digest.update(
            f"{relative}\t{len(data)}\t{hashlib.sha256(data).hexdigest().upper()}\n".encode("utf-8")
        )
    return digest.hexdigest().upper(), total_bytes


def build_zip(skill_root: Path, items: list[tuple[str, bytes]], destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        handle = destination.open("xb")
    except FileExistsError as exc:
        raise ReleaseError(f"refusing to overwrite release asset: {destination}") from exc

    # Open the final path ourselves with O_EXCL semantics, then hand the owned
    # file object to ZipFile. This removes the exists/open TOCTOU window.
    # Failed builds retain any partial final path: path identity is not an
    # atomic ownership proof, so exception cleanup must never unlink a
    # replacement that another process may have installed.
    try:
        with handle:
            with zipfile.ZipFile(
                handle,
                mode="w",
                # Store bytes verbatim. DEFLATE output varies across zlib/zlib-ng
                # runtimes even when every payload byte and ZIP header is fixed.
                compression=zipfile.ZIP_STORED,
                strict_timestamps=True,
            ) as archive:
                for relative, data in items:
                    info = zipfile.ZipInfo(
                        safe_arcname(skill_root.name, relative),
                        date_time=FIXED_ZIP_TIME,
                    )
                    info.create_system = 3
                    info.create_version = 20
                    info.extract_version = 20
                    info.flag_bits = 0
                    info.internal_attr = 0
                    info.external_attr = (stat.S_IFREG | 0o644) << 16
                    info.compress_type = zipfile.ZIP_STORED
                    archive.writestr(info, data, compress_type=zipfile.ZIP_STORED)
    except Exception as exc:
        raise ReleaseError(
            "release ZIP build failed; partial output retained fail-closed at "
            f"{destination}; retry with a fresh --out directory: {exc}"
        ) from exc


def asset_name(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ReleaseError("release asset filename must be a non-empty string")
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
        raise ReleaseError(f"unsafe release asset filename: {value!r}")
    return value


def contained_file(directory: Path, name: str) -> Path:
    candidate = (directory / name).resolve()
    try:
        candidate.relative_to(directory)
    except ValueError as exc:
        raise ReleaseError(f"release asset escapes output directory: {name!r}") from exc
    if candidate.parent != directory:
        raise ReleaseError(f"release asset is not a direct child of output directory: {name!r}")
    return candidate


def exclusive_write(path: Path, data: bytes) -> None:
    try:
        handle = path.open("xb")
    except FileExistsError as exc:
        raise ReleaseError(f"refusing to overwrite release asset: {path}") from exc

    try:
        with handle:
            handle.write(data)
    except Exception as exc:
        raise ReleaseError(
            "release asset write failed; partial output retained fail-closed at "
            f"{path}; retry with a fresh --out directory: {exc}"
        ) from exc


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def main() -> int:
    args = parse_args()
    repo = args.repo.resolve()
    out = args.out.resolve()
    manifest, manifest_bytes = load_manifest(repo)
    skill_meta = manifest["skill"]
    skill_root = (repo / skill_meta["path"]).resolve()
    try:
        skill_root.relative_to(repo)
    except ValueError as exc:
        raise ReleaseError("skill path escapes repository") from exc

    try:
        out.relative_to(skill_root)
    except ValueError:
        pass
    else:
        raise ReleaseError("output directory must not be inside the Skill payload")

    manifest_source = repo / "release" / "PUBLIC_RELEASE_MANIFEST.json"
    evidence_source = repo / "docs" / "RELEASE_EVIDENCE.md"
    evidence_bytes = read_regular_bytes(evidence_source)

    files = inventory(skill_root)
    items = snapshot(skill_root, files)
    tree, total_bytes = snapshot_tree(items)
    if len(files) != skill_meta["files"]:
        raise ReleaseError(f"file count mismatch: {len(files)} != {skill_meta['files']}")
    if total_bytes != skill_meta["bytes"]:
        raise ReleaseError(f"byte count mismatch: {total_bytes} != {skill_meta['bytes']}")
    if tree != skill_meta["source_tree_sha256"]:
        raise ReleaseError(f"source tree mismatch: {tree} != {skill_meta['source_tree_sha256']}")

    if out.exists() and any(out.iterdir()):
        raise ReleaseError(f"output directory must be fresh or empty: {out}")
    out.mkdir(parents=True, exist_ok=True)

    archive_name = asset_name(manifest["assets"]["skill_zip"]["filename"])
    if archive_name.casefold() in {name.casefold() for name in RESERVED_ASSET_NAMES}:
        raise ReleaseError(f"release ZIP filename is reserved: {archive_name!r}")
    archive_path = contained_file(out, archive_name)
    manifest_asset = contained_file(out, manifest_source.name)
    evidence_asset = contained_file(out, evidence_source.name)
    checksum_path = contained_file(out, "SHA256SUMS.txt")
    try:
        build_zip(skill_root, items, archive_path)
        archive_sha = sha256_file(archive_path)

        post_files = inventory(skill_root)
        post_tree, post_bytes = source_tree(skill_root, post_files)
        if post_tree != tree or post_bytes != total_bytes or len(post_files) != len(files):
            raise ReleaseError("source changed while release assets were being built")

        exclusive_write(manifest_asset, manifest_bytes)
        exclusive_write(evidence_asset, evidence_bytes)

        checksums = {
            archive_path.name: archive_sha,
            manifest_asset.name: sha256_file(manifest_asset),
            evidence_asset.name: sha256_file(evidence_asset),
        }
        checksum_bytes = "".join(
            f"{digest}  {name}\n" for name, digest in sorted(checksums.items())
        ).encode("utf-8")
        exclusive_write(checksum_path, checksum_bytes)
    except Exception as exc:
        raise ReleaseError(
            "release build did not complete; no automatic path cleanup was attempted; "
            f"treat {out} as quarantined and retry with a fresh --out directory: {exc}"
        ) from exc

    result = {
        "status": "pass",
        "version": manifest["release"]["version"],
        "source_tree_sha256": tree,
        "files": len(files),
        "bytes": total_bytes,
        "assets": {
            **checksums,
            checksum_path.name: sha256_file(checksum_path),
        },
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, OSError, ReleaseError, zipfile.BadZipFile) as exc:
        print(json.dumps({"status": "fail", "error": str(exc)}, indent=2), file=sys.stderr)
        raise SystemExit(1)
