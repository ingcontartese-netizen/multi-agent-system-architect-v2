from __future__ import annotations

import importlib.util
import os
import stat
import sys
import unicodedata
import zipfile
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[2]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build = load_module("public_build_release", REPO / "tools" / "build_release.py")
verify = load_module("public_verify_release", REPO / "tools" / "verify_release.py")


def test_payload_declares_intentional_package_free_setuptools_layout() -> None:
    project = (REPO / "skills" / "multi-agent-system-architect-v2" / "pyproject.toml").read_text(
        encoding="utf-8"
    )
    assert "[tool.setuptools]\npackages = []\n" in project


def test_ci_bootstrap_is_exactly_pinned_and_never_editable_installs_payload() -> None:
    workflow = (REPO / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
    install_lines = [
        line.strip()
        for line in workflow.splitlines()
        if line.lstrip().startswith("run: python -m pip install")
    ]
    assert len(install_lines) == 3
    assert all(" -e " not in line and "--editable" not in line for line in install_lines)
    for dependency in verify.PINNED_CI_DEPENDENCIES:
        assert all(line.count(f'"{dependency}"') == 1 for line in install_lines)


@pytest.mark.parametrize(
    "value",
    [
        "../escape.zip",
        "..\\escape.zip",
        "C:\\outside.zip",
        "C:outside.zip",
        "/absolute.zip",
        "CON.zip",
        "NUL.txt",
        "trailing.",
        "trailing ",
        "line\nbreak.zip",
        "PUBLIC_RELEASE_MANIFEST.json",
    ],
)
def test_builder_rejects_unsafe_or_reserved_archive_names(value: str) -> None:
    if value == "PUBLIC_RELEASE_MANIFEST.json":
        with pytest.raises(build.ReleaseError):
            name = build.asset_name(value)
            if name.casefold() in {item.casefold() for item in build.RESERVED_ASSET_NAMES}:
                raise build.ReleaseError("reserved")
    else:
        with pytest.raises(build.ReleaseError):
            build.asset_name(value)


@pytest.mark.parametrize(
    "value",
    [
        "../escape.zip",
        "..\\escape.zip",
        "C:\\outside.zip",
        "C:outside.zip",
        "/absolute.zip",
        "COM1.zip",
        "trailing.",
        "tab\tname.zip",
    ],
)
def test_verifier_rejects_unsafe_asset_names(value: str) -> None:
    with pytest.raises(verify.VerificationError):
        verify.asset_name(value)


@pytest.mark.parametrize(
    "relative",
    [
        "dir/C:bad.txt",
        "dir/AUX.txt",
        "dir/trailing.",
        "dir/back\\slash.txt",
        "dir/control\x01.txt",
        "dir/../escape.txt",
        "dir/" + unicodedata.normalize("NFD", "café.txt"),
    ],
)
def test_builder_rejects_nonportable_archive_components(relative: str) -> None:
    with pytest.raises(build.ReleaseError):
        build.safe_arcname("multi-agent-system-architect-v2", relative)


def test_json_runner_rejects_exit_zero_false_pass(tmp_path: Path) -> None:
    with pytest.raises(verify.VerificationError, match="non-pass"):
        verify.run_json(
            [sys.executable, "-c", "import json; print(json.dumps({'status':'fail'}))"],
            tmp_path,
        )


def test_checksum_parser_rejects_windows_drive_name_before_hashing(tmp_path: Path) -> None:
    (tmp_path / "SHA256SUMS.txt").write_text("0" * 64 + "  C:outside.zip\n", encoding="utf-8")
    with pytest.raises(verify.VerificationError, match="unsafe"):
        verify.verify_checksums(tmp_path, {"expected.zip"})


def test_builder_and_verifier_reject_hardlinks(tmp_path: Path) -> None:
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    first.write_text("same bytes", encoding="utf-8")
    try:
        os.link(first, second)
    except OSError as exc:
        pytest.skip(f"hardlinks unavailable: {exc}")
    if first.lstat().st_nlink < 2:
        pytest.skip("runtime does not expose hardlink counts")
    with pytest.raises(build.ReleaseError, match="hard-linked"):
        build.inventory(tmp_path)
    with pytest.raises(verify.VerificationError, match="hard-linked"):
        verify.inventory(tmp_path)


@pytest.mark.parametrize(
    "field,value",
    [
        ("sha256", None),
        ("sha256", "a" * 64),
        ("format", "deterministic-zip"),
        ("root_directory", "wrong-root"),
    ],
)
def test_verifier_requires_exact_zip_contract(field: str, value: object) -> None:
    contract = {
        "filename": "multi-agent-system-architect-v2-2.1.2.zip",
        "format": "deterministic-zip-stored",
        "root_directory": "multi-agent-system-architect-v2",
        "sha256": "B15112C77B694179026E582471B02870A8E22DAF85CB54D5CEC8AE3821A12620",
    }
    contract[field] = value
    manifest = {"assets": {"skill_zip": contract}}
    with pytest.raises(verify.VerificationError):
        verify.validate_zip_asset_contract(manifest, "multi-agent-system-architect-v2")


def canonical_zip_info() -> zipfile.ZipInfo:
    info = zipfile.ZipInfo("multi-agent-system-architect-v2/SKILL.md", (1980, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.create_version = 20
    info.extract_version = 20
    info.flag_bits = 0
    info.internal_attr = 0
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    info.compress_type = zipfile.ZIP_STORED
    info.file_size = 10
    info.compress_size = 10
    return info


def test_verifier_accepts_complete_stored_zip_metadata_profile() -> None:
    verify.verify_zip_info_metadata(canonical_zip_info(), "multi-agent-system-architect-v2/SKILL.md")


@pytest.mark.parametrize(
    "field,value",
    [
        ("compress_type", zipfile.ZIP_DEFLATED),
        ("flag_bits", 0x800),
        ("create_version", 45),
        ("extract_version", 45),
        ("internal_attr", 1),
    ],
)
def test_verifier_rejects_noncanonical_zip_metadata(field: str, value: int) -> None:
    info = canonical_zip_info()
    setattr(info, field, value)
    with pytest.raises(verify.VerificationError):
        verify.verify_zip_info_metadata(info, "multi-agent-system-architect-v2/SKILL.md")


def test_builder_preserves_preexisting_release_asset(tmp_path: Path) -> None:
    destination = tmp_path / "release.zip"
    destination.write_bytes(b"foreign asset")
    with pytest.raises(build.ReleaseError, match="refusing to overwrite"):
        build.build_zip(tmp_path, [("SKILL.md", b"payload")], destination)
    assert destination.read_bytes() == b"foreign asset"


def test_builder_uses_exclusive_owned_handle_without_path_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "release.zip"
    real_zipfile = zipfile.ZipFile

    def race_probe(target, *args, **kwargs):
        if isinstance(target, (str, bytes, os.PathLike)):
            Path(target).write_bytes(b"foreign race winner")
            raise FileExistsError(target)
        return real_zipfile(target, *args, **kwargs)

    monkeypatch.setattr(build.zipfile, "ZipFile", race_probe)
    build.build_zip(tmp_path, [("SKILL.md", b"payload")], destination)
    with real_zipfile(destination) as archive:
        assert archive.read(f"{tmp_path.name}/SKILL.md") == b"payload"


def test_exclusive_write_preserves_preexisting_companion_asset(tmp_path: Path) -> None:
    destination = tmp_path / "PUBLIC_RELEASE_MANIFEST.json"
    destination.write_bytes(b"foreign asset")
    with pytest.raises(build.ReleaseError, match="refusing to overwrite"):
        build.exclusive_write(destination, b"new payload")
    assert destination.read_bytes() == b"foreign asset"


def test_exclusive_write_removes_only_its_partial_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "RELEASE_EVIDENCE.md"
    original_open = Path.open

    class FailingWriter:
        def __init__(self, handle):
            self.handle = handle

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            self.handle.close()
            return False

        def fileno(self):
            return self.handle.fileno()

        def write(self, data):
            self.handle.write(data[:1])
            self.handle.flush()
            raise OSError("synthetic partial-write failure")

    def patched_open(path, *args, **kwargs):
        handle = original_open(path, *args, **kwargs)
        if path == destination and args and args[0] == "xb":
            return FailingWriter(handle)
        return handle

    monkeypatch.setattr(Path, "open", patched_open)
    with pytest.raises(OSError, match="synthetic partial-write failure"):
        build.exclusive_write(destination, b"new payload")
    assert not destination.exists()


def test_physical_tree_binds_empty_directories(tmp_path: Path) -> None:
    (tmp_path / "SKILL.md").write_text("payload", encoding="utf-8")
    algorithm_a, digest_a, files_a, directories_a = verify.physical_tree(tmp_path)
    (tmp_path / "empty").mkdir()
    algorithm_b, digest_b, files_b, directories_b = verify.physical_tree(tmp_path)
    assert algorithm_a == algorithm_b == "release-physical-tree-v1"
    assert files_a == files_b == 1
    assert directories_a == 0
    assert directories_b == 1
    assert digest_a != digest_b


def test_cleanup_removes_owned_file_but_preserves_replacement(tmp_path: Path) -> None:
    target = tmp_path / "asset.txt"
    target.write_bytes(b"owned")
    owned_identity = target.lstat()
    assert build.remove_if_owned(target, owned_identity) is True
    assert not target.exists()

    target.write_bytes(b"first identity")
    stale_identity = target.lstat()
    target.unlink()
    target.write_bytes(b"foreign replacement")
    assert build.remove_if_owned(target, stale_identity) is False
    assert target.read_bytes() == b"foreign replacement"
