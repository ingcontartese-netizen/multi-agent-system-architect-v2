from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "scripts" / "secret_scan.py"
ENTROPY_FIELDS = {
    "entropy",
    "kind",
    "length",
    "line",
    "path",
    "token_sha256",
}


def run_scan(root: Path, *, entropy: bool = False) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    command = [sys.executable, "-B", str(SCANNER), str(root)]
    if entropy:
        command.append("--entropy")
    command.append("--json")
    return subprocess.run(
        command,
        text=True,
        capture_output=True,
        encoding="utf-8",
        errors="strict",
        env=env,
        timeout=30,
    )


def lower_material(seed: bytes) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    material = b"".join(
        hashlib.sha256(seed + bytes((index,))).digest() for index in range(3)
    )
    return "".join(alphabet[value % len(alphabet)] for value in material[:64])


def mixed_material(seed: bytes) -> str:
    return base64.b64encode(hashlib.sha512(seed).digest()).decode("ascii")


def hex_material(seed: bytes) -> str:
    return hashlib.sha256(seed).hexdigest()[:48]


def write_bytes(path: Path, *parts: bytes) -> None:
    path.write_bytes(b"".join(parts))


def load_scanner_module():
    spec = importlib.util.spec_from_file_location("secret_scan_21_under_test", SCANNER)
    assert spec is not None and spec.loader is not None
    scripts = str(SCANNER.parent)
    sys.path.insert(0, scripts)
    try:
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(scripts)
    return module


def test_entropy_profile_catches_e1_through_e6_and_redacts(tmp_path: Path) -> None:
    lower = lower_material(b"semantic-lower")
    mixed = mixed_material(b"semantic-mixed")
    camel = mixed_material(b"semantic-camel")
    secret_key = mixed_material(b"semantic-secret-key")
    dsa = mixed_material(b"carrier-dsa")
    ecdsa = hex_material(b"carrier-ecdsa")
    pgpass = mixed_material(b"carrier-pgpass")
    npm = mixed_material(b"native-npm")
    netrc = mixed_material(b"native-netrc")

    write_bytes(
        tmp_path / "e1-lower.json",
        b'{"api_key":"',
        lower.encode("ascii"),
        b'"}\n',
    )
    write_bytes(
        tmp_path / "e1-mixed.json",
        b'{"api_key":"',
        mixed.encode("ascii"),
        b'"}\n',
    )
    write_bytes(
        tmp_path / "semantic.env",
        b"dbPassword=",
        camel.encode("ascii"),
        b"\nSECRET_KEY=",
        secret_key.encode("ascii"),
        b"\n",
    )
    write_bytes(tmp_path / "id_dsa", dsa.encode("ascii"), b"\n")
    write_bytes(tmp_path / "id_ecdsa", ecdsa.encode("ascii"), b"\n")
    write_bytes(
        tmp_path / ".pgpass",
        b"db.invalid:5432:sample:user:",
        pgpass.encode("ascii"),
        b"\n",
    )
    write_bytes(
        tmp_path / ".npmrc",
        b"//registry.invalid/:_authToken=",
        npm.encode("ascii"),
        b"\n",
    )
    write_bytes(
        tmp_path / ".netrc",
        b"machine example.invalid login synthetic password ",
        netrc.encode("ascii"),
        b"\n",
    )

    first = run_scan(tmp_path, entropy=True)
    second = run_scan(tmp_path, entropy=True)
    assert first.returncode == second.returncode == 1, first.stdout + first.stderr
    assert first.stdout == second.stdout
    payload = json.loads(first.stdout)
    entropy_findings = payload["entropy_findings"]
    finding_paths = {item["path"] for item in entropy_findings}
    assert {"e1-lower.json", "e1-mixed.json"} <= finding_paths
    kinds = {item["kind"] for item in entropy_findings}
    assert {
        "entropy_bare_base64",
        "entropy_bare_hex",
        "entropy_native_netrc",
        "entropy_native_npmrc",
        "entropy_native_pgpass",
        "entropy_semantic_assignment",
    } <= kinds
    assert all(set(item) == ENTROPY_FIELDS for item in entropy_findings)
    assert all(item["length"] > 0 and item["entropy"] > 0 for item in entropy_findings)
    identities = [
        (item["path"], item["line"], item["kind"], item["token_sha256"])
        for item in entropy_findings
    ]
    assert identities == sorted(identities)
    assert len(identities) == len(set(identities))
    assert payload["patterns"] == 15
    assert payload["policy_version"] == "2.1.0"
    assert payload["eligible_files"] == payload["scanned_files"] == 8
    assert payload["skipped_files"] == 0
    assert payload["detectors"]["entropy_enabled"] is True
    assert len(payload["config_sha256"]) == 64
    assert payload["config_sha256"] == json.loads(second.stdout)["config_sha256"]
    output = first.stdout + first.stderr
    for value in (lower, mixed, camel, secret_key, dsa, ecdsa, pgpass, npm, netrc):
        assert value not in output


def test_entropy_profile_avoids_digest_uuid_prose_and_placeholders(
    tmp_path: Path,
) -> None:
    digest = hashlib.sha256(b"digest-control").hexdigest()
    identifier = str(uuid.uuid5(uuid.NAMESPACE_DNS, "scanner-control.invalid"))
    random_text = mixed_material(b"non-carrier-prose")
    hint = mixed_material(b"password-hint-control")
    count = mixed_material(b"token-count-control")
    credential_name = mixed_material(b"credential-name-control")
    write_bytes(
        tmp_path / "controls.env",
        b"SHA256=",
        digest.encode("ascii"),
        b"\nrequest_id=",
        identifier.encode("ascii"),
        b"\nPASSWORD_HINT=",
        hint.encode("ascii"),
        b"\nTOKEN_COUNT=",
        count.encode("ascii"),
        b"\ncredential_name=",
        credential_name.encode("ascii"),
        b"\ndbPassword=replace_",
        b"me\nSECRET_KEY=${SECRET_",
        b"KEY}\napi_key=change",
        b"me\n",
    )
    write_bytes(tmp_path / "id_dsa", digest.encode("ascii"), b"\n")
    write_bytes(
        tmp_path / ".netrc",
        b"machine example.invalid login synthetic password place",
        b"holder\n",
    )
    write_bytes(
        tmp_path / "notes.md",
        b"This prose mentions password rotation without assigning a value.\n",
        random_text.encode("ascii"),
        b"\n",
    )

    result = run_scan(tmp_path, entropy=True)
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "pass"
    assert payload["findings"] == []
    assert payload["entropy_findings"] == []


def test_entropy_is_opt_in_and_legacy_regex_findings_stay_compatible(
    tmp_path: Path,
) -> None:
    value = mixed_material(b"opt-in-control")
    write_bytes(tmp_path / "settings.env", b"dbPassword=", value.encode("ascii"), b"\n")

    legacy = run_scan(tmp_path)
    assert legacy.returncode == 0, legacy.stdout + legacy.stderr
    legacy_payload = json.loads(legacy.stdout)
    assert legacy_payload["findings"] == []
    assert "entropy_findings" not in legacy_payload
    assert legacy_payload["detectors"]["entropy_enabled"] is False

    enabled = run_scan(tmp_path, entropy=True)
    assert enabled.returncode == 1, enabled.stdout + enabled.stderr
    enabled_payload = json.loads(enabled.stdout)
    assert enabled_payload["findings"] == []
    assert enabled_payload["entropy_findings"][0]["kind"] == "entropy_semantic_assignment"
    assert value not in enabled.stdout + enabled.stderr


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (b"valid\x00tail", "NUL byte"),
        (bytes((0xFF, 0xFE, 0x41)), "Invalid UTF-8"),
    ],
)
def test_scanner_fails_closed_on_nul_and_invalid_utf8(
    tmp_path: Path,
    content: bytes,
    message: str,
) -> None:
    (tmp_path / "input.txt").write_bytes(content)
    result = run_scan(tmp_path, entropy=True)
    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["status"] == "error"
    assert message in payload["error"]
    assert payload["scanned_files"] == 0


@pytest.mark.parametrize("limit", ["files", "file_bytes", "total_bytes"])
def test_scanner_enforces_resource_caps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    limit: str,
) -> None:
    module = load_scanner_module()
    (tmp_path / "a.txt").write_bytes(b"alpha\n")
    (tmp_path / "b.txt").write_bytes(b"bravo\n")
    module.MAX_FILES = 10
    module.MAX_FILE_BYTES = 10
    module.MAX_TOTAL_BYTES = 20
    if limit == "files":
        module.MAX_FILES = 1
    elif limit == "file_bytes":
        module.MAX_FILE_BYTES = 5
    else:
        module.MAX_TOTAL_BYTES = 10
    monkeypatch.setattr(
        sys,
        "argv",
        [str(SCANNER), str(tmp_path), "--entropy", "--json"],
    )

    assert module.main() == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "error"
    assert "limit" in payload["error"]
    assert payload["scanned_files"] == 0
    assert payload["limits"]["max_files"] == module.MAX_FILES
    assert payload["limits"]["max_file_bytes"] == module.MAX_FILE_BYTES
    assert payload["limits"]["max_total_bytes"] == module.MAX_TOTAL_BYTES


def test_canonical_tree_has_no_entropy_findings() -> None:
    result = run_scan(ROOT, entropy=True)
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["findings"] == []
    assert payload["entropy_findings"] == []


def test_scanner_rejects_symlink_and_hardlink_carriers(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    source.write_text("benign\n", encoding="utf-8", newline="\n")
    hardlink = tmp_path / "linked.txt"
    try:
        os.link(source, hardlink)
    except (OSError, NotImplementedError):
        pytest.skip("hardlinks unavailable")
    result = run_scan(tmp_path, entropy=True)
    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["status"] == "error"
    assert "hardlinked" in payload["error"]
