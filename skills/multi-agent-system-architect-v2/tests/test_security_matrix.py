from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
SCRIPT = SCRIPTS / "security_matrix.py"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location("security_matrix_under_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
security_matrix = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = security_matrix
SPEC.loader.exec_module(security_matrix)


EXPECTED_DIGESTS = {
    "generator": "A9698BBA460D716DC8A4C6308C2206917EF334A186D122852E5A4A701E5A6297",
    "parity": "6CBA4D76C2EF6491F3068C7AA7693E45FC5B562FA1DAA126614C7AD67F2A88C0",
    "scanner": "1CCA9AF8B8FDC21248E0F3F7811729AAACC601E60FE00F3BE758455AF0458197",
    "scanner_entropy_precision": "DC9B8531ACA02F75B22BB4890BE494B66ABCD9C757C492B9EE69A7FF652E1B2B",
    "portable_properties": "597D93C8D521FE18EF87B590D50DE73022EF1808B6BABBC4FCB2DC3C74910CD2",
    "negative_ordered": "52A3459EAD7D79F1AA21DA6F2B891BFA1DDAC30169F544EC00E1139935CD3808",
    "all_ordered": "A745EAE420DEB88722812F8B11D56713171FB2865E999B61D5DFBC2BCADC675B",
}


def _digest(case_ids: list[str]) -> str:
    return hashlib.sha256("\n".join(case_ids).encode("utf-8")).hexdigest().upper()


@pytest.fixture(scope="session")
def cli_runs() -> tuple[subprocess.CompletedProcess[str], subprocess.CompletedProcess[str]]:
    command = [sys.executable, str(SCRIPT), str(ROOT), "--json"]
    first = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=security_matrix.MAX_TOTAL_SECONDS + 10,
        check=False,
    )
    second = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=security_matrix.MAX_TOTAL_SECONDS + 10,
        check=False,
    )
    return first, second


def test_case_registry_exact_order_uniqueness_and_digest() -> None:
    ids = security_matrix.all_case_ids()
    expected_generator = (
        [f"G-CFG-{index:03d}" for index in range(1, 41)]
        + [f"G-PATH-{index:03d}" for index in range(1, 46)]
        + [f"G-PARSE-{index:03d}" for index in range(1, 11)]
    )
    expected_parity = (
        [f"P-MAN-{index:03d}" for index in range(1, 56)]
        + [f"P-HOSTPATH-{index:03d}" for index in range(1, 37)]
        + [f"P-ENC-{index:03d}" for index in range(1, 11)]
        + [f"P-PROJECT-{index:03d}" for index in range(1, 11)]
    )
    expected_scanner = [f"SCAN-COMPAT-{index:03d}" for index in range(1, 18)]
    expected_entropy_precision = [
        "SCAN-ENTROPY-SEMANTIC-ASSIGNMENT",
        "SCAN-ENTROPY-NATIVE-NPMRC",
        "SCAN-ENTROPY-NATIVE-NETRC",
        "SCAN-ENTROPY-NATIVE-PGPASS",
        "SCAN-ENTROPY-BARE-HEX",
        "SCAN-ENTROPY-BARE-BASE64",
        "SCAN-PRECISION-COMMON-DIGEST",
        "SCAN-PRECISION-UUID",
        "SCAN-PRECISION-PLACEHOLDER",
        "SCAN-PRECISION-NONSECRET-SUFFIX",
        "SCAN-PRECISION-GENERIC-NAME",
        "SCAN-PRECISION-LOW-ENTROPY",
    ]
    expected_portable = (
        [f"PROP-PATH-ALIAS-{index:03d}" for index in range(1, 7)]
        + [f"PROP-PATH-RESERVED-{index:03d}" for index in range(1, 7)]
        + [f"PROP-PATH-NFC-{index:03d}" for index in range(1, 3)]
        + [f"PROP-PATH-WINCHAR-{index:03d}" for index in range(1, 11)]
        + [f"PROP-PATH-UNICODE-{index:03d}" for index in range(1, 9)]
        + [f"PROP-ENC-{index:03d}" for index in range(1, 9)]
        + [f"PROP-SHAPE-{index:03d}" for index in range(1, 7)]
        + [f"PROP-PATH-FUZZ-{index:03d}" for index in range(1, 13)]
    )
    assert ids == {
        "generator": expected_generator,
        "parity": expected_parity,
        "scanner": expected_scanner,
        "scanner_entropy_precision": expected_entropy_precision,
        "portable_properties": expected_portable,
    }
    ordered = (
        expected_generator
        + expected_parity
        + expected_scanner
        + expected_entropy_precision
        + expected_portable
    )
    assert len(expected_generator) == 95
    assert len(expected_parity) == 111
    assert len(expected_scanner) == 17
    assert len(expected_entropy_precision) == 12
    assert len(expected_portable) == 58
    assert len(ordered) == 293 == len(set(ordered))
    assert _digest(expected_generator) == EXPECTED_DIGESTS["generator"]
    assert _digest(expected_parity) == EXPECTED_DIGESTS["parity"]
    assert _digest(expected_scanner) == EXPECTED_DIGESTS["scanner"]
    assert _digest(expected_entropy_precision) == EXPECTED_DIGESTS["scanner_entropy_precision"]
    assert _digest(expected_portable) == EXPECTED_DIGESTS["portable_properties"]
    assert _digest(expected_generator + expected_parity) == EXPECTED_DIGESTS["negative_ordered"]
    assert _digest(ordered) == EXPECTED_DIGESTS["all_ordered"]


def test_portable_paths_use_shipped_predicate_and_fuzz_is_finite() -> None:
    fixed = [
        case
        for case in security_matrix.portable_property_cases()
        if case.evaluator == "portable_path"
    ]
    assert len(fixed) == 32
    for case in fixed:
        try:
            result = security_matrix.canonical_relative_posix_path(
                case.payload,
                label=case.case_id,
            )
            accepted = result == case.payload
        except security_matrix.ContractError:
            accepted = False
        assert accepted == case.expected
        assert security_matrix._run_property(case) == (True, True)

    first = [
        security_matrix._sha_fuzz_path(index)
        for index in range(1, security_matrix.SHA_FUZZ_CASES + 1)
    ]
    second = [
        security_matrix._sha_fuzz_path(index)
        for index in range(1, security_matrix.SHA_FUZZ_CASES + 1)
    ]
    assert first == second
    assert len(first) == len(set(first)) == 12
    assert all(1 <= len(value) <= security_matrix.MAX_FUZZ_PATH_CODEPOINTS for value in first)
    assert security_matrix._value_digest(first) == (
        "ECFAE319FFD59158AB707EC8D10CEDB0F12F03B778AD9DEE39A8D71383733FEA"
    )


def test_manifest_fixture_uses_current_70_file_contract() -> None:
    manifest = security_matrix._base_manifest()
    assert manifest["canonical_files"] == 70
    assert [entry["files"] for entry in manifest["entries"]] == [70, 70, 70]


def test_cli_is_deterministic_and_reports_fixed_denominators(
    cli_runs: tuple[subprocess.CompletedProcess[str], subprocess.CompletedProcess[str]],
) -> None:
    first, second = cli_runs
    assert first.returncode == second.returncode == 0, first.stdout + first.stderr
    assert first.stderr == second.stderr == ""
    assert first.stdout == second.stdout
    payload = json.loads(first.stdout)
    assert payload["status"] == "pass"
    assert payload["suite_version"] == "2.1.2"
    assert payload["seed"] == 210001
    assert payload["denominators"] == {
        "generator_negative": "95/95",
        "parity_negative": "111/111",
        "negative_total": "206/206",
        "scanner_compatibility": "17/17",
        "scanner_entropy_precision": "12/12",
        "portable_properties": "58/58",
        "total": "293/293",
    }
    assert payload["digests"] == EXPECTED_DIGESTS
    assert payload["errors"] == []
    assert payload["platform_evidence"] == {
        "windows": (
            "live" if security_matrix.os.name == "nt" else "modeled_not_live_verified"
        ),
        "linux": "modeled_not_live_verified",
        "macos": "modeled_not_live_verified",
    }
    assert payload["declared_limits"] == {
        "linux_case_sensitivity": "modeled_not_live_verified",
        "macos_normalization_and_firmlink": "modeled_not_live_verified",
        "posix_permissions": "not_exercised",
        "finite_fuzz_scope": {
            "cases": 12,
            "corpus_sha256": "ECFAE319FFD59158AB707EC8D10CEDB0F12F03B778AD9DEE39A8D71383733FEA",
            "derivation": "SHA-256",
            "invariant": "no_crash_and_repeatable_outcome",
            "max_path_codepoints": 48,
        },
    }


def test_no_fixture_or_synthetic_token_leaks_to_output(
    cli_runs: tuple[subprocess.CompletedProcess[str], subprocess.CompletedProcess[str]],
) -> None:
    first, _ = cli_runs
    output = first.stdout + first.stderr
    for _, _, content, _ in security_matrix._scanner_specs():
        assert content not in output
    for _, _, _, content, token, _ in security_matrix._entropy_specs():
        assert content not in output
        assert token not in output
    assert "masa-security-matrix-" not in output
    assert "fixture.txt" not in output


def test_input_output_and_source_preservation(
    cli_runs: tuple[subprocess.CompletedProcess[str], subprocess.CompletedProcess[str]],
) -> None:
    first, _ = cli_runs
    payload = json.loads(first.stdout)
    assert payload["preservation"] == {
        "typed_inputs": "206/206",
        "portable_inputs": "58/58",
        "scanner_inputs_and_outputs": "17/17",
        "entropy_inputs_and_outputs": "12/12",
        "source_unchanged": True,
    }
    readback = payload["source_readback"]
    assert readback["files_before"] == readback["files_after"] == 70
    assert readback["sha256_before"] == readback["sha256_after"]
    assert payload["resources"] == {
        "case_cap": 300,
        "fixture_bytes_cap": 4096,
        "subprocess_timeout_seconds": 5.0,
        "temp_file_cap": 32,
        "total_timeout_seconds": 120.0,
    }


def test_exit_two_for_invalid_root(tmp_path: Path) -> None:
    invalid = tmp_path / "not-the-canonical-root"
    invalid.mkdir()
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), str(invalid), "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=10,
        check=False,
    )
    assert completed.returncode == 2
    assert completed.stderr == ""
    assert json.loads(completed.stdout) == {
        "status": "error",
        "suite_version": "2.1.2",
        "seed": 210001,
        "error": "ContractError",
    }


def test_main_maps_matrix_failure_to_exit_one(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        security_matrix,
        "parse_args",
        lambda: SimpleNamespace(root=ROOT, json=True),
    )
    monkeypatch.setattr(
        security_matrix,
        "run_matrix",
        lambda root: {
            "status": "fail",
            "suite_version": "2.1.2",
            "seed": 210001,
            "errors": ["synthetic_failure"],
        },
    )
    assert security_matrix.main() == 1
