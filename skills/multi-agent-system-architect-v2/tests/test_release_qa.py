from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import _release_guard as guard  # noqa: E402
import security_matrix as matrix  # noqa: E402


@pytest.fixture
def source(tmp_path: Path) -> Path:
    candidate = tmp_path / "multi-agent-system-architect-v2"
    (candidate / "scripts").mkdir(parents=True)
    (candidate / "tests").mkdir()
    (candidate / "SKILL.md").write_text(
        "---\nname: multi-agent-system-architect-v2\n"
        "description: fixture\n---\n\n# Fixture\n",
        encoding="utf-8",
        newline="\n",
    )
    (candidate / "pyproject.toml").write_text(
        '[project]\nname = "fixture"\nversion = "2.1.2"\n',
        encoding="utf-8",
        newline="\n",
    )
    return candidate


def _cli(*arguments: object) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONUTF8"] = "1"
    environment["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [
            sys.executable,
            "-B",
            str(SCRIPTS / "release_qa.py"),
            *(str(item) for item in arguments),
        ],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        check=False,
        timeout=30,
        env=environment,
    )


def _remove_lease_after_tamper(lease: guard.CooperativeLease, original: bytes) -> None:
    owner = lease.path / guard.LEASE_OWNER
    owner.write_bytes(original)
    lease.release()


def _materialize_required_components(source: Path) -> None:
    names = {item.script for item in guard.VALIDATOR_SPECS}
    names.update({"generate_host_adapters.py", "adapter_parity_check.py"})
    for name in names:
        (source / "scripts" / name).write_text(
            "# release QA fixture component\n",
            encoding="utf-8",
            newline="\n",
        )


def _manifest_hash(records: tuple[tuple[str, int, str], ...]) -> str:
    data = "".join(
        f"{path}\t{size}\t{file_hash}\n"
        for path, size, file_hash in records
    ).encode("utf-8")
    return guard.sha256_bytes(data)


def _stubbed_evidence(root: Path) -> tuple[dict, dict, dict]:
    snapshot = guard.snapshot_tree(root)
    source_hash = _manifest_hash(snapshot.records)
    quick = {"files": snapshot.files, "public_tree_sha256": "A" * 64}
    source = {
        "files": snapshot.files,
        "manifest_sha256": source_hash,
        "tree_sha256": source_hash,
        "_records": snapshot.records,
    }
    validators = {
        "quick_validate": quick,
        "source_manifest": guard.public_source_evidence(source),
        "secret_scan": {
            "config_sha256": guard.EXPECTED_SECRET_CONFIG_SHA256,
            "entropy_enabled": True,
            "patterns": guard.EXPECTED_SECRET_PATTERNS,
            "scanned_files": 1,
        },
        "contract_bundle": {"artifacts": "9/9"},
        "eval_corpus_v2": {
            "cases": 36,
            "hard_check_ids": 108,
            "fault_scenarios": 47,
            "mutants": 32,
        },
        "security_matrix": {
            "denominators": guard.SECURITY_DENOMINATORS,
            "digests": {"all_ordered": guard.SECURITY_ALL_CASE_IDS_SHA256},
        },
    }
    return validators, quick, source


def _source_payload(
    root: Path,
    records: tuple[tuple[str, int, str], ...],
) -> dict:
    tree_hash = _manifest_hash(records)
    return {
        "algorithm": "relative_posix_path<TAB>bytes<TAB>uppercase_sha256<LF>",
        "encoding": "UTF-8 without BOM",
        "errors": [],
        "excluded_dirs": [".git", ".pytest_cache", "__pycache__"],
        "excluded_suffixes": [".pyc"],
        "files": len(records),
        "records": [
            {"path": path, "size": size, "sha256": file_hash}
            for path, size, file_hash in records
        ],
        "root": str(root.resolve()),
        "status": "pass",
        "tree_sha256": tree_hash,
    }


def _ids_digest(values: list[str]) -> str:
    return guard.sha256_bytes("\n".join(values).encode("utf-8"))


def _security_payload(source_manifest: dict) -> dict:
    case_ids = matrix.all_case_ids()
    ordered = [
        case_id
        for group in guard.SECURITY_CASE_COUNTS
        for case_id in case_ids[group]
    ]
    digests = {
        group: _ids_digest(case_ids[group])
        for group in guard.SECURITY_CASE_COUNTS
    }
    digests["negative_ordered"] = _ids_digest(
        case_ids["generator"] + case_ids["parity"]
    )
    digests["all_ordered"] = _ids_digest(ordered)
    return {
        "case_ids": case_ids,
        "declared_limits": copy.deepcopy(guard.SECURITY_DECLARED_LIMITS),
        "denominators": dict(guard.SECURITY_DENOMINATORS),
        "digests": digests,
        "errors": [],
        "platform_evidence": {
            "windows": (
                "live" if guard.sys.platform == "win32" else "modeled_not_live_verified"
            ),
            "linux": (
                "live"
                if guard.sys.platform.startswith("linux")
                else "modeled_not_live_verified"
            ),
            "macos": (
                "live" if guard.sys.platform == "darwin" else "modeled_not_live_verified"
            ),
        },
        "preservation": dict(guard.SECURITY_PRESERVATION),
        "resources": dict(guard.SECURITY_RESOURCES),
        "seed": guard.SECURITY_SUITE_SEED,
        "source_readback": {
            "files_before": source_manifest["files"],
            "files_after": source_manifest["files"],
            "sha256_before": source_manifest["tree_sha256"],
            "sha256_after": source_manifest["tree_sha256"],
        },
        "status": "pass",
        "suite_version": guard.RUNNER_VERSION,
    }


def _junit_bytes(outcomes: list[tuple[str, str]]) -> bytes:
    tallies = {
        "failure": sum(outcome == "failure" for _, outcome in outcomes),
        "error": sum(outcome == "error" for _, outcome in outcomes),
        "skipped": sum(outcome == "skipped" for _, outcome in outcomes),
    }
    cases = []
    for name, outcome in outcomes:
        marker = "" if outcome == "passed" else f"<{outcome} />"
        cases.append(f'<testcase classname="tests.test_guard" name="{name}">{marker}</testcase>')
    return (
        '<testsuites><testsuite name="pytest" '
        f'tests="{len(outcomes)}" failures="{tallies["failure"]}" '
        f'errors="{tallies["error"]}" skipped="{tallies["skipped"]}">'
        + "".join(cases)
        + "</testsuite></testsuites>"
    ).encode("utf-8")


def test_list_is_deterministic_and_reports_component_availability(
    source: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture_files, _ = guard._physical_inventory(source)
    monkeypatch.setattr(guard, "PUBLIC_ONLY_FILE_SET", frozenset(fixture_files))
    monkeypatch.setattr(
        guard,
        "_run_public_source_gate",
        lambda *_args, **_kwargs: {"files": guard.snapshot_tree(source).files},
    )
    first, first_code = guard.list_command(source)
    second, second_code = guard.list_command(source)
    assert first_code == second_code == 0
    assert first == second
    payload = first
    assert payload["status"] == "pass"
    assert payload["command"] == "list"
    assert payload["source_snapshot"]["files"] == 2
    assert payload["adapter_bundles"] == 2
    assert payload["payload_readbacks"] == 6
    assert any(
        item["id"] == "security_matrix" and item["available"] is False
        for item in payload["components"]
    )


def test_lease_contention_status_expiry_and_no_auto_reclaim(
    source: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lease = guard.CooperativeLease.acquire(source, 30)
    try:
        with pytest.raises(guard.BlockedError) as contention:
            guard.CooperativeLease.acquire(source, 30)
        assert contention.value.code == "LEASE_HELD"

        active, active_code = guard.inspect_lease(source)
        assert active_code == 3
        assert active["state"] == "active"
        assert "token" not in active
        assert len(active["token_sha256"]) == 64

        monkeypatch.setattr(guard.time, "time", lambda: active["expires_epoch"] + 1)
        expired, expired_code = guard.inspect_lease(source)
        assert expired_code == 3
        assert expired["state"] == "expired"
        with pytest.raises(guard.BlockedError):
            guard.CooperativeLease.acquire(source, 30)
    finally:
        lease.release()
    absent, absent_code = guard.inspect_lease(source)
    assert absent_code == 0
    assert absent == {"state": "absent"}


def test_lease_loss_is_fail_closed_and_does_not_delete_foreign_state(
    source: Path,
) -> None:
    lease = guard.CooperativeLease.acquire(source, 60)
    owner = lease.path / guard.LEASE_OWNER
    original = owner.read_bytes()
    value = json.loads(original)
    value["token_sha256"] = "A" * 64
    owner.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    with pytest.raises(guard.BlockedError) as lost:
        lease.release()
    assert lost.value.code == "LEASE_OWNERSHIP_LOST"
    assert lease.path.is_dir()
    assert owner.is_file()
    _remove_lease_after_tamper(lease, original)


def test_work_root_path_rejections_are_side_effect_free(source: Path) -> None:
    existing = source.parent / "existing"
    existing.mkdir()
    with pytest.raises(guard.RunnerError) as present:
        guard.validate_work_root(source, existing)
    assert present.value.code == "WORK_ROOT_MUST_BE_ABSENT"

    inside = source / "work"
    with pytest.raises(guard.RunnerError) as overlap:
        guard.validate_work_root(source, inside)
    assert overlap.value.code == "WORK_ROOT_SOURCE_OVERLAP"
    assert not inside.exists()

    install_parent = source.parent / ".codex" / "skills"
    install_parent.mkdir(parents=True)
    install_target = install_parent / "qa-work"
    with pytest.raises(guard.RunnerError) as install:
        guard.validate_work_root(source, install_target)
    assert install.value.code == "WORK_ROOT_INSTALL_ROOT_FORBIDDEN"
    assert not install_target.exists()


def test_physical_snapshot_detects_same_size_file_and_empty_directory_drift(
    source: Path,
) -> None:
    before = guard.snapshot_tree(source)
    project = source / "pyproject.toml"
    original = project.read_bytes()
    changed = bytes([original[0] ^ 1]) + original[1:]
    assert len(changed) == len(original)
    project.write_bytes(changed)
    after_file = guard.snapshot_tree(source)
    assert after_file.tree_sha256 != before.tree_sha256
    assert after_file.files == before.files

    project.write_bytes(original)
    (source / "empty-directory").mkdir()
    after_directory = guard.snapshot_tree(source)
    assert after_directory.tree_sha256 != before.tree_sha256
    assert after_directory.directories == before.directories + 1


def test_create_once_seal_never_overwrites(source: Path) -> None:
    seal = source.parent / "release-seal.json"
    payload = {
        "schema_version": guard.SCHEMA_VERSION,
        "status": "pass",
        "tree_sha256": "B" * 64,
    }
    guard.write_seal_once(seal, payload)
    frozen = seal.read_bytes()
    frozen_hash = hashlib.sha256(frozen).hexdigest()
    with pytest.raises(guard.RunnerError) as duplicate:
        guard.write_seal_once(seal, {"status": "different"})
    assert duplicate.value.code == "SEAL_EXISTS"
    assert hashlib.sha256(seal.read_bytes()).hexdigest() == frozen_hash


def test_owned_work_cleanup_refuses_identity_replacement_and_preserves_canary(
    source: Path,
) -> None:
    work_path = source.parent / "owned-work"
    owned = guard.OwnedWork.create(work_path, source)
    displaced = source.parent / "displaced-owned-work"
    work_path.rename(displaced)
    work_path.mkdir()
    canary = work_path / "CANARY.txt"
    canary.write_bytes(b"must-survive\n")
    with pytest.raises(guard.BlockedError) as lost:
        owned.cleanup()
    assert lost.value.code == "WORK_IDENTITY_LOST"
    assert canary.read_bytes() == b"must-survive\n"
    shutil.rmtree(work_path)
    displaced.rename(work_path)
    owned.cleanup()


def test_validator_profile_is_public_v2_entropy_and_nonrecursive() -> None:
    by_id = {item.identifier: item for item in guard.VALIDATOR_SPECS}
    assert by_id["quick_validate"].arguments == (
        "{root}",
        "--profile",
        "public-only",
        "--json",
    )
    assert by_id["eval_corpus_v2"].arguments == (
        "{root}",
        "--profile",
        "v2",
        "--json",
    )
    assert by_id["secret_scan"].arguments == (
        "{root}",
        "--entropy",
        "--json",
    )
    flattened = [argument for item in guard.VALIDATOR_SPECS for argument in item.arguments]
    assert "full" not in flattened
    assert all("release_qa.py" not in item.script for item in guard.VALIDATOR_SPECS)


def test_secret_entropy_evidence_is_semantically_required() -> None:
    child = guard.ChildResult(0, b"", b"")
    records = (
        ("SKILL.md", 4, "A" * 64),
        ("asset.bin", 3, "B" * 64),
        ("scripts/secret_scan.py", 10, "C" * 64),
    )
    source_manifest = {
        "files": len(records),
        "tree_sha256": _manifest_hash(records),
        "_records": records,
    }
    counts = guard.expected_secret_counts(source_manifest)
    passing = {
        "status": "pass",
        "findings": [],
        "entropy_findings": [],
        "patterns": guard.EXPECTED_SECRET_PATTERNS,
        "policy_version": guard.EXPECTED_SECRET_POLICY_VERSION,
        "config_sha256": guard.EXPECTED_SECRET_CONFIG_SHA256,
        "detectors": {
            "context_entropy": list(guard.EXPECTED_SECRET_ENTROPY_DETECTORS),
            "entropy_enabled": True,
            "regex": list(guard.EXPECTED_SECRET_REGEX_DETECTORS),
        },
        "layers": list(guard.EXPECTED_SECRET_LAYERS),
        "limits": guard.EXPECTED_SECRET_LIMITS,
        **counts,
    }
    evidence = guard.validate_secret_payload(
        child,
        passing,
        step="secret_scan",
        source_manifest=source_manifest,
    )
    assert evidence["entropy_enabled"] is True
    assert evidence["config_sha256"] == guard.EXPECTED_SECRET_CONFIG_SHA256

    disabled = copy.deepcopy(passing)
    disabled["detectors"]["entropy_enabled"] = False
    with pytest.raises(guard.QaFailure) as rejected:
        guard.validate_secret_payload(
            child,
            disabled,
            step="secret_scan",
            source_manifest=source_manifest,
        )
    assert rejected.value.code == "SECRET_POLICY_DRIFT"

    false_pass = dict(passing, scanned_files=1, skipped_files=67)
    with pytest.raises(guard.QaFailure) as denominator:
        guard.validate_secret_payload(
            child,
            false_pass,
            step="secret_scan",
            source_manifest=source_manifest,
        )
    assert denominator.value.code == "SECRET_DENOMINATOR_INVALID"


def test_run_reports_temporarily_missing_security_matrix_without_creating_work(
    source: Path,
) -> None:
    required_scripts = {
        item.script for item in guard.VALIDATOR_SPECS if item.identifier != "security_matrix"
    }
    required_scripts.update({"generate_host_adapters.py", "adapter_parity_check.py"})
    for name in required_scripts:
        (source / "scripts" / name).write_text(
            "# fixture\n", encoding="utf-8", newline="\n"
        )
    work = source.parent / "work"
    expected = guard.snapshot_tree(source)
    payload, exit_code = guard.run_command(
        source,
        work,
        timeout_seconds=30,
        lease_seconds=60,
        expect_files=expected.files,
        expect_tree=expected.tree_sha256,
        seal_out=None,
    )
    assert exit_code == 2
    assert payload["status"] == "error"
    assert payload["errors"][0]["code"] == "COMPONENTS_MISSING"
    assert payload["errors"][0]["detail"]["components"] == ["security_matrix"]
    assert not work.exists()
    assert not guard.lease_path_for(source).exists()


def test_cli_error_is_json_and_uses_exit_two() -> None:
    completed = _cli("run", "missing")
    assert completed.returncode == 2
    assert completed.stderr == ""
    payload = json.loads(completed.stdout)
    assert payload["status"] == "error"
    assert payload["errors"][0]["code"] == "CLI_INVALID"


def test_run_success_cleans_owned_work_and_creates_external_seal(
    source: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _materialize_required_components(source)
    monkeypatch.setattr(
        guard,
        "_run_validator_profile",
        lambda cold, **_kwargs: _stubbed_evidence(cold),
    )
    monkeypatch.setattr(
        guard,
        "_run_public_source_gate",
        lambda *_args, **_kwargs: {"files": guard.snapshot_tree(source).files},
    )
    monkeypatch.setattr(
        guard,
        "_run_pytest",
        lambda *_args, **_kwargs: {
            "collected": 1,
            "passed": 1,
            "failed": 0,
            "errors": 0,
            "skipped": 0,
            "node_ids_sha256": "D" * 64,
        },
    )
    monkeypatch.setattr(
        guard,
        "_run_adapters",
        lambda *_args, **_kwargs: (
            {
                "bundles": "2/2",
                "parity": "2/2",
                "manifest_deterministic": True,
                "payload_readbacks": "6/6",
            },
            [
                {"bundle": bundle, "host": host, "status": "pass"}
                for bundle in (1, 2)
                for host in guard.REQUIRED_HOST_IDS
            ],
        ),
    )
    expected = guard.snapshot_tree(source)
    work = source.parent / "qa-work"
    seal = source.parent / "qa-seal.json"
    original_write_seal = guard.write_seal_once
    seal_preconditions: dict[str, bool] = {}

    def checked_write_seal(path: Path, value: dict) -> None:
        seal_preconditions["lease_absent"] = not guard.lease_path_for(source).exists()
        seal_preconditions["work_absent"] = not work.exists()
        original_write_seal(path, value)

    monkeypatch.setattr(guard, "write_seal_once", checked_write_seal)
    payload, exit_code = guard.run_command(
        source,
        work,
        timeout_seconds=30,
        lease_seconds=60,
        expect_files=expected.files,
        expect_tree=expected.tree_sha256,
        seal_out=seal,
    )
    assert exit_code == 0, payload
    assert payload["status"] == "pass"
    assert payload["work"]["status"] == "owned_output_removed"
    assert payload["seal"]["status"] == "created"
    assert not work.exists()
    assert seal.is_file()
    assert json.loads(seal.read_text(encoding="utf-8"))["status"] == "pass"
    assert seal_preconditions == {"lease_absent": True, "work_absent": True}
    assert not guard.lease_path_for(source).exists()


def test_run_detects_source_drift_retains_work_and_does_not_seal(
    source: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _materialize_required_components(source)

    def validator_with_drift(cold: Path, **_kwargs):
        skill = source / "SKILL.md"
        original = skill.read_bytes()
        skill.write_bytes(bytes([original[0] ^ 1]) + original[1:])
        return _stubbed_evidence(cold)

    monkeypatch.setattr(guard, "_run_validator_profile", validator_with_drift)
    monkeypatch.setattr(
        guard,
        "_run_public_source_gate",
        lambda *_args, **_kwargs: {"files": guard.snapshot_tree(source).files},
    )
    monkeypatch.setattr(
        guard,
        "_run_pytest",
        lambda *_args, **_kwargs: {
            "collected": 1,
            "passed": 1,
            "failed": 0,
            "errors": 0,
            "skipped": 0,
            "node_ids_sha256": "D" * 64,
        },
    )
    monkeypatch.setattr(
        guard,
        "_run_adapters",
        lambda *_args, **_kwargs: (
            {"bundles": "2/2", "parity": "2/2", "payload_readbacks": "6/6"},
            [],
        ),
    )
    work = source.parent / "drift-work"
    seal = source.parent / "drift-seal.json"
    expected = guard.snapshot_tree(source)
    payload, exit_code = guard.run_command(
        source,
        work,
        timeout_seconds=30,
        lease_seconds=60,
        expect_files=expected.files,
        expect_tree=expected.tree_sha256,
        seal_out=seal,
    )
    assert exit_code == 1
    assert payload["status"] == "fail"
    assert any(item["code"] == "SOURCE_DRIFT" for item in payload["errors"])
    assert payload["work"]["status"] == "retained"
    assert work.is_dir()
    assert not seal.exists()
    assert not guard.lease_path_for(source).exists()
    shutil.rmtree(work)


def test_source_manifest_schema_recompute_and_contract_denominator(
    source: Path,
) -> None:
    assert guard.parse_json_bytes(b'{"value": 1}\r\n', step="json-test") == {
        "value": 1
    }
    with pytest.raises(guard.RunnerError):
        guard.parse_json_bytes(b'{"value": 1}\r', step="json-test")
    child = guard.ChildResult(0, b"", b"")
    records = (
        ("SKILL.md", 4, "A" * 64),
        ("scripts/tool.py", 9, "B" * 64),
    )
    payload = _source_payload(source, records)
    evidence = guard.validate_source_payload(
        child,
        payload,
        step="source_manifest",
        expected_root=source,
    )
    assert evidence["_records"] == records
    assert guard.public_source_evidence(evidence) == {
        "manifest_algorithm": guard.SOURCE_MANIFEST_ALGORITHM,
        "files": 2,
        "manifest_sha256": _manifest_hash(records),
    }

    missing_status = dict(payload)
    missing_status.pop("status")
    with pytest.raises(guard.QaFailure):
        guard.validate_source_payload(
            child, missing_status, step="source_manifest", expected_root=source
        )
    wrong_tree = dict(payload, tree_sha256="C" * 64)
    with pytest.raises(guard.QaFailure) as recompute:
        guard.validate_source_payload(
            child, wrong_tree, step="source_manifest", expected_root=source
        )
    assert recompute.value.code == "SOURCE_TREE_RECOMPUTE_MISMATCH"

    contract = {"status": "pass", "errors": [], "checks": {"artifacts": "9/9"}}
    assert guard.validate_contract_payload(
        child, contract, step="contract_bundle"
    ) == {"artifacts": "9/9"}
    with pytest.raises(guard.QaFailure) as drift:
        guard.validate_contract_payload(
            child,
            {**contract, "checks": {"artifacts": "8/8"}},
            step="contract_bundle",
        )
    assert drift.value.code == "CONTRACT_DENOMINATOR_DRIFT"


def test_security_matrix_requires_exact_counts_digests_limits_and_live_platform(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child = guard.ChildResult(0, b"", b"")
    source_manifest = {"files": 70, "tree_sha256": "A" * 64}
    passing = _security_payload(source_manifest)
    evidence = guard.validate_security_payload(
        child,
        passing,
        step="security_matrix",
        source_manifest=source_manifest,
    )
    assert evidence["denominators"] == guard.SECURITY_DENOMINATORS
    assert evidence["digests"]["all_ordered"] == guard.SECURITY_ALL_CASE_IDS_SHA256

    wrong_denominator = copy.deepcopy(passing)
    wrong_denominator["denominators"]["total"] = "292/292"
    with pytest.raises(guard.QaFailure) as denominator:
        guard.validate_security_payload(
            child,
            wrong_denominator,
            step="security_matrix",
            source_manifest=source_manifest,
        )
    assert denominator.value.code == "SECURITY_DENOMINATOR_DRIFT"

    wrong_ids = copy.deepcopy(passing)
    wrong_ids["case_ids"]["generator"][0] = "GEN-REPLACED"
    with pytest.raises(guard.QaFailure) as digest:
        guard.validate_security_payload(
            child,
            wrong_ids,
            step="security_matrix",
            source_manifest=source_manifest,
        )
    assert digest.value.code == "SECURITY_DIGEST_DRIFT"

    wrong_fuzz = copy.deepcopy(passing)
    wrong_fuzz["declared_limits"]["finite_fuzz_scope"]["corpus_sha256"] = "B" * 64
    with pytest.raises(guard.QaFailure) as fuzz:
        guard.validate_security_payload(
            child,
            wrong_fuzz,
            step="security_matrix",
            source_manifest=source_manifest,
        )
    assert fuzz.value.code == "SECURITY_EVIDENCE_MISSING"

    monkeypatch.setattr(guard.sys, "platform", "linux")
    linux = _security_payload(source_manifest)
    guard.validate_security_payload(
        child, linux, step="security_matrix", source_manifest=source_manifest
    )
    linux["platform_evidence"]["linux"] = "modeled_not_live_verified"
    with pytest.raises(guard.QaFailure):
        guard.validate_security_payload(
            child, linux, step="security_matrix", source_manifest=source_manifest
        )


def test_pytest_junit_requires_exact_collection_zero_skips_and_stable_digest() -> None:
    first = guard.validate_pytest_junit(
        _junit_bytes([("test_b", "passed"), ("test_a", "passed")]),
        returncode=0,
        expected_items=2,
    )
    second = guard.validate_pytest_junit(
        _junit_bytes([("test_a", "passed"), ("test_b", "passed")]),
        returncode=0,
        expected_items=2,
    )
    assert first == second
    assert first["collected"] == first["passed"] == 2
    assert guard.SHA256_RE.fullmatch(first["node_ids_sha256"])

    with pytest.raises(guard.QaFailure) as drift:
        guard.validate_pytest_junit(
            _junit_bytes([("test_a", "passed"), ("test_b", "passed")]),
            returncode=0,
            expected_items=3,
        )
    assert drift.value.code == "PYTEST_DENOMINATOR_DRIFT"
    with pytest.raises(guard.QaFailure) as skipped:
        guard.validate_pytest_junit(
            _junit_bytes([("test_a", "passed"), ("test_b", "skipped")]),
            returncode=0,
            expected_items=2,
        )
    assert skipped.value.code == "PYTEST_FAILED"


def test_path_spelling_matches_common_portability_policy() -> None:
    unsafe = (
        "e\u0301/file.py",
        "folder/COM1.txt",
        "folder/trailing. ",
        "folder/name?.py",
        "folder/control\x01.py",
        "folder/format\u200d.py",
        "folder/confusable\u2215name.py",
        "C:/absolute.py",
    )
    for value in unsafe:
        with pytest.raises(guard.QaFailure):
            guard._canonical_relative_posix_path(value, step="path-test")
    assert (
        guard._canonical_relative_posix_path(
            ".codex/skills/valid-name/SKILL.md", step="path-test"
        )
        == ".codex/skills/valid-name/SKILL.md"
    )


def test_adapter_manifest_schema_paths_and_payload_identities_are_exact(
    tmp_path: Path,
) -> None:
    cold = tmp_path / "multi-agent-system-architect-v2"
    (cold / "scripts").mkdir(parents=True)
    (cold / "SKILL.md").write_bytes(b"skill\n")
    (cold / "scripts" / "tool.py").write_bytes(b"print('ok')\n")
    cold_snapshot = guard.snapshot_tree(cold)
    target = tmp_path / "payload"
    shutil.copytree(cold, target, copy_function=shutil.copyfile)
    guard._assert_independent_payload(cold, target, cold_snapshot)

    linked = target / "SKILL.md"
    linked.unlink()
    os.link(cold / "SKILL.md", linked)
    with pytest.raises(guard.ReleaseQaError):
        guard._assert_independent_payload(cold, target, cold_snapshot)

    bundle = tmp_path / "bundle"
    bundle.mkdir()
    source_manifest = {"files": 2, "tree_sha256": "A" * 64}
    entries = [
        {
            "host": host,
            "relative_path": f"hosts/{host}",
            "files": 2,
            "tree_sha256": "A" * 64,
        }
        for host in guard.REQUIRED_HOST_IDS
    ]
    manifest = {
        "schema_version": "1.0",
        "canonical_name": cold.name,
        "canonical_version": guard.RUNNER_VERSION,
        "canonical_files": 2,
        "canonical_tree_sha256": "A" * 64,
        "entries": entries,
        "doctrine_forks": False,
    }
    manifest_path = bundle / "ADAPTER_MANIFEST.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    _, parsed = guard._manifest_entries(
        bundle,
        canonical_name=cold.name,
        canonical_version=guard.RUNNER_VERSION,
        source_manifest=source_manifest,
    )
    assert [entry["host"] for entry in parsed] == list(guard.REQUIRED_HOST_IDS)
    duplicate = copy.deepcopy(manifest)
    duplicate["entries"][1]["relative_path"] = duplicate["entries"][0][
        "relative_path"
    ]
    manifest_path.write_text(
        json.dumps(duplicate, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    with pytest.raises(guard.QaFailure) as collision:
        guard._manifest_entries(
            bundle,
            canonical_name=cold.name,
            canonical_version=guard.RUNNER_VERSION,
            source_manifest=source_manifest,
        )
    assert collision.value.code == "ADAPTER_PATH_DUPLICATE"


def test_expect_tree_is_physical_algorithm_not_source_manifest_hash(
    source: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _materialize_required_components(source)
    physical = guard.snapshot_tree(source)
    manifest_hash = _manifest_hash(physical.records)
    assert manifest_hash != physical.tree_sha256
    monkeypatch.setattr(
        guard,
        "_run_public_source_gate",
        lambda *_args, **_kwargs: {"files": physical.files},
    )
    work = source.parent / "algorithm-work"
    payload, exit_code = guard.run_command(
        source,
        work,
        timeout_seconds=30,
        lease_seconds=60,
        expect_files=physical.files,
        expect_tree=manifest_hash,
        seal_out=None,
    )
    assert exit_code == 1
    assert payload["expectation"]["algorithm"] == guard.PHYSICAL_TREE_ALGORITHM
    assert payload["errors"][0]["code"] == "EXPECT_TREE_MISMATCH"
    assert payload["errors"][0]["detail"]["algorithm"] == guard.PHYSICAL_TREE_ALGORITHM
    assert not work.exists()
    assert not guard.lease_path_for(source).exists()


def test_public_gate_mutation_cannot_become_expected_baseline(
    source: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _materialize_required_components(source)
    fixture_files, _ = guard._physical_inventory(source)
    monkeypatch.setattr(guard, "PUBLIC_ONLY_FILE_SET", frozenset(fixture_files))
    skill = source / "SKILL.md"
    original = skill.read_bytes()
    expected = guard.snapshot_tree(source)

    def mutating_gate(*_args, **_kwargs):
        data = skill.read_bytes()
        skill.write_bytes(bytes([data[0] ^ 1]) + data[1:])
        return {"files": expected.files}

    monkeypatch.setattr(guard, "_run_public_source_gate", mutating_gate)
    list_payload, list_exit_code = guard.list_command(source)
    assert list_exit_code == 1
    assert list_payload["errors"][0]["code"] == "SOURCE_DRIFT"

    skill.write_bytes(original)
    expected = guard.snapshot_tree(source)
    work = source.parent / "mutation-work"
    seal = source.parent / "mutation-seal.json"
    payload, exit_code = guard.run_command(
        source,
        work,
        timeout_seconds=30,
        lease_seconds=60,
        expect_files=expected.files,
        expect_tree=expected.tree_sha256,
        seal_out=seal,
    )
    assert exit_code == 1
    assert payload["errors"][0]["code"] == "EXPECT_TREE_MISMATCH"
    assert not work.exists()
    assert not seal.exists()
    assert not guard.lease_path_for(source).exists()


def test_seal_evidence_is_relocation_clean_and_has_no_runtime_paths(
    source: Path,
    tmp_path: Path,
) -> None:
    relocated = tmp_path / "elsewhere" / source.name
    relocated.parent.mkdir()
    shutil.copytree(source, relocated, copy_function=shutil.copyfile)
    left = guard.snapshot_tree(source)
    right = guard.snapshot_tree(relocated)
    assert left == right
    validators = {"source_manifest": {"files": left.files, "manifest_sha256": "A" * 64}}
    pytest_result = {
        "collected": 2,
        "passed": 2,
        "failed": 0,
        "errors": 0,
        "skipped": 0,
        "node_ids_sha256": "B" * 64,
    }
    adapters = {"bundles": "2/2", "payload_readbacks": "6/6"}
    first = guard._seal_payload(left, validators, pytest_result, adapters)
    second = guard._seal_payload(right, validators, pytest_result, adapters)
    assert first == second
    assert first["evidence_sha256"] == guard.canonical_json_hash(
        {
            "adapters": adapters,
            "pytest": pytest_result,
            "source_snapshot": left.public_payload(),
            "validators": validators,
        }
    )
    serialized = json.dumps(first, sort_keys=True)
    assert str(source.parent) not in serialized
    assert str(relocated.parent) not in serialized
