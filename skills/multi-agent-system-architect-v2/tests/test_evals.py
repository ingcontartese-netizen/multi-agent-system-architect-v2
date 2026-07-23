from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
EVALS = ROOT / "evals"
PUBLIC_V2_FILES = (
    "v2_behavioral_inputs.yaml",
    "v2_fault_injection.yaml",
    "control_vocabulary.yaml",
)
EXPECTED_CASE_IDS = [f"F2-BHV-{index:03d}" for index in range(1, 37)]
EXPECTED_HARD_KEYS = ["route", "hard_gate", "evidence_recovery"]
EXPECTED_MUTATION_IDS = [f"MUT-{index:02d}" for index in range(1, 33)]
EXPECTED_FAULT_COUNTS = {"E1": 15, "E2": 17, "E3": 15, "total": 47}
FORBIDDEN_V2_KEYS = {
    "answer_key",
    "expected",
    "expected_answer",
    "expected_output",
    "hidden_expected_answer",
    "hidden_expected_output",
    "hidden_expected_outputs",
    "outcome",
    "score",
    "truth_map",
    "verdict",
}


def run_script(name: str, *args: object) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [sys.executable, "-B", str(SCRIPTS / name), *(str(arg) for arg in args)],
        text=True,
        encoding="utf-8",
        errors="strict",
        capture_output=True,
        env=env,
        timeout=30,
    )


def assert_runtime_evidence(payload: dict) -> None:
    assert payload["runtime_evidence"] == {
        "interpreter": sys.implementation.name,
        "version": (
            f"{sys.version_info.major}.{sys.version_info.minor}."
            f"{sys.version_info.micro}"
        ),
        "text_encoding": "UTF-8",
        "stdio_encoding": "UTF-8",
        "utf8_mode": True,
        "bytecode_disabled": True,
        "invocation_mode": "python-script",
    }


def load_public_v2_registries() -> tuple[dict, dict, dict]:
    inputs = yaml.safe_load(
        (EVALS / "v2_behavioral_inputs.yaml").read_text(encoding="utf-8")
    )
    faults = yaml.safe_load(
        (EVALS / "v2_fault_injection.yaml").read_text(encoding="utf-8")
    )
    vocabulary = yaml.safe_load(
        (EVALS / "control_vocabulary.yaml").read_text(encoding="utf-8")
    )
    return inputs, faults, vocabulary


def reject_forbidden_v2_keys(value: object, path: str = "$") -> None:
    if isinstance(value, dict):
        overlap = FORBIDDEN_V2_KEYS.intersection(value)
        assert not overlap, f"forbidden V2 key at {path}: {sorted(overlap)}"
        for key, item in value.items():
            reject_forbidden_v2_keys(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_forbidden_v2_keys(item, f"{path}[{index}]")


def validate_public_v2_registries(
    inputs: dict,
    faults: dict,
    vocabulary: dict,
) -> None:
    assert inputs["schema_version"] == faults["schema_version"] == "2.0"
    assert inputs["profile_id"] == "MASA-V2-SEALED-BEHAVIORAL-INPUTS"
    assert inputs["status"] == "SEALED_BEHAVIORAL_FROZEN"
    assert inputs["evaluation_lane"] == "SEALED_BEHAVIORAL"
    assert inputs["candidate_visibility"] == "CANDIDATE_VISIBLE"
    assert inputs["oracle_visibility"] == "VERIFIER_SEALED_NOT_PRESENT"
    assert inputs["embedded_expected_outputs_allowed"] is False
    assert isinstance(inputs["runner_instruction"], str)
    assert inputs["runner_instruction"].strip()

    cases = inputs["cases"]
    case_ids = [item["case_id"] for item in cases]
    assert inputs["case_count"] == len(cases) == 36
    assert case_ids == EXPECTED_CASE_IDS
    assert len(set(case_ids)) == 36
    prompts = []
    for case in cases:
        assert set(case) == {"case_id", "evidence_level", "fixture_prompt"}
        assert case["evidence_level"] == {
            "input": "source_verified_synthetic_fixture",
            "required_output": "tool_verified_after_deterministic_replay",
        }
        assert isinstance(case["fixture_prompt"], str)
        assert case["fixture_prompt"].strip()
        prompts.append(case["fixture_prompt"])
    assert len(set(prompts)) == 36

    assert faults["profile_id"] == "MASA-V2-PUBLIC-FAULT-AND-MUTATION-REGISTRY"
    assert faults["status"] == "PUBLIC_WHITE_BOX_FROZEN"
    assert faults["evaluation_lane"] == "PUBLIC_WHITE_BOX"
    assert faults["candidate_visibility"] == "EXCLUDED_FROM_SEALED_BEHAVIORAL"
    assert faults["oracle_visibility"] == "PUBLIC_WHITE_BOX"
    assert faults["fault_counts"] == EXPECTED_FAULT_COUNTS
    assert set(faults["fault_scenarios"]) == {"E1", "E2", "E3"}
    fault_ids: list[str] = []
    expected_fault_fields = {
        "scenario_id",
        "evidence_level",
        "exact_injection",
        "public_white_box_oracle_contract",
        "public_white_box_expected_owner",
        "public_white_box_expected_recovery",
        "public_white_box_expected_risk_class",
    }
    for lane in ("E1", "E2", "E3"):
        scenarios = faults["fault_scenarios"][lane]
        assert len(scenarios) == EXPECTED_FAULT_COUNTS[lane]
        for scenario in scenarios:
            assert set(scenario) == expected_fault_fields
            assert scenario["scenario_id"].startswith(f"F2-{lane}-")
            assert scenario["evidence_level"] == {
                "before_execution": "source_verified_synthetic_fixture",
                "required_after_execution": "tool_verified",
            }
            assert scenario["public_white_box_expected_risk_class"] in {
                f"R{index}" for index in range(6)
            }
            for field in (
                "exact_injection",
                "public_white_box_oracle_contract",
                "public_white_box_expected_owner",
                "public_white_box_expected_recovery",
            ):
                assert isinstance(scenario[field], str)
                assert scenario[field].strip()
            fault_ids.append(scenario["scenario_id"])
    assert len(fault_ids) == len(set(fault_ids)) == 47

    mutants = faults["mutants"]
    mutation_ids = [item["mutation_id"] for item in mutants]
    test_ids = [item["deterministic_test_id"] for item in mutants]
    expected_mutant_fields = {
        "deterministic_test_id",
        "public_white_box_kill_oracle",
        "public_white_box_required_lifecycle",
        "fault",
        "planned_test_locator",
        "injection_operator",
        "mutation_id",
        "target_locator",
    }
    assert faults["mutation_count"] == len(mutants) == 32
    assert mutation_ids == EXPECTED_MUTATION_IDS
    assert len(set(mutation_ids)) == len(set(test_ids)) == 32
    for index, mutant in enumerate(mutants, start=1):
        assert set(mutant) == expected_mutant_fields
        assert mutant["deterministic_test_id"] == f"V2-MUT-{index:02d}"
        assert mutant["public_white_box_required_lifecycle"] == [
            "INJECTED",
            "EXECUTED",
            "KILLED",
        ]
        assert mutant["public_white_box_kill_oracle"].strip()

    v2 = vocabulary["v2"]
    assert v2["evaluation_lanes"] == [
        "SEALED_BEHAVIORAL",
        "PUBLIC_WHITE_BOX",
        "VERIFIER_SEALED",
    ]
    assert v2["hard_decision_keys"] == EXPECTED_HARD_KEYS
    assert v2["outcomes"] == ["PASS", "FAIL", "TIMEOUT", "ABORTED", "INVALID"]
    assert v2["passing_outcomes"] == ["PASS"]
    assert v2["failure_outcomes"] == ["FAIL", "TIMEOUT", "ABORTED", "INVALID"]
    assert v2["fault_lanes"] == ["E1", "E2", "E3"]
    assert v2["mutation_lifecycle"] == ["INJECTED", "EXECUTED", "KILLED"]
    reject_forbidden_v2_keys(inputs)
    reject_forbidden_v2_keys(faults)


def public_only_root(tmp_path: Path) -> Path:
    root = tmp_path / "public-subject"
    shutil.copytree(
        ROOT,
        root,
        ignore=shutil.ignore_patterns(".pytest_cache", "__pycache__", "*.pyc"),
    )
    assert all((root / "evals" / name).is_file() for name in PUBLIC_V2_FILES)
    assert not (root / "evals" / "behavioral_rubric.yaml").exists()
    assert not (root / "evals" / "v2_behavioral_rubric.yaml").exists()
    assert not (root / "scripts" / "score_behavioral_outputs.py").exists()
    return root


def run_v2(root: Path) -> tuple[subprocess.CompletedProcess[str], dict]:
    result = run_script("eval_corpus_check.py", root, "--profile", "v2", "--json")
    return result, json.loads(result.stdout)


def valid_v1_output() -> dict:
    return {
        "case_id": "EV01",
        "status": "done",
        "scope_decision": "no-system",
        "architecture_mode": "A",
        "autonomy_level": "AU0",
        "risk_class": "R0",
        "system_shape": "A bounded deterministic procedure is sufficient.",
        "controls": ["no_system_handoff"],
        "blocked_actions": ["multi_agent_default"],
        "artifacts": ["scope_decision"],
        "next_gate": "Independent review of the bounded decision.",
        "provenance": {
            "sources_read": ["SKILL.md"],
            "sections_consulted": ["Required Workflow"],
            "model_synthesis": "The smallest governed shape was selected.",
            "limits": ["Synthetic schema compatibility check only"],
        },
    }


def valid_v2_output() -> dict:
    return {
        "schema_version": "2.0",
        "case_id": "F2-BHV-001",
        "attempt_id": "ATTEMPT-0001",
        "candidate_state": "CANDIDATE_UNSCORED",
        "scoring_state": "BLOCKED_UNTIL_CANDIDATE_FREEZE_AND_REVEAL",
        "classification": {
            "scope_decision": "no-system",
            "architecture_mode": "A",
            "autonomy_level": "AU0",
            "risk_class": "R0",
        },
        "hard_decisions": {
            key: {
                "decision": f"Retain the {key} candidate decision.",
                "rationale": "The public fixture supports structural validation only.",
            }
            for key in EXPECTED_HARD_KEYS
        },
        "governed_artifact": {
            "artifact_type": "evaluation_decision",
            "artifact_id": "F2-BHV-001-CANDIDATE",
            "summary": "A blind candidate artifact awaiting independent verification.",
        },
        "owner": "candidate-evaluator",
        "evidence_level": {
            "input": "source_verified_synthetic_fixture",
            "claim": "observed",
        },
        "state_transition": {
            "from_state": "PUBLIC_FIXTURE_LOADED",
            "to_state": "CANDIDATE_UNSCORED",
            "effect_classification": "NO_EFFECT",
        },
        "recovery_decision": {
            "action": "Preserve evidence and require readback before any retry.",
            "retry_authorized": False,
            "evidence": ["public fixture", "candidate bytes"],
        },
        "approvals_required": ["independent reveal after candidate freeze"],
        "unknowns": ["sealed verifier material remains unavailable"],
        "external_effects_performed": False,
        "provenance": {
            "sources_read": ["SKILL.md", "evals/v2_behavioral_inputs.yaml"],
            "sections_consulted": ["Required Workflow", "F2-BHV-001"],
            "evidence_ids": ["F2-BHV-001"],
            "model_synthesis": "Candidate and verifier roles remain separated.",
            "limits": ["No answer key, truth map, or external action"],
        },
    }


def test_v2_public_checker_passes_with_only_three_public_subjects(
    tmp_path: Path,
) -> None:
    root = public_only_root(tmp_path)
    result, payload = run_v2(root)
    assert result.returncode == 0, result.stdout + result.stderr
    assert payload["status"] == "pass"
    assert payload["profile"] == "v2-public-oracle-free"
    assert payload["cases"] == 36
    assert payload["hard_check_ids"] == 108
    assert payload["fault_scenarios"] == 47
    assert payload["fault_counts"] == EXPECTED_FAULT_COUNTS
    assert payload["mutants"] == 32
    assert payload["required_lifecycle"] == ["INJECTED", "EXECUTED", "KILLED"]
    assert payload["semantic_scoring"] == "not_performed"
    assert payload["oracle_material"] == "not_loaded"
    assert payload["errors"] == []
    assert_runtime_evidence(payload)


def test_v2_public_registries_and_denominators_pass() -> None:
    validate_public_v2_registries(*load_public_v2_registries())


def test_v2_duplicate_identifiers_fail_closed(tmp_path: Path) -> None:
    root = public_only_root(tmp_path)
    path = root / "evals" / "v2_behavioral_inputs.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["cases"][1]["case_id"] = data["cases"][0]["case_id"]
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8", newline="\n")
    result, payload = run_v2(root)
    assert result.returncode == 1
    assert payload["status"] == "fail"
    assert any("case" in error.lower() for error in payload["errors"])


def test_v2_fault_and_mutation_duplicates_fail_closed(tmp_path: Path) -> None:
    root = public_only_root(tmp_path)
    path = root / "evals" / "v2_fault_injection.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["fault_scenarios"]["E1"][1]["scenario_id"] = data["fault_scenarios"]["E1"][0][
        "scenario_id"
    ]
    data["mutants"][1]["mutation_id"] = data["mutants"][0]["mutation_id"]
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8", newline="\n")
    result, payload = run_v2(root)
    assert result.returncode == 1
    assert payload["status"] == "fail"
    assert payload["errors"]


@pytest.mark.parametrize(
    ("file_name", "field", "value"),
    [
        ("v2_behavioral_inputs.yaml", "case_count", 35),
        ("v2_fault_injection.yaml", "mutation_count", 31),
    ],
)
def test_v2_denominator_drift_fails_closed(
    tmp_path: Path,
    file_name: str,
    field: str,
    value: object,
) -> None:
    root = public_only_root(tmp_path)
    path = root / "evals" / file_name
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data[field] = value
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8", newline="\n")
    result, payload = run_v2(root)
    assert result.returncode == 1
    assert payload["status"] == "fail"
    assert payload["errors"]


def test_v2_outcome_failure_rules_fail_closed(tmp_path: Path) -> None:
    root = public_only_root(tmp_path)
    path = root / "evals" / "control_vocabulary.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["v2"]["failure_outcomes"] = ["FAIL", "INVALID"]
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8", newline="\n")
    result, payload = run_v2(root)
    assert result.returncode == 1
    assert payload["status"] == "fail"
    assert any("outcome" in error.lower() for error in payload["errors"])


def test_v2_mut_29(tmp_path: Path) -> None:
    _, faults, _ = load_public_v2_registries()
    mutant = next(
        item for item in faults["mutants"] if item["mutation_id"] == "MUT-29"
    )
    assert mutant["deterministic_test_id"] == "V2-MUT-29"
    assert mutant["target_locator"] == (
        "evals/control_vocabulary.yaml#/v2/failure_outcomes"
    )
    assert mutant["planned_test_locator"] == "tests/test_evals.py::test_v2_mut_29"
    assert mutant["public_white_box_required_lifecycle"] == [
        "INJECTED",
        "EXECUTED",
        "KILLED",
    ]

    root = public_only_root(tmp_path)
    path = root / "evals" / "control_vocabulary.yaml"
    before = path.read_bytes()
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["v2"]["failure_outcomes"] = ["FAIL", "INVALID"]
    path.write_text(
        yaml.safe_dump(data, sort_keys=False),
        encoding="utf-8",
        newline="\n",
    )
    injected = path.read_bytes() != before
    result, payload = run_v2(root)
    executed = bool(result.stdout)
    killed = result.returncode == 1 and any(
        "TIMEOUT_ABORT_OUTCOME_REJECTED" in error
        or "outcome" in error.lower()
        for error in payload["errors"]
    )
    assert [
        state
        for state, reached in (
            ("INJECTED", injected),
            ("EXECUTED", executed),
            ("KILLED", killed),
        )
        if reached
    ] == ["INJECTED", "EXECUTED", "KILLED"]
    assert payload["status"] == "fail"


@pytest.mark.parametrize(
    "forbidden_key",
    ["answer_key", "expected_answer", "hidden_expected_outputs", "truth_map"],
)
def test_v2_forbidden_answer_material_fails_closed(
    tmp_path: Path,
    forbidden_key: str,
) -> None:
    root = public_only_root(tmp_path)
    path = root / "evals" / "v2_behavioral_inputs.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["cases"][0][forbidden_key] = "forbidden"
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8", newline="\n")
    result, payload = run_v2(root)
    assert result.returncode == 1
    assert payload["status"] == "fail"
    assert any("forbidden" in error.lower() for error in payload["errors"])


def test_v2_duplicate_yaml_keys_are_rejected(tmp_path: Path) -> None:
    root = public_only_root(tmp_path)
    path = root / "evals" / "v2_behavioral_inputs.yaml"
    path.write_text(
        path.read_text(encoding="utf-8") + "\ncase_count: 36\n",
        encoding="utf-8",
        newline="\n",
    )
    result, payload = run_v2(root)
    assert result.returncode == 1
    assert payload["status"] == "fail"
    assert any("duplicate yaml key" in error.lower() for error in payload["errors"])


def test_behavioral_output_schema_accepts_v1_and_v2_public_shapes() -> None:
    schema = json.loads((EVALS / "behavioral_output.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)
    validator.validate(valid_v1_output())
    validator.validate(valid_v2_output())


def test_behavioral_output_schema_rejects_unknown_and_forbidden_fields() -> None:
    schema = json.loads((EVALS / "behavioral_output.schema.json").read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)

    unknown_decision = valid_v2_output()
    unknown_decision["hard_decisions"]["oracle_guess"] = {
        "decision": "Guess",
        "rationale": "This must never be accepted by the public candidate schema.",
    }
    assert list(validator.iter_errors(unknown_decision))

    contaminated = valid_v2_output()
    contaminated["answer_key"] = "forbidden"
    assert list(validator.iter_errors(contaminated))


def test_behavioral_output_schema_rejects_external_effect_claim() -> None:
    schema = json.loads((EVALS / "behavioral_output.schema.json").read_text(encoding="utf-8"))
    output = valid_v2_output()
    output["external_effects_performed"] = True
    assert list(jsonschema.Draft202012Validator(schema).iter_errors(output))
