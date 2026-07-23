#!/usr/bin/env python3
"""Validate the V1 corpus or the public, oracle-free V2 eval profile."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from _common import ContractError, emit, read_utf8


EXPECTED_IDS = [f"EV{index:02d}" for index in range(1, 21)]
EXPECTED_CATEGORIES = {
    "triage_independence": 5,
    "autonomy_risk_recovery": 4,
    "knowledge_rag": 5,
    "selection_portability_verification": 6,
}
SCALAR_VALUES = {
    "status": {"done", "needs_review", "blocked"},
    "scope_decision": {
        "no-system",
        "deterministic-workflow",
        "single-agent",
        "multi-agent",
        "privileged-procedure",
    },
    "architecture_mode": {"A", "B", "C"},
    "autonomy_level": {f"AU{index}" for index in range(6)},
    "risk_class": {f"R{index}" for index in range(6)},
}

V2_FILES = {
    "inputs": "v2_behavioral_inputs.yaml",
    "faults": "v2_fault_injection.yaml",
    "vocabulary": "control_vocabulary.yaml",
}
V2_PROFILE_IDS = {
    "inputs": "MASA-V2-SEALED-BEHAVIORAL-INPUTS",
    "faults": "MASA-V2-PUBLIC-FAULT-AND-MUTATION-REGISTRY",
}
V2_STATUSES = {
    "inputs": "SEALED_BEHAVIORAL_FROZEN",
    "faults": "PUBLIC_WHITE_BOX_FROZEN",
}
V2_INPUT_ROOT_FIELDS = {
    "schema_version",
    "profile_id",
    "status",
    "evaluation_lane",
    "candidate_visibility",
    "oracle_visibility",
    "embedded_expected_outputs_allowed",
    "case_count",
    "runner_instruction",
    "cases",
}
V2_FAULT_ROOT_FIELDS = {
    "schema_version",
    "profile_id",
    "status",
    "evaluation_lane",
    "candidate_visibility",
    "oracle_visibility",
    "fault_counts",
    "fault_scenarios",
    "mutation_count",
    "public_white_box_mutation_pass_rule",
    "public_white_box_mutation_survivor_rule",
    "public_white_box_mutation_timeout_or_abort",
    "mutants",
}
V2_CASE_FIELDS = {
    "case_id",
    "evidence_level",
    "fixture_prompt",
}
V2_FAULT_FIELDS = {
    "scenario_id",
    "evidence_level",
    "exact_injection",
    "public_white_box_oracle_contract",
    "public_white_box_expected_owner",
    "public_white_box_expected_recovery",
    "public_white_box_expected_risk_class",
}
V2_MUTANT_FIELDS = {
    "deterministic_test_id",
    "public_white_box_kill_oracle",
    "public_white_box_required_lifecycle",
    "fault",
    "planned_test_locator",
    "injection_operator",
    "mutation_id",
    "target_locator",
}
V2_FAULT_COUNTS = {"E1": 15, "E2": 17, "E3": 15, "total": 47}
V2_HARD_SUFFIXES = ("route", "hard_gate", "evidence_recovery")
V2_MUTATION_LIFECYCLE = ["INJECTED", "EXECUTED", "KILLED"]
V2_OUTCOME_VOCABULARY = {
    "allowed": ["PASS", "FAIL", "TIMEOUT", "ABORTED", "INVALID"],
    "failure_rule": (
        "FAIL, TIMEOUT, ABORTED and INVALID are failures for every "
        "denominator and hard gate."
    ),
    "passing": ["PASS"],
    "retry_rule": (
        "A technical retry never replaces the original scored attempt. The "
        "original TIMEOUT or ABORTED attempt remains a failure and cost in "
        "its denominator. A retry uses a distinct attempt_id, remains linked "
        "to the same cell_id, and is diagnostic only unless F3_00 allocates "
        "a separate frozen cell."
    ),
}
V2_MUTATION_RULES = {
    "public_white_box_mutation_pass_rule": (
        "32/32 means every frozen mutant is injected, the affected "
        "deterministic test path is executed, and that test path kills the "
        "mutant. Merely proposing or generating a mutant is not a pass."
    ),
    "public_white_box_mutation_survivor_rule": (
        "Any surviving, unexecuted, invalid, timed-out or aborted mutant "
        "fails the non-compensatory gate."
    ),
    "public_white_box_mutation_timeout_or_abort": (
        "The affected mutant is NOT_KILLED and the 32/32 gate fails."
    ),
}
V2_EXPECTED_CASE_IDS = [f"F2-BHV-{index:03d}" for index in range(1, 37)]
V2_MUTATION_ID_RE = re.compile(r"MUT-(?:0[1-9]|[12][0-9]|3[0-2])")
V2_TEST_ID_RE = re.compile(r"V2-MUT-(?:0[1-9]|[12][0-9]|3[0-2])")


def configure_utf8_stdio() -> None:
    """Make the public text protocol UTF-8 even outside Python UTF-8 mode."""

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="strict")


def runtime_evidence() -> dict[str, str | bool]:
    """Return path-free runtime facts that are stable for this interpreter."""

    return {
        "interpreter": sys.implementation.name,
        "version": (
            f"{sys.version_info.major}.{sys.version_info.minor}."
            f"{sys.version_info.micro}"
        ),
        "text_encoding": "UTF-8",
        "stdio_encoding": (
            "UTF-8"
            if (getattr(sys.stdout, "encoding", "") or "")
            .replace("_", "-")
            .lower()
            in {"utf-8", "utf8"}
            else "NON-UTF-8"
        ),
        "utf8_mode": bool(sys.flags.utf8_mode),
        "bytecode_disabled": bool(sys.dont_write_bytecode),
        "invocation_mode": "python-script",
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path, help="Explicit skill root")
    parser.add_argument(
        "--profile",
        choices=("v1", "v2"),
        type=str.lower,
        default="v2",
        help="Validation profile; defaults to the installable public V2 contract",
    )
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def _load_unique_yaml(path: Path) -> Any:
    """Load public YAML while rejecting duplicate mapping keys."""
    try:
        import yaml
    except ImportError as exc:
        raise ContractError("PyYAML is required for V2 eval validation") from exc

    class UniqueKeyLoader(yaml.SafeLoader):
        pass

    def construct_mapping(
        loader: UniqueKeyLoader, node: Any, deep: bool = False
    ) -> dict[Any, Any]:
        loader.flatten_mapping(node)
        result: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in result:
                raise ContractError(f"duplicate YAML key in {path}: {key!r}")
            result[key] = loader.construct_object(value_node, deep=deep)
        return result

    UniqueKeyLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        construct_mapping,
    )
    try:
        return yaml.load(read_utf8(path), Loader=UniqueKeyLoader)
    except ContractError:
        raise
    except yaml.YAMLError as exc:
        raise ContractError(f"Invalid YAML in {path}: {exc}") from exc


def _unique_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ContractError(f"duplicate JSON key in eval corpus: {key}")
        value[key] = item
    return value


def _load_unique(path: Path) -> Any:
    """Load governed JSON/YAML criteria without last-key-wins ambiguity."""

    if path.suffix.lower() == ".json":
        try:
            return json.loads(
                read_utf8(path),
                object_pairs_hook=_unique_json_pairs,
            )
        except json.JSONDecodeError as exc:
            raise ContractError(f"Invalid JSON in {path}: {exc}") from exc
    return _load_unique_yaml(path)


def _normalized_key(value: str) -> str:
    value = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def forbidden_material_paths(value: Any, cursor: str = "$") -> list[str]:
    """Find answer/truth/hidden-output material without treating custody metadata as data."""
    hits: list[str] = []
    if isinstance(value, dict):
        for raw_key, item in value.items():
            key = _normalized_key(str(raw_key))
            collapsed = key.replace("_", "")
            allowed_metadata = key == "answer_key_visibility"
            forbidden = (
                (
                    not allowed_metadata
                    and (
                        collapsed.startswith("answerkey")
                        or collapsed in {"answer", "answers", "answermaterial"}
                    )
                )
                or "truthmap" in collapsed
                or collapsed == "truth"
                or collapsed.startswith("truth")
                or collapsed.startswith("groundtruth")
                or collapsed.startswith("hiddenexpected")
                or collapsed.startswith("hiddenanswer")
                or collapsed.startswith("hiddenoutput")
                or collapsed.startswith("hiddenmaterial")
                or collapsed in {
                    "expectedanswer",
                    "expectedoutput",
                    "expectedoutputs",
                    "expectedanswers",
                    "candidateoutputs",
                    "oraclepayload",
                    "score",
                    "scores",
                    "verdict",
                    "verdicts",
                }
            )
            child_cursor = f"{cursor}.{raw_key}"
            if forbidden:
                hits.append(child_cursor)
            hits.extend(forbidden_material_paths(item, child_cursor))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            hits.extend(forbidden_material_paths(item, f"{cursor}[{index}]"))
    return hits


def _nonempty_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _unique_text(values: Any) -> bool:
    return (
        isinstance(values, list)
        and all(_nonempty_text(item) for item in values)
        and len(values) == len(set(values))
    )


def _exact_fields(
    value: dict[str, Any], expected: set[str], label: str, errors: list[str]
) -> None:
    """Require one exact public mapping shape, not an extensible answer carrier."""

    actual = set(value)
    if actual != expected:
        errors.append(
            f"{label}: fields mismatch: "
            f"missing={sorted(expected - actual)} extra={sorted(actual - expected)}"
        )


def _validate_public_outcome_contract(
    vocabulary: dict[str, Any], errors: list[str]
) -> None:
    """Keep every non-PASS terminal outcome in the public failure denominator."""

    v2 = vocabulary.get("v2")
    if not isinstance(v2, dict):
        errors.append("V2 vocabulary mapping is required")
        return
    allowed = ["PASS", "FAIL", "TIMEOUT", "ABORTED", "INVALID"]
    failures = ["FAIL", "TIMEOUT", "ABORTED", "INVALID"]
    if (
        v2.get("outcomes") != allowed
        or v2.get("passing_outcomes") != ["PASS"]
        or v2.get("failure_outcomes") != failures
    ):
        errors.append(
            "TIMEOUT_ABORT_OUTCOME_REJECTED: V2 outcome denominator/failure "
            "rules drifted"
        )


def _validate_public_locator(
    root: Path, locator: Any, label: str, errors: list[str]
) -> None:
    """Require a relative locator whose public file exists inside the package."""

    if not _nonempty_text(locator):
        errors.append(f"{label}: nonempty public locator required")
        return
    raw = str(locator).replace("\\", "/")
    file_part = raw.split("#", 1)[0].split("::", 1)[0]
    parts = Path(file_part).parts
    if (
        not file_part
        or file_part.startswith("/")
        or ":" in file_part
        or ".." in parts
    ):
        errors.append(f"{label}: unsafe public locator {locator!r}")
        return
    if not (root / Path(file_part)).is_file():
        errors.append(f"{label}: public locator target is absent: {file_part}")


def validate_v2_public_profile(
    root: Path,
) -> tuple[dict[str, Any], int, list[str]]:
    """Validate the installable V2 profile without loading any sealed oracle."""

    root = root.resolve()
    eval_root = root / "evals"
    errors: list[str] = []
    checks = 0

    protected = (
        eval_root / "behavioral_rubric.yaml",
        eval_root / "v2_behavioral_rubric.yaml",
        root / "scripts" / "score_behavioral_outputs.py",
    )
    present = [path.relative_to(root).as_posix() for path in protected if path.exists()]
    if present:
        errors.append(f"protected eval material must be absent: {present}")
    checks += len(protected)

    docs: dict[str, dict[str, Any]] = {}
    for role, name in V2_FILES.items():
        value = _load_unique_yaml(eval_root / name)
        if not isinstance(value, dict):
            raise ContractError(f"{name} must contain a mapping")
        docs[role] = value
        forbidden = forbidden_material_paths(value)
        if forbidden:
            errors.append(f"{name}: forbidden answer/truth material keys: {forbidden}")
        checks += 1

    schema = _load_unique(eval_root / "behavioral_output.schema.json")
    if not isinstance(schema, dict):
        raise ContractError("behavioral_output.schema.json must contain an object")
    try:
        import jsonschema
    except ImportError as exc:
        raise ContractError("jsonschema is required for eval validation") from exc
    jsonschema.Draft202012Validator.check_schema(schema)
    checks += 1

    inputs = docs["inputs"]
    faults = docs["faults"]
    vocabulary = docs["vocabulary"]
    expected_case_count = len(V2_EXPECTED_CASE_IDS)
    _exact_fields(inputs, V2_INPUT_ROOT_FIELDS, "V2 inputs", errors)
    _exact_fields(faults, V2_FAULT_ROOT_FIELDS, "V2 faults", errors)
    checks += 2

    for role in ("inputs", "faults"):
        value = docs[role]
        if value.get("schema_version") != "2.0":
            errors.append(f"{role}: schema_version must be 2.0")
        if value.get("profile_id") != V2_PROFILE_IDS[role]:
            errors.append(f"{role}: profile_id mismatch")
        if value.get("status") != V2_STATUSES[role]:
            errors.append(f"{role}: public status mismatch")
        checks += 3

    if (
        inputs.get("evaluation_lane") != "SEALED_BEHAVIORAL"
        or inputs.get("candidate_visibility") != "CANDIDATE_VISIBLE"
        or inputs.get("oracle_visibility") != "VERIFIER_SEALED_NOT_PRESENT"
        or inputs.get("embedded_expected_outputs_allowed") is not False
        or inputs.get("case_count") != expected_case_count
        or not _nonempty_text(inputs.get("runner_instruction"))
    ):
        errors.append("V2 input root contract drifted")
    checks += 6

    input_cases = inputs.get("cases")
    if not isinstance(input_cases, list):
        errors.append("V2 inputs cases must be a list")
        input_cases = []
    input_ids: list[str] = []
    prompts: list[str] = []
    for index, case in enumerate(input_cases):
        if not isinstance(case, dict):
            errors.append(f"V2 input case {index}: object required")
            continue
        case_id = case.get("case_id")
        _exact_fields(case, V2_CASE_FIELDS, str(case_id or index), errors)
        if isinstance(case_id, str):
            input_ids.append(case_id)
        evidence = case.get("evidence_level")
        if evidence != {
            "input": "source_verified_synthetic_fixture",
            "required_output": "tool_verified_after_deterministic_replay",
        }:
            errors.append(f"{case_id or index}: evidence_level mismatch")
        prompt = case.get("fixture_prompt")
        if not _nonempty_text(prompt):
            errors.append(f"{case_id or index}: fixture_prompt required")
        else:
            prompts.append(str(prompt))
            if re.search(
                r"\b(?:PASS|FAIL|TIMEOUT|ABORTED|INVALID|AU[0-5]|R[0-5]|Mode [ABC])\b",
                str(prompt),
                re.IGNORECASE,
            ):
                errors.append(f"{case_id or index}: answer-bearing prompt label")
        checks += 1
    if input_ids != V2_EXPECTED_CASE_IDS:
        errors.append("V2 expected_case_ids denominator/order drifted")
    if len(prompts) != expected_case_count or len(set(prompts)) != expected_case_count:
        errors.append(
            f"V2 fixture prompts must be {expected_case_count} unique values"
        )
    hard_ids = [
        f"{case_id}:{suffix}"
        for case_id in V2_EXPECTED_CASE_IDS
        for suffix in V2_HARD_SUFFIXES
    ]
    expected_hard_count = expected_case_count * len(V2_HARD_SUFFIXES)
    if len(hard_ids) != expected_hard_count or len(set(hard_ids)) != expected_hard_count:
        errors.append(
            "V2 derived hard-decision denominator must be "
            f"{expected_hard_count}"
        )
    checks += 3

    if (
        faults.get("evaluation_lane") != "PUBLIC_WHITE_BOX"
        or faults.get("candidate_visibility")
        != "EXCLUDED_FROM_SEALED_BEHAVIORAL"
        or faults.get("oracle_visibility") != "PUBLIC_WHITE_BOX"
        or faults.get("fault_counts") != V2_FAULT_COUNTS
    ):
        errors.append("V2 public-white-box root contract drifted")
    checks += 4

    fault_groups = faults.get("fault_scenarios")
    if not isinstance(fault_groups, dict) or set(fault_groups) != {"E1", "E2", "E3"}:
        errors.append("V2 fault_scenarios must contain exactly E1/E2/E3")
        fault_groups = {}
    fault_ids: list[str] = []
    for lane in ("E1", "E2", "E3"):
        scenarios = fault_groups.get(lane, [])
        if not isinstance(scenarios, list) or len(scenarios) != V2_FAULT_COUNTS[lane]:
            errors.append(f"{lane}: expected {V2_FAULT_COUNTS[lane]} fault scenarios")
            scenarios = []
        for index, scenario in enumerate(scenarios):
            if not isinstance(scenario, dict):
                errors.append(f"{lane}[{index}]: object required")
                continue
            scenario_id = scenario.get("scenario_id")
            _exact_fields(scenario, V2_FAULT_FIELDS, str(scenario_id or index), errors)
            if not isinstance(scenario_id, str) or not scenario_id.startswith(f"F2-{lane}-"):
                errors.append(f"{lane}[{index}]: invalid scenario_id")
            else:
                fault_ids.append(scenario_id)
            if scenario.get("evidence_level") != {
                "before_execution": "source_verified_synthetic_fixture",
                "required_after_execution": "tool_verified",
            }:
                errors.append(f"{scenario_id or index}: evidence_level mismatch")
            if scenario.get("public_white_box_expected_risk_class") not in {
                f"R{item}" for item in range(6)
            }:
                errors.append(f"{scenario_id or index}: invalid public risk class")
            for field in (
                "exact_injection",
                "public_white_box_oracle_contract",
                "public_white_box_expected_owner",
                "public_white_box_expected_recovery",
            ):
                if not _nonempty_text(scenario.get(field)):
                    errors.append(f"{scenario_id or index}: {field} required")
            checks += 1
    if len(fault_ids) != 47 or len(set(fault_ids)) != 47:
        errors.append("V2 requires 47 globally unique fault scenario IDs")
    checks += 1

    if faults.get("mutation_count") != 32:
        errors.append("V2 mutation_count must be 32")
    for field, expected in V2_MUTATION_RULES.items():
        if faults.get(field) != expected:
            errors.append(f"V2 {field} drifted")
    mutants = faults.get("mutants")
    if not isinstance(mutants, list):
        errors.append("V2 mutants must be a list")
        mutants = []
    mutation_ids: list[str] = []
    test_ids: list[str] = []
    fault_names: list[str] = []
    for index, mutant in enumerate(mutants):
        if not isinstance(mutant, dict):
            errors.append(f"mutant {index}: object required")
            continue
        mutation_id = mutant.get("mutation_id")
        test_id = mutant.get("deterministic_test_id")
        _exact_fields(mutant, V2_MUTANT_FIELDS, str(mutation_id or index), errors)
        if isinstance(mutation_id, str):
            mutation_ids.append(mutation_id)
        if isinstance(test_id, str):
            test_ids.append(test_id)
        fault_name = mutant.get("fault")
        if _nonempty_text(fault_name):
            fault_names.append(str(fault_name))
        if mutant.get("public_white_box_required_lifecycle") != V2_MUTATION_LIFECYCLE:
            errors.append(f"{mutation_id or index}: public mutation lifecycle drifted")
        if not _nonempty_text(mutant.get("public_white_box_kill_oracle")):
            errors.append(f"{mutation_id or index}: public kill oracle required")
        _validate_public_locator(
            root,
            mutant.get("target_locator"),
            f"{mutation_id or index}.target_locator",
            errors,
        )
        _validate_public_locator(
            root,
            mutant.get("planned_test_locator"),
            f"{mutation_id or index}.planned_test_locator",
            errors,
        )
        if not _nonempty_text(mutant.get("injection_operator")):
            errors.append(f"{mutation_id or index}: injection_operator required")
        checks += 1
    expected_mutations = [f"MUT-{index:02d}" for index in range(1, 33)]
    expected_tests = [f"V2-MUT-{index:02d}" for index in range(1, 33)]
    if mutation_ids != expected_mutations:
        errors.append("V2 mutation IDs/denominator/order drifted")
    if test_ids != expected_tests:
        errors.append("V2 deterministic test IDs/denominator/order drifted")
    if len(fault_names) != 32 or len(set(fault_names)) != 32:
        errors.append("V2 mutant fault names must be 32 unique values")
    checks += 6

    v2_vocab = vocabulary.get("v2")
    if not isinstance(v2_vocab, dict):
        errors.append("V2 vocabulary mapping is required")
        v2_vocab = {}
    expected_vocab = {
        "evaluation_lanes": ["SEALED_BEHAVIORAL", "PUBLIC_WHITE_BOX", "VERIFIER_SEALED"],
        "candidate_visibility": ["CANDIDATE_VISIBLE", "EXCLUDED_FROM_SEALED_BEHAVIORAL"],
        "candidate_states": ["CANDIDATE_UNSCORED"],
        "scoring_states": ["BLOCKED_UNTIL_CANDIDATE_FREEZE_AND_REVEAL"],
        "oracle_visibility": ["VERIFIER_SEALED", "VERIFIER_SEALED_NOT_PRESENT", "PUBLIC_WHITE_BOX"],
        "hard_decision_keys": list(V2_HARD_SUFFIXES),
        "evidence_levels": ["observed", "source_verified", "tool_verified", "live_verified", "human_baptized"],
        "fixture_evidence_levels": ["source_verified_synthetic_fixture", "tool_verified_after_deterministic_replay", "tool_verified"],
        "effect_classifications": ["NO_EFFECT", "EFFECT_CONFIRMED", "STATE_UNCERTAIN", "NOT_APPLICABLE"],
        "fault_lanes": ["E1", "E2", "E3"],
        "mutation_lifecycle": V2_MUTATION_LIFECYCLE,
    }
    for field, expected in expected_vocab.items():
        if v2_vocab.get(field) != expected:
            errors.append(f"V2 vocabulary drift: {field}")
        checks += 1
    expected_classification = {
        "scope_decision": [
            "no-system",
            "deterministic-workflow",
            "single-agent",
            "multi-agent",
            "privileged-procedure",
        ],
        "architecture_mode": ["A", "B", "C"],
        "autonomy_level": [f"AU{item}" for item in range(6)],
        "risk_class": [f"R{item}" for item in range(6)],
    }
    if v2_vocab.get("classification") != expected_classification:
        errors.append("V2 classification vocabulary drifted")
    _validate_public_outcome_contract(vocabulary, errors)
    checks += 2

    one_of = schema.get("oneOf")
    definitions = schema.get("$defs")
    if one_of != [
        {"$ref": "#/$defs/v1BehavioralOutput"},
        {"$ref": "#/$defs/v2BehavioralOutput"},
    ] or not isinstance(definitions, dict) or not {
        "v1BehavioralOutput",
        "v2BehavioralOutput",
    }.issubset(definitions):
        errors.append("behavioral output schema dispatcher drifted")
    checks += 1

    return (
        {
            "inputs": inputs,
            "faults": faults,
            "vocabulary": vocabulary,
            "case_ids": input_ids,
            "hard_check_ids": hard_ids,
            "fault_ids": fault_ids,
            "mutation_ids": mutation_ids,
        },
        checks,
        errors,
    )


def validate_v1(root: Path) -> tuple[dict[str, Any], int, list[str]]:
    """Validate the public V1 input/schema surface without loading a rubric."""

    errors: list[str] = []
    checks = 0
    eval_root = root.resolve() / "evals"
    inputs = _load_unique(eval_root / "behavioral_inputs.yaml")
    vocabulary = _load_unique(eval_root / "control_vocabulary.yaml")
    schema = _load_unique(eval_root / "behavioral_output.schema.json")
    if not isinstance(inputs, dict) or not isinstance(vocabulary, dict):
        raise ContractError("V1 public inputs and vocabulary must be mappings")
    if not isinstance(schema, dict):
        raise ContractError("behavioral output schema must be an object")
    try:
        import jsonschema
    except ImportError as exc:
        raise ContractError("jsonschema is required for eval validation") from exc
    jsonschema.Draft202012Validator.check_schema(schema)
    checks += 1

    material = forbidden_material_paths(inputs)
    if material:
        errors.append(f"V1 inputs contain forbidden answer/truth material: {material}")
    cases = inputs.get("cases")
    if not isinstance(cases, list):
        errors.append("V1 cases must be a list")
        cases = []
    ids = [item.get("id") if isinstance(item, dict) else None for item in cases]
    if ids != EXPECTED_IDS:
        errors.append(f"V1 public input IDs/order mismatch: {ids}")
    categories = Counter(
        item.get("category") for item in cases if isinstance(item, dict)
    )
    if dict(categories) != EXPECTED_CATEGORIES:
        errors.append(f"V1 category coverage mismatch: {dict(categories)}")
    prompts = [
        item.get("prompt") for item in cases if isinstance(item, dict)
    ]
    if not _unique_text(prompts) or len(prompts) != 20:
        errors.append("V1 requires 20 unique nonempty public prompts")
    leaked = []
    for item in cases:
        if not isinstance(item, dict):
            continue
        prompt = str(item.get("prompt", ""))
        if re.search(r"\b(?:Mode [ABC]|AU[0-5]|R[0-5])\b", prompt):
            leaked.append(item.get("id"))
    if leaked:
        errors.append(f"V1 answer-bearing prompt labels: {leaked}")
    checks += 5

    m7_ids = {"EV01", "EV03", "EV04", "EV05"}
    domains = {
        item.get("domain")
        for item in cases
        if isinstance(item, dict) and item.get("id") in m7_ids
    }
    if len(domains) != 4 or None in domains:
        errors.append("V1 M7 anchors must cover four independent domains")
    checks += 1

    for field in ("controls", "blocked_actions", "artifacts"):
        values = vocabulary.get(field)
        if not _unique_text(values):
            errors.append(f"V1 public vocabulary invalid: {field}")
        checks += 1
    definitions = schema.get("$defs")
    if not isinstance(definitions, dict) or "v1BehavioralOutput" not in definitions:
        errors.append("V1 public schema branch is absent")
    checks += 1
    return {"cases": 20, "m7_anchors": 4}, checks, errors


def main() -> int:
    configure_utf8_stdio()
    args = parse_args()
    root = args.root.resolve()
    errors: list[str] = []
    checks = 0
    summary: dict[str, Any] = {}
    try:
        if args.profile == "v2":
            profile, checks, errors = validate_v2_public_profile(root)
            summary = {
                "profile": "v2-public-oracle-free",
                "cases": len(profile["case_ids"]) if not errors else 0,
                "hard_check_ids": len(profile["hard_check_ids"]) if not errors else 0,
                "fault_scenarios": len(profile["fault_ids"]) if not errors else 0,
                "fault_counts": V2_FAULT_COUNTS if not errors else {},
                "mutants": len(profile["mutation_ids"]) if not errors else 0,
                "required_lifecycle": V2_MUTATION_LIFECYCLE,
                "semantic_scoring": "not_performed",
                "oracle_material": "not_loaded",
            }
        else:
            summary, checks, errors = validate_v1(root)
    except (OSError, TypeError, ValueError, ContractError) as exc:
        errors.append(str(exc))

    payload = {
        "status": "pass" if not errors else "fail",
        **summary,
        "checks": checks,
        "errors": errors,
        "runtime_evidence": runtime_evidence(),
    }
    if args.profile == "v1":
        payload["cases"] = 20 if not errors else 0
        payload["m7_anchors"] = 4 if not errors else 0
    emit(payload, args.json)
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
