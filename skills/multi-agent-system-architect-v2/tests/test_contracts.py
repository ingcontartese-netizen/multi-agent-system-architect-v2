from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import jsonschema
import yaml


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "assets/schemas/contracts.schema.json").read_text(encoding="utf-8"))
INDEX = json.loads((ROOT / "assets/schemas/schema_index.json").read_text(encoding="utf-8"))


def validator(definition: str) -> jsonschema.Draft202012Validator:
    wrapper = {
        "$schema": SCHEMA["$schema"],
        "$ref": f"#/$defs/{definition}",
        "$defs": SCHEMA["$defs"],
    }
    return jsonschema.Draft202012Validator(
        wrapper, format_checker=jsonschema.FormatChecker()
    )


def load(relative: str):
    path = ROOT / relative
    if path.suffix == ".json":
        return json.loads(path.read_text(encoding="utf-8"))
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_schema_bundle_and_all_structured_templates_validate() -> None:
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    assert len(INDEX["artifacts"]) == 9
    for relative, pointer in INDEX["artifacts"].items():
        data = load(relative)
        pointer = INDEX.get("versioned_artifacts", {}).get(relative, {}).get(
            "dispatcher", pointer
        )
        definition = pointer.rsplit("/", 1)[-1]
        validator(definition).validate(data)


def test_ready_requirements_need_authority_success_and_baseline() -> None:
    data = load("templates/REQUIREMENTS.yaml")
    data["document_status"] = "ready"
    errors = list(validator("requirementsV2").iter_errors(data))
    assert errors
    data["requirement_id"] = "REQ-1"
    data["authority"]["owner"] = "product-owner"
    data["authority"]["human_sovereign"] = "decision-owner"
    data["goal"]["outcome"] = "Verified result"
    data["goal"]["beneficiary"] = "Operator"
    data["success_checks"] = [{"id": "S1", "check": "artifact exists"}]
    data["non_agentic_baseline"]["approach"] = "direct model"
    data["data"]["sensitivity"] = "internal"
    data["design_only"] = False
    validator("requirementsV2").validate(data)


def test_mode_c_requires_justification_and_separation_candidate() -> None:
    data = load("templates/TRIAGE_DECISION.yaml")
    data.update(
        {
            "document_status": "ready",
            "decision_id": "TRIAGE-1",
            "requirement_id": "REQ-1",
            "object_categories": ["agent-framework"],
            "alternatives": [{"id": "mode-b"}, {"id": "mode-c"}],
            "decision": "Mode C",
            "why": "Independent verifier boundary",
            "exit_strategy": "Collapse to Mode B",
        }
    )
    data["classification"] = {"mode": "C", "autonomy": "AU2", "risk": "R2"}
    data["multi_agent_justified"] = False
    assert list(validator("triageDecisionV2").iter_errors(data))
    data["multi_agent_justified"] = True
    data["separation_candidates"] = [{"role": "verifier", "boundary": "independence"}]
    validator("triageDecisionV2").validate(data)


def test_au5_ready_envelope_is_rejected_and_au4_needs_controls() -> None:
    data = load("templates/AUTONOMY_RISK_ENVELOPE.yaml")
    data["document_status"] = "ready"
    data["classification"] = {"mode": "C", "autonomy": "AU5", "risk": "R4"}
    assert list(validator("autonomyRiskEnvelopeV2").iter_errors(data))
    data["classification"]["autonomy"] = "AU4"
    data["envelope_id"] = "ENV-1"
    data["owner"] = "operations"
    data["stop_conditions"] = ["budget exceeded"]
    data["maximum_unattended_seconds"] = 3600
    data["kill_switch"] = {"owner": "ops", "mechanism": "cancel-run", "tested_at": "2026-07-12"}
    data["durable_state"] = {
        "store": "database",
        "checkpoint_policy": "each transition",
        "heartbeat_seconds": 30,
        "lease_seconds": 90,
    }
    validator("autonomyRiskEnvelopeV2").validate(data)


def test_commit_tool_requires_approval() -> None:
    data = load("templates/TOOL_CONTRACT.yaml")
    data.update(
        {
            "document_status": "ready",
            "tool_id": "commit-record",
            "version": "1.0",
            "owner": "ops",
            "purpose": "Commit one approved record",
            "read_or_write": "commit_write",
            "errors": [
                {
                    "code": "CONFLICT",
                    "phase": "commit",
                    "observable_cause": "target changed after preview",
                    "retryable": False,
                    "effect_may_have_occurred": False,
                    "safe_state": "no_effect",
                    "owner": "ops",
                    "next_action": "request a fresh preview",
                    "evidence_locator": "audit/commit-record",
                }
            ],
            "allowed_targets": ["staging-table"],
            "input_schema": {"type": "object"},
            "output_schema": {"type": "object"},
        }
    )
    data["classification"]["risk"] = "R4"
    data["approval_policy"]["required"] = False
    assert list(validator("toolContractV2").iter_errors(data))
    data["approval_policy"]["required"] = True
    validator("toolContractV2").validate(data)


def test_markdown_templates_have_required_mechanism_headings() -> None:
    expected = {
        "PURPOSE_CANON.md": ["Authority Order", "Non-Goals", "Stop Conditions", "Provenance"],
        "ADR.md": ["Alternatives", "Sensitivity", "Rollback And Exit", "Provenance"],
        "ARCHITECTURE_PLANES.md": ["State Ownership", "Cross-Plane Contracts", "Verification And Exit"],
        "MEMORY_RETRIEVAL_POLICY.md": ["Untrusted Content", "Correction, Deletion, And Expiry", "Evaluation"],
        "THREAT_MODEL.md": ["Trust Boundaries", "Threat Register", "Verification And Response"],
        "REPORT_ENVELOPE.md": ["Evidence And Claims", "Risk And Stop Conditions", "Machine Contract", "Colophon"],
        "ACCEPTANCE_PLAN.md": ["Negative And Recovery Cases", "Release Gate", "Completion Rule"],
    }
    for name, headings in expected.items():
        text = (ROOT / "templates" / name).read_text(encoding="utf-8")
        for heading in headings:
            assert f"## {heading}" in text

    skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    assert "Each installation is an independent, host-local capability" in skill
    assert "no other agent, host, or team is required" in skill
    assert "Local subagents, multiple agents, and cross-host collaboration are optional" in skill
    assert "never implicitly share or transfer identity, authority" in skill


def run_json_cli(script: str, *arguments: str) -> tuple[subprocess.CompletedProcess[str], dict]:
    command = [
        sys.executable,
        "-B",
        str(ROOT / "scripts" / script),
        *arguments,
        "--json",
    ]
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        env=env,
    )
    return completed, json.loads(completed.stdout)


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


def clone_root(tmp_path: Path, name: str) -> Path:
    destination = tmp_path / name
    shutil.copytree(
        ROOT,
        destination,
        ignore=shutil.ignore_patterns(".pytest_cache", "__pycache__", "*.pyc"),
    )
    return destination


def write_yaml(path: Path, value: dict) -> None:
    path.write_bytes(
        yaml.safe_dump(value, sort_keys=False, allow_unicode=True).encode("utf-8")
    )


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def test_version_dispatch_accepts_exact_v1_and_v2_and_rejects_hybrids() -> None:
    v2 = load("templates/REQUIREMENTS.yaml")
    validator("requirementsV2").validate(v2)
    validator("requirementsAny").validate(v2)
    assert list(validator("requirements").iter_errors(v2))

    v1 = copy.deepcopy(v2)
    v1["schema_version"] = "1.0"
    for field in (
        "contract_version",
        "contract_refs",
        "non_goals",
        "authoritative_inputs",
        "output_format",
        "stop_conditions",
        "required_evidence",
        "errors",
    ):
        v1.pop(field)
    validator("requirements").validate(v1)
    validator("requirementsAny").validate(v1)

    hybrid = copy.deepcopy(v1)
    hybrid["contract_version"] = "2.0"
    assert list(validator("requirementsAny").iter_errors(hybrid))
    unknown = copy.deepcopy(v2)
    unknown["schema_version"] = "3.0"
    assert list(validator("requirementsAny").iter_errors(unknown))
    missing = copy.deepcopy(v2)
    missing.pop("schema_version")
    assert list(validator("requirementsAny").iter_errors(missing))
    assert list(validator("requirementsAny").iter_errors({}))


def test_contract_bundle_cli_checks_nine_artifacts_and_is_read_only() -> None:
    completed, result = run_json_cli(
        "contract_bundle_check.py", str(ROOT)
    )
    assert completed.returncode == 0, completed.stderr
    assert result["status"] == "pass"
    assert result["checks"]["artifacts"] == "9/9"
    assert result["checks"]["schema"] == "17/17"
    assert result["graph"]["nodes"] == 8
    assert result["provenance"]["manifests"] == 1
    assert result["closure"]["closed"] is True
    assert result["input_readback"]["unchanged"] is True
    assert result["network_access"] == "disabled"

    single, single_result = run_json_cli(
        "contract_bundle_check.py",
        str(ROOT),
        "--artifact",
        "templates/REQUIREMENTS.yaml",
    )
    assert single.returncode == 0, single.stderr
    assert single_result["checks"]["artifacts"] == "1/1"
    assert single_result["checks"]["schema"] == "2/2"


def test_contract_bundle_invalid_artifact_fails_without_mutation(
    tmp_path: Path,
) -> None:
    candidate = clone_root(tmp_path, "invalid-contract")
    target = candidate / "templates" / "REQUIREMENTS.yaml"
    data = yaml.safe_load(target.read_text(encoding="utf-8"))
    data.pop("contract_version")
    write_yaml(target, data)
    before = sha256(target)

    completed, result = run_json_cli(
        "contract_bundle_check.py",
        str(candidate),
        "--artifact",
        "templates/REQUIREMENTS.yaml",
    )

    assert completed.returncode == 1
    assert result["status"] == "fail"
    assert any(item["code"].startswith("SCHEMA_") for item in result["errors"])
    assert result["input_readback"]["unchanged"] is True
    assert sha256(target) == before
    assert not list(candidate.rglob("__pycache__"))
    assert not list(candidate.rglob(".pytest_cache"))


def test_contract_bundle_resolves_provenance_and_rejects_cycles(
    tmp_path: Path,
) -> None:
    candidate = clone_root(tmp_path, "graph-contract")
    requirements_path = candidate / "templates" / "REQUIREMENTS.yaml"
    triage_path = candidate / "templates" / "TRIAGE_DECISION.yaml"
    provenance_path = candidate / "templates" / "PROVENANCE_MANIFEST.json"

    requirements = yaml.safe_load(requirements_path.read_text(encoding="utf-8"))
    triage = yaml.safe_load(triage_path.read_text(encoding="utf-8"))
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    requirements["requirement_id"] = "REQ-001"
    requirements["authority"]["owner"] = "product-owner"
    requirements["contract_refs"] = [
        {
            "artifact_type": "triage_decision",
            "artifact_id": "TRIAGE-001",
            "contract_version": "2.0",
            "schema_version": "2.0",
            "relation": "triaged_by",
            "expected_owner": "triage-owner",
            "expected_risk": "R2",
            "required": True,
        }
    ]
    triage["decision_id"] = "TRIAGE-001"
    triage["owner"] = "triage-owner"
    triage["classification"]["risk"] = "R2"
    provenance["artifact_id"] = "PROV-001"
    provenance["owner"] = "evidence-owner"
    provenance["contract_refs"] = [
        {
            "artifact_type": "requirements",
            "artifact_id": "REQ-001",
            "contract_version": "2.0",
            "schema_version": "2.0",
            "relation": "records_provenance_for",
            "expected_owner": "product-owner",
            "expected_risk": None,
            "required": True,
        }
    ]
    write_yaml(requirements_path, requirements)
    write_yaml(triage_path, triage)
    provenance_path.write_bytes(
        (json.dumps(provenance, indent=2, sort_keys=True) + "\n").encode("utf-8")
    )

    completed, result = run_json_cli(
        "contract_bundle_check.py", str(candidate)
    )
    assert completed.returncode == 0, completed.stderr
    assert result["status"] == "pass"
    assert result["checks"]["references"] == "2/2"
    assert len(result["graph"]["edges"]) == 2
    assert result["closure"]["closed"] is True

    triage["contract_refs"] = [
        {
            "artifact_type": "requirements",
            "artifact_id": "REQ-001",
            "contract_version": "2.0",
            "schema_version": "2.0",
            "relation": "returns_to",
            "expected_owner": "product-owner",
            "expected_risk": None,
            "required": True,
        }
    ]
    write_yaml(triage_path, triage)
    before = sha256(triage_path)
    failed, failed_result = run_json_cli(
        "contract_bundle_check.py", str(candidate)
    )
    assert failed.returncode == 1
    assert failed_result["status"] == "fail"
    assert failed_result["checks"]["references"] == "3/3"
    assert any(item["code"] == "GRAPH_CYCLE" for item in failed_result["errors"])
    assert failed_result["input_readback"]["unchanged"] is True
    assert sha256(triage_path) == before


def simulator_module():
    scripts = str(ROOT / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    import gc_state_simulator

    return gc_state_simulator


def quick_validate_module():
    scripts = str(ROOT / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    import quick_validate

    return quick_validate


def v1_e1_event() -> dict:
    return {
        "schema_version": "1.0",
        "lane": "E1",
        "queue": [
            {"physical_id": 1, "event_id": "EVENT-001"},
            {"physical_id": 2, "event_id": "EVENT-002"},
        ],
        "physical_max": 2,
        "physical_last": 2,
        "complete_eof": True,
        "cursor_before": 0,
        "consumed_ids": [1, 2],
        "cursor_after": 2,
        "cursor_readback": 2,
        "observed_max": 2,
        "active_writers": ["writer-1"],
        "watcher_count": 1,
        "terminal_state": "CONSUMED",
    }


def no_approval() -> dict:
    return {
        "required": False,
        "approval_id": None,
        "approver": None,
        "decision": None,
        "target_digest": None,
    }


def pending_approval() -> dict:
    return {
        "required": True,
        "approval_id": "APR-001",
        "approver": "human-owner",
        "decision": "pending",
        "target_digest": "A" * 64,
    }


def test_gc_state_event_validator_covers_queue_provenance_and_hybrids() -> None:
    simulator = simulator_module()
    v1 = v1_e1_event()
    assert simulator.validate_event(v1) == []

    v2 = copy.deepcopy(v1)
    v2.update(
        {
            "schema_version": "2.0",
            "contract_version": "2.0",
            "provenance": {
                "scenario_id": "PUBLIC-TEST",
                "registry_sha256": "B" * 64,
            },
            "closure": {
                "input_read_only": True,
                "readback_complete": True,
            },
        }
    )
    assert simulator.validate_event(v2, "E1", "PUBLIC-TEST") == []

    hybrid = copy.deepcopy(v1)
    hybrid["contract_version"] = "2.0"
    assert simulator.validate_event(hybrid)
    duplicate = copy.deepcopy(v1)
    duplicate["queue"][1]["physical_id"] = 1
    assert any("strictly ordered" in item for item in simulator.validate_event(duplicate))
    stale_cursor = copy.deepcopy(v1)
    stale_cursor["cursor_readback"] = 1
    assert any("readback" in item for item in simulator.validate_event(stale_cursor))


def test_gc_state_event_validator_covers_lease_fencing_and_human_approval() -> None:
    simulator = simulator_module()
    lease_event = {
        "schema_version": "1.0",
        "lane": "E2",
        "renewal_state": "ACTIVE",
        "leases": [
            {
                "session_id": "session-1",
                "active": True,
                "epoch": 1,
                "fencing_token": 10,
            }
        ],
        "writer_session": "session-1",
        "presented_fencing_token": 10,
        "continuity_verified": True,
        "write_requested": True,
        "human_approval": no_approval(),
    }
    assert simulator.validate_event(lease_event) == []
    stale = copy.deepcopy(lease_event)
    stale["presented_fencing_token"] = 9
    assert any("stale" in item for item in simulator.validate_event(stale))
    dual = copy.deepcopy(lease_event)
    dual["leases"].append(
        {
            "session_id": "session-2",
            "active": True,
            "epoch": 2,
            "fencing_token": 20,
        }
    )
    assert any("exactly one" in item for item in simulator.validate_event(dual))
    no_continuity = copy.deepcopy(lease_event)
    no_continuity["continuity_verified"] = False
    assert any("continuity" in item for item in simulator.validate_event(no_continuity))

    uncertain = {
        "schema_version": "1.0",
        "lane": "E3",
        "attempt_id": "ATTEMPT-001",
        "effect_state": "STATE_UNCERTAIN",
        "readback_state": "REQUIRED",
        "automatic_retry": False,
        "silent_failover": False,
        "breaker_open": True,
        "terminal_state": "PM_REQUIRED",
        "lease": {
            "owner": "supervisor",
            "active": True,
            "epoch": 1,
            "fencing_token": 100,
        },
        "presented_fencing_token": 100,
        "human_approval": pending_approval(),
    }
    assert simulator.validate_event(uncertain) == []
    blind_retry = copy.deepcopy(uncertain)
    blind_retry["automatic_retry"] = True
    assert any("automatic_retry" in item for item in simulator.validate_event(blind_retry))
    missing_human = copy.deepcopy(uncertain)
    missing_human["human_approval"] = no_approval()
    assert any("human approval" in item for item in simulator.validate_event(missing_human))


def test_gc_state_simulator_self_test_and_fault_scenario_are_deterministic() -> None:
    self_test, result = run_json_cli(
        "gc_state_simulator.py", str(ROOT), "--self-test"
    )
    assert self_test.returncode == 0, self_test.stderr
    assert result["status"] == "pass"
    assert result["checks"]["fault_scenarios"] == "47/47"
    assert result["checks"]["invariant_self_tests"] == "9/9"
    assert result["checks"]["mutant_fixtures_validated"] == "32/32"
    assert result["mutants_killed"] is None
    assert result["input_readback"]["unchanged"] is True
    assert result["network_access"] == "disabled"
    assert_runtime_evidence(result)

    first, first_result = run_json_cli(
        "gc_state_simulator.py",
        str(ROOT),
        "--scenario",
        "F2-E1-DUPLICATE_ID",
    )
    second, second_result = run_json_cli(
        "gc_state_simulator.py",
        str(ROOT),
        "--scenario",
        "F2-E1-DUPLICATE_ID",
    )
    assert first.returncode == second.returncode == 0
    assert first.stdout == second.stdout
    assert first_result == second_result
    assert first_result["event_status"] == "rejected"
    assert first_result["oracle_satisfied"] is True
    assert first_result["input_readback"]["unchanged"] is True
    assert_runtime_evidence(first_result)


def test_runtime_evidence_is_stable_and_path_free() -> None:
    quick, quick_result = run_json_cli("quick_validate.py", str(ROOT))
    assert quick.stdout
    assert_runtime_evidence(quick_result)

    requirements, requirements_result = run_json_cli(
        "validate_requirements.py",
        str(ROOT / "templates" / "REQUIREMENTS.yaml"),
        "--skill-root",
        str(ROOT),
        "--allow-draft",
    )
    assert requirements.returncode == 0, requirements.stderr
    assert_runtime_evidence(requirements_result)

    evidence = requirements_result["runtime_evidence"]
    assert all(
        "/" not in value and "\\" not in value
        for value in evidence.values()
        if isinstance(value, str)
    )


def test_quick_validate_meta_gate_rejects_rc0_failure_and_zero_denominators() -> None:
    quick_validate = quick_validate_module()

    failed_payload = {
        "status": "fail",
        "cases": 0,
        "hard_check_ids": 0,
        "fault_scenarios": 0,
        "mutants": 0,
    }
    failed_findings = quick_validate.deterministic_child_errors(
        "eval_v2",
        0,
        failed_payload,
    )
    assert any("status mismatch" in item for item in failed_findings)
    assert any("cases mismatch" in item for item in failed_findings)
    assert any("hard_check_ids mismatch" in item for item in failed_findings)
    assert any("fault_scenarios mismatch" in item for item in failed_findings)
    assert any("mutants mismatch" in item for item in failed_findings)

    zero_payload = {
        "status": "pass",
        "checks": {
            "fault_scenarios": "0/0",
            "invariant_self_tests": "0/0",
            "mutant_fixtures_validated": "0/0",
        },
    }
    zero_findings = quick_validate.deterministic_child_errors(
        "gc_state_self_test",
        0,
        zero_payload,
    )
    assert len(zero_findings) == 3
    assert all("denominator" in item for item in zero_findings)


def test_quick_validate_rejects_duplicate_delegated_json_keys() -> None:
    quick_validate = quick_validate_module()

    try:
        quick_validate.load_unique_json_payload(
            '{"status":"fail","status":"pass"}',
            "synthetic-child",
        )
    except quick_validate.ContractError as exc:
        assert "duplicate JSON key: status" in str(exc)
    else:
        raise AssertionError("duplicate delegated JSON key was accepted")


def test_quick_validate_rejects_duplicate_skill_frontmatter(
    tmp_path: Path,
) -> None:
    candidate = clone_root(tmp_path, "multi-agent-system-architect")
    skill_path = candidate / "SKILL.md"
    raw = skill_path.read_text(encoding="utf-8")
    name_match = next(
        line for line in raw.splitlines() if line.startswith("name:")
    )
    skill_path.write_text(
        raw.replace(name_match, f"{name_match}\n{name_match}", 1),
        encoding="utf-8",
        newline="\n",
    )

    completed, payload = run_json_cli("quick_validate.py", str(candidate))
    assert completed.returncode == 1
    assert payload["status"] == "fail"
    assert any(
        "duplicate YAML key in SKILL.md frontmatter: name" in item
        for item in payload["errors"]
    )


def test_validate_requirements_rejects_duplicate_json_and_yaml_keys(
    tmp_path: Path,
) -> None:
    source = ROOT / "templates" / "REQUIREMENTS.yaml"
    document = yaml.safe_load(source.read_text(encoding="utf-8"))

    json_path = tmp_path / "duplicate-requirements.json"
    json_body = json.dumps(document, sort_keys=True)
    duplicate_json = (
        '{"schema_version":'
        + json.dumps(document["schema_version"])
        + ","
        + json_body[1:]
    )
    json_path.write_text(duplicate_json, encoding="utf-8", newline="\n")
    json_run, json_result = run_json_cli(
        "validate_requirements.py",
        str(json_path),
        "--skill-root",
        str(ROOT),
        "--allow-draft",
    )
    assert json_run.returncode == 1
    assert json_result["status"] == "fail"
    assert any("duplicate JSON key: schema_version" in item for item in json_result["errors"])
    assert_runtime_evidence(json_result)

    yaml_path = tmp_path / "duplicate-requirements.yaml"
    duplicate_yaml = source.read_text(encoding="utf-8") + (
        f"\nschema_version: {document['schema_version']}\n"
    )
    yaml_path.write_text(duplicate_yaml, encoding="utf-8", newline="\n")
    yaml_run, yaml_result = run_json_cli(
        "validate_requirements.py",
        str(yaml_path),
        "--skill-root",
        str(ROOT),
        "--allow-draft",
    )
    assert yaml_run.returncode == 1
    assert yaml_result["status"] == "fail"
    assert any("duplicate YAML key: schema_version" in item for item in yaml_result["errors"])
    assert_runtime_evidence(yaml_result)


def test_gc_state_simulator_rejects_invalid_supplied_event_without_mutation(
    tmp_path: Path,
) -> None:
    event = v1_e1_event()
    event["queue"][1]["physical_id"] = 1
    event_path = tmp_path / "invalid-event.json"
    event_path.write_bytes(
        (json.dumps(event, indent=2, sort_keys=True) + "\n").encode("utf-8")
    )
    before = sha256(event_path)

    completed, result = run_json_cli(
        "gc_state_simulator.py",
        str(ROOT),
        "--scenario",
        "F2-E1-DUPLICATE_ID",
        "--event",
        str(event_path),
    )

    assert completed.returncode == 1
    assert result["status"] == "fail"
    assert result["event_status"] == "rejected"
    assert result["oracle_satisfied"] is False
    assert result["event_readback"]["unchanged"] is True
    assert result["input_readback"]["unchanged"] is True
    assert sha256(event_path) == before


def _write_public_skill(
    candidate: Path,
    quick_validate,
    *,
    name: str | None = None,
    description: object | None = None,
    extra_frontmatter: tuple[str, ...] = (),
) -> None:
    skill = candidate / "SKILL.md"
    current, body = quick_validate.parse_frontmatter(
        skill.read_text(encoding="utf-8")
    )
    if name is None:
        name = quick_validate.PUBLIC_ONLY_EXPECTED_NAME
    if description is None:
        description = current["description"].strip()
    lines = [
        "---",
        f"name: {name}",
        f"description: {json.dumps(description, ensure_ascii=False)}",
        f"license: {current['license']}",
        *extra_frontmatter,
        "---",
        body,
    ]
    skill.write_bytes("\n".join(lines).encode("utf-8"))


def _make_public_candidate(
    tmp_path: Path,
    label: str,
) -> tuple[object, Path]:
    quick_validate = quick_validate_module()
    candidate = tmp_path / label / quick_validate.PUBLIC_ONLY_EXPECTED_NAME
    for relative in quick_validate.PUBLIC_ONLY_FILES:
        source = ROOT.joinpath(*relative.split("/"))
        target = candidate.joinpath(*relative.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    _write_public_skill(candidate, quick_validate)

    # Synthetic opaque sentinels prove name-only skipping without copying or
    # inspecting any protected source carrier.
    for relative in sorted(quick_validate.PUBLIC_ONLY_PROTECTED_NAMES):
        target = candidate.joinpath(*relative.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"opaque sentinel: must not be opened\n")
    return quick_validate, candidate


def _public_snapshot(quick_validate, candidate: Path) -> dict[str, str]:
    return {
        relative: hashlib.sha256(
            candidate.joinpath(*relative.split("/")).read_bytes()
        ).hexdigest().upper()
        for relative in quick_validate.PUBLIC_ONLY_FILES
    }


def _candidate_relative(candidate: Path, value: object) -> str | None:
    try:
        raw = os.fspath(value)
    except TypeError:
        return None
    if isinstance(raw, bytes):
        raw = os.fsdecode(raw)
    candidate_absolute = Path(os.path.abspath(candidate))
    path_absolute = Path(os.path.abspath(raw))
    try:
        relative = path_absolute.relative_to(candidate_absolute).as_posix()
    except ValueError:
        return None
    return "" if relative == "." else relative


def test_public_only_exact_inventory_determinism_and_opaque_skip(
    tmp_path: Path,
    monkeypatch,
) -> None:
    quick_validate, candidate = _make_public_candidate(tmp_path, "positive")
    before = _public_snapshot(quick_validate, candidate)
    protected = {
        "evals/behavioral_rubric.yaml",
        "evals/v2_behavioral_rubric.yaml",
        "scripts/score_behavioral_outputs.py",
    }
    assert set(quick_validate.PUBLIC_ONLY_PROTECTED_NAMES) == protected

    real_stat = quick_validate.os.stat
    real_lstat = quick_validate.os.lstat
    real_open = quick_validate.os.open
    real_scandir = quick_validate.os.scandir

    def guarded_stat(path, *args, **kwargs):
        relative = _candidate_relative(candidate, path)
        assert relative not in protected, f"protected stat attempted: {relative}"
        return real_stat(path, *args, **kwargs)

    def guarded_lstat(path, *args, **kwargs):
        relative = _candidate_relative(candidate, path)
        assert relative not in protected, f"protected lstat attempted: {relative}"
        return real_lstat(path, *args, **kwargs)

    def guarded_open(path, *args, **kwargs):
        relative = _candidate_relative(candidate, path)
        assert relative not in protected, f"protected open attempted: {relative}"
        return real_open(path, *args, **kwargs)

    class GuardedEntry:
        def __init__(self, entry, directory: str | None):
            self._entry = entry
            self._relative = (
                entry.name if not directory else f"{directory}/{entry.name}"
            )

        @property
        def name(self):
            return self._entry.name

        def _guard(self, operation: str) -> None:
            assert self._relative not in protected, (
                f"protected DirEntry.{operation} attempted: {self._relative}"
            )

        def stat(self, *args, **kwargs):
            self._guard("stat")
            return self._entry.stat(*args, **kwargs)

        def is_file(self, *args, **kwargs):
            self._guard("is_file")
            return self._entry.is_file(*args, **kwargs)

        def is_dir(self, *args, **kwargs):
            self._guard("is_dir")
            return self._entry.is_dir(*args, **kwargs)

        def is_symlink(self, *args, **kwargs):
            self._guard("is_symlink")
            return self._entry.is_symlink(*args, **kwargs)

    class GuardedScandir:
        def __init__(self, iterator, directory: str | None):
            self._iterator = iterator
            self._directory = directory

        def __enter__(self):
            self._iterator.__enter__()
            return self

        def __exit__(self, exc_type, exc, traceback):
            return self._iterator.__exit__(exc_type, exc, traceback)

        def __iter__(self):
            return self

        def __next__(self):
            return GuardedEntry(next(self._iterator), self._directory)

    def guarded_scandir(path):
        directory = _candidate_relative(candidate, path)
        return GuardedScandir(real_scandir(path), directory)

    def forbidden_subprocess(*args, **kwargs):
        raise AssertionError("public-only profile attempted a subprocess")

    monkeypatch.setattr(quick_validate.os, "stat", guarded_stat)
    monkeypatch.setattr(quick_validate.os, "lstat", guarded_lstat)
    monkeypatch.setattr(quick_validate.os, "open", guarded_open)
    monkeypatch.setattr(quick_validate.os, "scandir", guarded_scandir)
    monkeypatch.setattr(quick_validate.subprocess, "run", forbidden_subprocess)

    first = quick_validate.validate_public_only(candidate)
    second = quick_validate.validate_public_only(candidate)
    assert first == second
    assert first["status"] == "pass", first["errors"]
    assert first["checks"]["public_inventory"] == "70/70"
    assert first["checks"]["stable_text_reads"] == "70/70"
    assert first["checks"]["final_public_inventory"] == "70/70"
    assert first["checks"]["final_stable_text_reads"] == "70/70"
    assert first["checks"]["final_readback"] == "70/70"
    assert first["checks"]["v2_behavioral_inputs"] == "36/36"
    assert first["checks"]["v2_fault_scenarios"] == "47/47"
    assert first["checks"]["v2_mutants"] == "32/32"
    assert first["checks"]["control_vocabulary_lanes"] == "3/3"
    assert first["checks"]["behavioral_output_shapes"] == "2/2"
    assert first["observed_public_files"] == 70
    assert first["validated_public_files"] == 70
    assert first["opaque_protected_names_seen"] == sorted(protected)
    assert first["input_readback"]["unchanged"] is True
    assert first["input_readback"]["inventory_unchanged"] is True
    assert first["input_readback"]["protected_names_unchanged"] is True
    assert first["input_readback"]["token_set_complete"] is True
    assert first["input_readback"]["digest_set_complete"] is True
    assert first["input_readback"]["tree_unchanged"] is True
    assert (
        first["input_readback"]["initial_tree_sha256"]
        == first["input_readback"]["final_tree_sha256"]
        == first["public_tree_sha256"]
    )
    assert len(first["public_tree_sha256"]) == 64
    assert first["subprocesses_started"] == 0

    emitted: list[tuple[dict[str, object], bool]] = []
    monkeypatch.setattr(quick_validate, "configure_utf8_stdio", lambda: None)
    monkeypatch.setattr(
        quick_validate,
        "_emit_public",
        lambda payload, as_json: emitted.append((payload, as_json)),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "quick_validate.py",
            str(candidate),
            "--profile",
            "public-only",
            "--json",
        ],
    )
    assert quick_validate.main() == 0
    assert emitted == [(first, True)]
    assert _public_snapshot(quick_validate, candidate) == before


def test_public_only_cli_json_is_deterministic_and_read_only(
    tmp_path: Path,
) -> None:
    quick_validate, candidate = _make_public_candidate(tmp_path, "cli")
    before = _public_snapshot(quick_validate, candidate)
    first_run, first = run_json_cli(
        "quick_validate.py",
        str(candidate),
        "--profile",
        "public-only",
    )
    second_run, second = run_json_cli(
        "quick_validate.py",
        str(candidate),
        "--profile",
        "public-only",
    )
    assert first_run.returncode == second_run.returncode == 0
    assert first_run.stdout == second_run.stdout
    assert first == second
    assert first["status"] == "pass"
    assert first["checks"]["public_inventory"] == "70/70"
    assert first["checks"]["stable_text_reads"] == "70/70"
    assert first["checks"]["final_public_inventory"] == "70/70"
    assert first["checks"]["final_stable_text_reads"] == "70/70"
    assert first["checks"]["final_readback"] == "70/70"
    assert first["checks"]["v2_behavioral_inputs"] == "36/36"
    assert first["checks"]["v2_fault_scenarios"] == "47/47"
    assert first["checks"]["v2_mutants"] == "32/32"
    assert first["checks"]["control_vocabulary_lanes"] == "3/3"
    assert first["checks"]["behavioral_output_shapes"] == "2/2"
    assert first["input_readback"]["unchanged"] is True
    assert _public_snapshot(quick_validate, candidate) == before


def test_public_only_inventory_is_exact_and_nonrecursive(
    tmp_path: Path,
    monkeypatch,
) -> None:
    quick_validate, candidate = _make_public_candidate(tmp_path, "inventory")
    unexpected = candidate / "unexpected-directory"
    unexpected.mkdir()
    (unexpected / "nested.txt").write_bytes(b"must remain unvisited\n")

    scanned: list[str | None] = []
    real_scandir = quick_validate.os.scandir

    def guarded_scandir(path):
        relative = _candidate_relative(candidate, path)
        assert relative != "unexpected-directory"
        scanned.append(relative)
        return real_scandir(path)

    monkeypatch.setattr(quick_validate.os, "scandir", guarded_scandir)
    payload = quick_validate.validate_public_only(candidate)
    assert payload["status"] == "fail"
    assert "unexpected path in public tree: unexpected-directory" in payload["errors"]
    assert not any("nested.txt" in error for error in payload["errors"])
    assert set(scanned) == set(quick_validate.PUBLIC_ONLY_DIRECTORIES)

    _, missing = _make_public_candidate(tmp_path, "missing")
    (missing / "tests" / "test_catalog.py").unlink()
    missing_payload = quick_validate.validate_public_only(missing)
    assert missing_payload["status"] == "fail"
    assert missing_payload["checks"]["public_inventory"] == "69/70"
    assert "missing public file: tests/test_catalog.py" in missing_payload["errors"]


def test_public_only_frontmatter_and_link_boundaries(tmp_path: Path) -> None:
    quick_validate, extra = _make_public_candidate(tmp_path, "frontmatter-extra")
    _write_public_skill(
        extra,
        quick_validate,
        extra_frontmatter=("compatibility: forbidden",),
    )
    payload = quick_validate.validate_public_only(extra)
    assert any("frontmatter key mismatch" in error for error in payload["errors"])

    _, wrong_name = _make_public_candidate(tmp_path, "frontmatter-name")
    _write_public_skill(wrong_name, quick_validate, name="wrong-name")
    payload = quick_validate.validate_public_only(wrong_name)
    assert any("frontmatter name mismatch" in error for error in payload["errors"])

    _, untrimmed = _make_public_candidate(tmp_path, "frontmatter-description")
    current, _ = quick_validate.parse_frontmatter(
        (untrimmed / "SKILL.md").read_text(encoding="utf-8")
    )
    _write_public_skill(
        untrimmed,
        quick_validate,
        description=current["description"] + " ",
    )
    payload = quick_validate.validate_public_only(untrimmed)
    assert any("description must be trimmed" in error for error in payload["errors"])

    for label, target, expected in (
        ("link-missing", "references/not-declared.md", "undeclared path"),
        ("link-escape", "../outside.md", "escapes public root"),
        (
            "link-protected",
            "evals/behavioral_rubric.yaml",
            "opaque protected path",
        ),
    ):
        _, candidate = _make_public_candidate(tmp_path, label)
        skill = candidate / "SKILL.md"
        skill.write_bytes(
            skill.read_bytes() + f"\n[boundary probe]({target})\n".encode("utf-8")
        )
        payload = quick_validate.validate_public_only(candidate)
        assert any(expected in error for error in payload["errors"]), payload


def test_public_only_encoding_and_hygiene_fail_closed(tmp_path: Path) -> None:
    quick_validate = quick_validate_module()

    def check(label: str, mutate, expected: str) -> None:
        _, candidate = _make_public_candidate(tmp_path, label)
        target = candidate / "pyproject.toml"
        mutate(target)
        payload = quick_validate.validate_public_only(candidate)
        assert payload["status"] == "fail"
        assert any(expected in error for error in payload["errors"]), payload

    check(
        "encoding-bom",
        lambda path: path.write_bytes(b"\xef\xbb\xbf" + path.read_bytes()),
        "UTF-8 BOM",
    )
    check(
        "encoding-cr",
        lambda path: path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n", 1)),
        "line endings must be LF",
    )
    check(
        "encoding-invalid",
        lambda path: path.write_bytes(path.read_bytes() + b"\xff"),
        "invalid UTF-8",
    )
    check(
        "hygiene-placeholder",
        lambda path: path.write_bytes(
            path.read_bytes() + (("TO" + "DO") + "\n").encode("utf-8")
        ),
        "active placeholder marker",
    )
    check(
        "hygiene-doctrine",
        lambda path: path.write_bytes(
            path.read_bytes() + (("Metodo " + "GC") + "\n").encode("utf-8")
        ),
        "public sanitation marker",
    )


def test_public_only_rejects_fstat_drift(
    tmp_path: Path,
    monkeypatch,
) -> None:
    quick_validate, candidate = _make_public_candidate(tmp_path, "fstat")
    real_fstat = quick_validate.os.fstat
    calls = 0

    def drifting_fstat(descriptor):
        nonlocal calls
        state = real_fstat(descriptor)
        calls += 1
        if calls == 2:
            fields = list(state)
            fields[6] += 1
            return os.stat_result(fields)
        return state

    monkeypatch.setattr(quick_validate.os, "fstat", drifting_fstat)
    try:
        quick_validate._read_stable_public_text(candidate, "pyproject.toml")
    except quick_validate.ContractError as exc:
        assert "changed during read" in str(exc)
    else:
        raise AssertionError("fstat drift was accepted")


def test_public_only_final_readback_detects_same_size_rewrite(
    tmp_path: Path,
    monkeypatch,
) -> None:
    quick_validate, candidate = _make_public_candidate(tmp_path, "same-size-race")
    target = candidate / "pyproject.toml"
    original = target.read_bytes()
    assert original
    rewritten = bytes([original[0] ^ 1]) + original[1:]
    assert len(rewritten) == len(original)

    real_inventory = quick_validate._inventory_public_tree
    inventory_calls = 0

    def racing_inventory(root: Path):
        nonlocal inventory_calls
        inventory_calls += 1
        if inventory_calls == 2:
            target.write_bytes(rewritten)
        return real_inventory(root)

    monkeypatch.setattr(
        quick_validate,
        "_inventory_public_tree",
        racing_inventory,
    )
    payload = quick_validate.validate_public_only(candidate)
    assert inventory_calls == 2
    assert payload["status"] == "fail"
    assert payload["checks"]["final_stable_text_reads"] == "70/70"
    assert payload["checks"]["final_readback"] == "69/70"
    assert payload["input_readback"]["unchanged"] is False
    assert payload["input_readback"]["tree_unchanged"] is False
    assert any(
        "public file bytes changed before final readback: pyproject.toml" in error
        for error in payload["errors"]
    )
    assert "public tree digest changed before final readback" in payload["errors"]


def test_public_only_final_inventory_detects_late_entry_and_protected_drift(
    tmp_path: Path,
    monkeypatch,
) -> None:
    quick_validate, late = _make_public_candidate(tmp_path, "late-entry")
    late_entry = late / "late-unexpected.txt"
    real_inventory = quick_validate._inventory_public_tree
    inventory_calls = 0

    def late_inventory(root: Path):
        nonlocal inventory_calls
        inventory_calls += 1
        if inventory_calls == 2:
            late_entry.write_bytes(b"late inventory probe\n")
        return real_inventory(root)

    monkeypatch.setattr(quick_validate, "_inventory_public_tree", late_inventory)
    payload = quick_validate.validate_public_only(late)
    assert inventory_calls == 2
    assert payload["status"] == "fail"
    assert payload["checks"]["final_public_inventory"] == "70/70"
    assert payload["checks"]["final_stable_text_reads"] == "70/70"
    assert payload["input_readback"]["inventory_unchanged"] is False
    assert payload["input_readback"]["unchanged"] is False
    assert "unexpected path in public tree: late-unexpected.txt" in payload["errors"]

    monkeypatch.undo()
    quick_validate, drift = _make_public_candidate(tmp_path, "protected-drift")
    protected = drift / "evals" / "behavioral_rubric.yaml"
    real_inventory = quick_validate._inventory_public_tree
    inventory_calls = 0

    def protected_drift_inventory(root: Path):
        nonlocal inventory_calls
        inventory_calls += 1
        if inventory_calls == 2:
            protected.unlink()
        return real_inventory(root)

    monkeypatch.setattr(
        quick_validate,
        "_inventory_public_tree",
        protected_drift_inventory,
    )
    payload = quick_validate.validate_public_only(drift)
    assert payload["status"] == "fail"
    assert payload["input_readback"]["protected_names_unchanged"] is False
    assert payload["input_readback"]["unchanged"] is False
    assert "protected-name set changed before final readback" in payload["errors"]


def test_public_only_public_contracts_fail_closed(tmp_path: Path) -> None:
    quick_validate, inputs_root = _make_public_candidate(tmp_path, "contract-inputs")
    inputs_path = inputs_root / "evals" / "v2_behavioral_inputs.yaml"
    inputs = yaml.safe_load(inputs_path.read_text(encoding="utf-8"))
    inputs["cases"][0]["direct_answer_label"] = "forbidden"
    write_yaml(inputs_path, inputs)
    payload = quick_validate.validate_public_only(inputs_root)
    assert payload["status"] == "fail"
    assert payload["checks"]["v2_behavioral_inputs"] == "35/36"
    assert any("direct-answer labels are forbidden" in error for error in payload["errors"])

    _, fault_root = _make_public_candidate(tmp_path, "contract-fault")
    fault_path = fault_root / "evals" / "v2_fault_injection.yaml"
    fault = yaml.safe_load(fault_path.read_text(encoding="utf-8"))
    fault["fault_counts"]["E2"] = 16
    write_yaml(fault_path, fault)
    payload = quick_validate.validate_public_only(fault_root)
    assert payload["status"] == "fail"
    assert any("fault counts must be E1=15 E2=17 E3=15" in error for error in payload["errors"])

    _, vocabulary_root = _make_public_candidate(tmp_path, "contract-vocabulary")
    vocabulary_path = vocabulary_root / "evals" / "control_vocabulary.yaml"
    vocabulary = yaml.safe_load(vocabulary_path.read_text(encoding="utf-8"))
    vocabulary["v2"]["evaluation_lanes"].remove("VERIFIER_SEALED")
    write_yaml(vocabulary_path, vocabulary)
    payload = quick_validate.validate_public_only(vocabulary_root)
    assert payload["status"] == "fail"
    assert payload["checks"]["control_vocabulary_lanes"] == "2/3"
    assert any("include all three evaluation lanes" in error for error in payload["errors"])

    _, schema_root = _make_public_candidate(tmp_path, "contract-schema")
    schema_path = schema_root / "evals" / "behavioral_output.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    schema["$defs"].pop("v2HardDecisions")
    schema_path.write_bytes(
        (json.dumps(schema, indent=2, sort_keys=True) + "\n").encode("utf-8")
    )
    payload = quick_validate.validate_public_only(schema_root)
    assert payload["status"] == "fail"
    assert payload["checks"]["behavioral_output_shapes"] == "1/2"
    assert any("V2 hard_decisions definition drifted" in error for error in payload["errors"])


def test_public_only_ordinary_python_creates_no_local_pycache(
    tmp_path: Path,
) -> None:
    quick_validate, candidate = _make_public_candidate(tmp_path, "ordinary-python")
    before = _public_snapshot(quick_validate, candidate)
    env = dict(os.environ)
    env.pop("PYTHONDONTWRITEBYTECODE", None)
    env.pop("PYTHONPYCACHEPREFIX", None)
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    completed = subprocess.run(
        [
            sys.executable,
            str(candidate / "scripts" / "quick_validate.py"),
            str(candidate),
            "--profile",
            "public-only",
            "--json",
        ],
        cwd=candidate,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        env=env,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["status"] == "pass"
    assert payload["checks"]["final_readback"] == "70/70"
    assert payload["input_readback"]["unchanged"] is True
    for relative in quick_validate.PUBLIC_ONLY_DIRECTORIES:
        directory = candidate.joinpath(*relative.split("/")) if relative else candidate
        assert not (directory / "__pycache__").exists()
    assert _public_snapshot(quick_validate, candidate) == before
