#!/usr/bin/env python3
"""Host-neutral, read-only oracle for the frozen GC V2 fault registry.

The simulator validates physical queue/cursor invariants (E1), lease,
continuity, and fencing invariants (E2), and effect/readback/human-approval
invariants (E3).  Built-in fault scenarios are synthetic state transitions:
they never touch a carrier, target, provider, or network.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from _common import ContractError, emit, sha256_bytes  # noqa: E402
from contract_bundle_check import _load_unique, _tree_fingerprint  # noqa: E402


REGISTRY_PATH = Path("evals/v2_fault_injection.yaml")
LANES = ("E1", "E2", "E3")
REGISTRY_FIELDS = frozenset(
    {
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
)
SCENARIO_FIELDS = frozenset(
    {
        "scenario_id",
        "evidence_level",
        "exact_injection",
        "public_white_box_oracle_contract",
        "public_white_box_expected_owner",
        "public_white_box_expected_recovery",
        "public_white_box_expected_risk_class",
    }
)
MUTANT_FIELDS = frozenset(
    {
        "mutation_id",
        "deterministic_test_id",
        "fault",
        "injection_operator",
        "planned_test_locator",
        "public_white_box_kill_oracle",
        "public_white_box_required_lifecycle",
        "target_locator",
    }
)
EVIDENCE_FIELDS = frozenset({"before_execution", "required_after_execution"})
COMMON_FIELDS = frozenset({"schema_version", "lane"})
V2_FIELDS = frozenset({"contract_version", "provenance", "closure"})
PROVENANCE_FIELDS = frozenset({"scenario_id", "registry_sha256"})
CLOSURE_FIELDS = frozenset({"input_read_only", "readback_complete"})
APPROVAL_FIELDS = frozenset(
    {
        "required",
        "approval_id",
        "approver",
        "decision",
        "target_digest",
    }
)
QUEUE_ITEM_FIELDS = frozenset({"physical_id", "event_id"})
LEASE_FIELDS = frozenset({"session_id", "active", "epoch", "fencing_token"})
EFFECT_LEASE_FIELDS = frozenset({"owner", "active", "epoch", "fencing_token"})
E1_FIELDS = frozenset(
    {
        "queue",
        "physical_max",
        "physical_last",
        "complete_eof",
        "cursor_before",
        "consumed_ids",
        "cursor_after",
        "cursor_readback",
        "observed_max",
        "active_writers",
        "watcher_count",
        "terminal_state",
    }
)
E2_FIELDS = frozenset(
    {
        "renewal_state",
        "leases",
        "writer_session",
        "presented_fencing_token",
        "continuity_verified",
        "write_requested",
        "human_approval",
    }
)
E3_FIELDS = frozenset(
    {
        "attempt_id",
        "effect_state",
        "readback_state",
        "automatic_retry",
        "silent_failover",
        "breaker_open",
        "terminal_state",
        "lease",
        "presented_fencing_token",
        "human_approval",
    }
)
RENEWAL_STATES = frozenset(
    {
        "ACTIVE",
        "RENEWAL_REQUESTED",
        "CHECKPOINTED",
        "OLD_SESSION_QUIESCED",
        "NEW_SESSION_STARTED",
        "REHYDRATED",
        "CONTINUITY_VERIFIED",
    }
)
SAFE_E1_OPERATORS = frozenset(
    {
        "NO_START",
        "LOCK_CONTENTION",
        "SLEEP",
        "PROCESS_CRASH",
        "HEARTBEAT_NO_PROGRESS",
        "TIMEOUT_NO_EVENT",
        "WATCHER_DISCONNECT",
    }
)


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
    parser = argparse.ArgumentParser(
        description="Read-only deterministic simulator for GC V2 E1/E2/E3 state."
    )
    parser.add_argument("root", type=Path, help="Explicit skill root")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--scenario", help="Frozen scenario ID from the public registry")
    group.add_argument(
        "--self-test",
        action="store_true",
        help="Run registry and state-oracle qualification cases",
    )
    parser.add_argument(
        "--event",
        help="Inline JSON or a local JSON/YAML path; valid only with --scenario",
    )
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def _is_int(value: Any) -> bool:
    return type(value) is int


def _non_empty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _sha(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9A-Fa-f]{64}", value) is not None


def _fields(value: Any, expected: frozenset[str], path: str) -> list[str]:
    if not isinstance(value, dict):
        return [f"{path} must be an object"]
    actual = set(value)
    if actual == expected:
        return []
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    return [f"{path} fields mismatch: missing={missing}, extra={extra}"]


def _validate_approval(
    approval: Any, path: str, *, require_decision: str | None = None
) -> list[str]:
    errors = _fields(approval, APPROVAL_FIELDS, path)
    if errors:
        return errors
    assert isinstance(approval, dict)
    required = approval["required"]
    if type(required) is not bool:
        return [f"{path}.required must be boolean"]
    nullable = ("approval_id", "approver", "decision", "target_digest")
    if not required:
        if any(approval[field] is not None for field in nullable):
            errors.append(f"{path} unrequired approval must contain only null details")
        return errors
    for field in ("approval_id", "approver", "decision"):
        if not _non_empty(approval[field]):
            errors.append(f"{path}.{field} must be non-empty")
    if not _sha(approval["target_digest"]):
        errors.append(f"{path}.target_digest must be a SHA-256 digest")
    if approval["decision"] not in {"pending", "approve", "retry", "park", "reject"}:
        errors.append(f"{path}.decision is unsupported")
    if require_decision is not None and approval["decision"] != require_decision:
        errors.append(f"{path}.decision must be {require_decision}")
    return errors


def _validate_envelope(
    event: Any, lane: str | None, scenario_id: str | None
) -> tuple[str | None, list[str]]:
    if not isinstance(event, dict):
        return lane, ["$ must be an object"]
    actual_lane = event.get("lane")
    if lane is not None and actual_lane != lane:
        return lane, [f"$.lane must match selected lane {lane}"]
    if actual_lane not in LANES:
        return None, ["$.lane must be E1, E2, or E3"]
    version = event.get("schema_version")
    lane_fields = {"E1": E1_FIELDS, "E2": E2_FIELDS, "E3": E3_FIELDS}[actual_lane]
    if version == "1.0":
        expected = COMMON_FIELDS | lane_fields
    elif version == "2.0":
        expected = COMMON_FIELDS | V2_FIELDS | lane_fields
    else:
        return actual_lane, ["$.schema_version must be 1.0 or 2.0"]
    errors = _fields(event, expected, "$")
    if errors or version == "1.0":
        return actual_lane, errors
    if event.get("contract_version") != "2.0":
        errors.append("$.contract_version must be 2.0")
    provenance = event.get("provenance")
    errors.extend(_fields(provenance, PROVENANCE_FIELDS, "$.provenance"))
    if isinstance(provenance, dict) and set(provenance) == PROVENANCE_FIELDS:
        if not _non_empty(provenance["scenario_id"]):
            errors.append("$.provenance.scenario_id must be non-empty")
        if scenario_id is not None and provenance["scenario_id"] != scenario_id:
            errors.append("$.provenance.scenario_id does not match selected scenario")
        if not _sha(provenance["registry_sha256"]):
            errors.append("$.provenance.registry_sha256 must be a SHA-256 digest")
    closure = event.get("closure")
    errors.extend(_fields(closure, CLOSURE_FIELDS, "$.closure"))
    if isinstance(closure, dict) and set(closure) == CLOSURE_FIELDS:
        if closure["input_read_only"] is not True:
            errors.append("$.closure.input_read_only must be true")
        if closure["readback_complete"] is not True:
            errors.append("$.closure.readback_complete must be true")
    return actual_lane, errors


def _validate_e1(event: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    queue = event["queue"]
    if not isinstance(queue, list):
        return ["$.queue must be an array"]
    physical_ids: list[Any] = []
    event_ids: list[Any] = []
    for index, item in enumerate(queue):
        item_path = f"$.queue/{index}"
        item_errors = _fields(item, QUEUE_ITEM_FIELDS, item_path)
        errors.extend(item_errors)
        if item_errors:
            continue
        assert isinstance(item, dict)
        physical_ids.append(item["physical_id"])
        event_ids.append(item["event_id"])
        if not _is_int(item["physical_id"]) or item["physical_id"] < 1:
            errors.append(f"{item_path}.physical_id must be a positive integer")
        if not _non_empty(item["event_id"]):
            errors.append(f"{item_path}.event_id must be non-empty")
    # relay_unique_id / relay_order: physical order is evidence, never repaired by sorting.
    if all(_is_int(value) for value in physical_ids):
        if physical_ids != list(range(1, len(queue) + 1)):
            errors.append(
                "$.queue physical IDs must be unique, gap-free, and strictly ordered"
            )
    if len(event_ids) != len(set(value for value in event_ids if isinstance(value, str))):
        errors.append("$.queue event IDs must be unique")
    physical_max = len(queue)
    for field in (
        "physical_max",
        "physical_last",
        "cursor_before",
        "cursor_after",
        "cursor_readback",
        "observed_max",
        "watcher_count",
    ):
        if not _is_int(event[field]) or event[field] < 0:
            errors.append(f"$.{field} must be a non-negative integer")
    if event["physical_max"] != physical_max:
        errors.append("$.physical_max must equal the physical queue MAX")
    if event["physical_last"] != physical_max:
        errors.append("$.physical_last must equal the physical queue tail")
    if event["complete_eof"] is not True:
        errors.append("$.complete_eof must be true")
    if event["observed_max"] != physical_max:
        errors.append("$.observed_max must be read back from physical MAX")
    if event["cursor_before"] > physical_max:
        errors.append("$.cursor_before cannot exceed physical MAX")
    consumed = event["consumed_ids"]
    if not isinstance(consumed, list) or any(
        not _is_int(value) or value < 1 for value in consumed
    ):
        errors.append("$.consumed_ids must contain positive integers")
        consumed = []
    if len(consumed) != len(set(consumed)):
        errors.append("$.consumed_ids must be unique")
    # cursor_readback: advancement is invalid until the physical checkpoint agrees.
    if event["cursor_after"] != event["cursor_readback"]:
        errors.append("$.cursor_after must equal its physical readback")
    writers = event["active_writers"]
    if (
        not isinstance(writers, list)
        or any(not _non_empty(value) for value in writers)
        or len(writers) != len(set(writers))
    ):
        errors.append("$.active_writers must contain unique non-empty IDs")
        writers = []
    terminal = event["terminal_state"]
    if terminal not in {"CONSUMED", "NO_EVENT", "FAILED"}:
        errors.append("$.terminal_state is unsupported")
    elif terminal == "CONSUMED":
        expected = list(range(event["cursor_before"] + 1, physical_max + 1))
        if consumed != expected:
            errors.append("$.consumed_ids must consume every higher ID once in order")
        if event["cursor_after"] != physical_max:
            errors.append("$.cursor_after must advance to physical MAX")
        if len(writers) != 1 or event["watcher_count"] != 1:
            errors.append("CONSUMED requires one writer and one watcher")
    elif terminal == "NO_EVENT":
        if physical_max != event["cursor_before"] or consumed:
            errors.append("NO_EVENT cannot hide a higher physical ID")
        if event["cursor_after"] != event["cursor_before"]:
            errors.append("NO_EVENT cannot advance the cursor")
        if len(writers) != 1 or event["watcher_count"] != 1:
            errors.append("NO_EVENT requires one writer and one watcher")
    elif terminal == "FAILED":
        if consumed or event["cursor_after"] != event["cursor_before"]:
            errors.append("FAILED must preserve the last valid cursor")
        if len(writers) > 1 or event["watcher_count"] > 1:
            errors.append("FAILED cannot retain dual writers or watchers")
    return errors


def _validate_e2(event: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if event["renewal_state"] not in RENEWAL_STATES:
        errors.append("$.renewal_state is unsupported")
    leases = event["leases"]
    if not isinstance(leases, list) or not leases:
        return errors + ["$.leases must be a non-empty array"]
    session_ids: list[Any] = []
    epochs: list[Any] = []
    tokens: list[Any] = []
    active: list[dict[str, Any]] = []
    for index, lease in enumerate(leases):
        path = f"$.leases/{index}"
        lease_errors = _fields(lease, LEASE_FIELDS, path)
        errors.extend(lease_errors)
        if lease_errors:
            continue
        assert isinstance(lease, dict)
        session_ids.append(lease["session_id"])
        epochs.append(lease["epoch"])
        tokens.append(lease["fencing_token"])
        if not _non_empty(lease["session_id"]):
            errors.append(f"{path}.session_id must be non-empty")
        if type(lease["active"]) is not bool:
            errors.append(f"{path}.active must be boolean")
        if not _is_int(lease["epoch"]) or lease["epoch"] < 1:
            errors.append(f"{path}.epoch must be a positive integer")
        if not _is_int(lease["fencing_token"]) or lease["fencing_token"] < 1:
            errors.append(f"{path}.fencing_token must be a positive integer")
        if lease["active"] is True:
            active.append(lease)
    if len(session_ids) != len(set(value for value in session_ids if isinstance(value, str))):
        errors.append("$.leases session IDs must be unique")
    if all(_is_int(value) for value in epochs) and epochs != sorted(set(epochs)):
        errors.append("$.leases epochs must be unique and strictly increasing")
    if all(_is_int(value) for value in tokens) and tokens != sorted(set(tokens)):
        errors.append("$.leases fencing tokens must be unique and strictly increasing")
    # writer_lease: a second active writer is split brain, even if both are live.
    if len(active) != 1:
        errors.append("$.leases must contain exactly one active writer lease")
    if type(event["continuity_verified"]) is not bool:
        errors.append("$.continuity_verified must be boolean")
    if type(event["write_requested"]) is not bool:
        errors.append("$.write_requested must be boolean")
    approval_errors = _validate_approval(event["human_approval"], "$.human_approval")
    errors.extend(approval_errors)
    # renewal_quiz: fencing alone cannot replace reconstructed continuity proof.
    if event["write_requested"] is True:
        if not _non_empty(event["writer_session"]):
            errors.append("$.writer_session is required for a write")
        if not _is_int(event["presented_fencing_token"]):
            errors.append("$.presented_fencing_token is required for a write")
        if len(active) == 1:
            if event["writer_session"] != active[0]["session_id"]:
                errors.append("$.writer_session does not own the active lease")
            if event["presented_fencing_token"] != active[0]["fencing_token"]:
                errors.append("$.presented_fencing_token is stale")
        if event["renewal_state"] != "ACTIVE" or event["continuity_verified"] is not True:
            errors.append("writes require ACTIVE state after continuity proof")
        approval = event["human_approval"]
        if isinstance(approval, dict) and approval.get("required"):
            if approval.get("decision") != "approve":
                errors.append("a required human approval must explicitly approve the write")
    else:
        if event["writer_session"] is not None or event["presented_fencing_token"] is not None:
            errors.append("a non-writing transition cannot present writer authority")
    if event["renewal_state"] in {"ACTIVE", "CONTINUITY_VERIFIED"}:
        if event["continuity_verified"] is not True:
            errors.append("ACTIVE/CONTINUITY_VERIFIED requires continuity proof")
    elif event["continuity_verified"] is not False:
        errors.append("continuity cannot be claimed before its verified state")
    return errors


def _validate_e3(event: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not _non_empty(event["attempt_id"]):
        errors.append("$.attempt_id must be non-empty")
    if type(event["automatic_retry"]) is not bool:
        errors.append("$.automatic_retry must be boolean")
    if type(event["silent_failover"]) is not bool:
        errors.append("$.silent_failover must be boolean")
    if type(event["breaker_open"]) is not bool:
        errors.append("$.breaker_open must be boolean")
    lease = event["lease"]
    lease_errors = _fields(lease, EFFECT_LEASE_FIELDS, "$.lease")
    errors.extend(lease_errors)
    if not lease_errors:
        assert isinstance(lease, dict)
        if not _non_empty(lease["owner"]):
            errors.append("$.lease.owner must be non-empty")
        if lease["active"] is not True:
            errors.append("$.lease.active must be true")
        for field in ("epoch", "fencing_token"):
            if not _is_int(lease[field]) or lease[field] < 1:
                errors.append(f"$.lease.{field} must be a positive integer")
        if event["presented_fencing_token"] != lease["fencing_token"]:
            errors.append("$.presented_fencing_token is stale")
    errors.extend(_validate_approval(event["human_approval"], "$.human_approval"))
    effect = event["effect_state"]
    readback = event["readback_state"]
    terminal = event["terminal_state"]
    approval = event["human_approval"]
    if event["silent_failover"] is not False:
        errors.append("$.silent_failover must always be false")
    if event["automatic_retry"] is not False:
        errors.append("$.automatic_retry must always be false")
    if effect == "NO_EFFECT":
        if readback != "CONFIRMED_ABSENT":
            errors.append("NO_EFFECT requires CONFIRMED_ABSENT readback")
        if terminal not in {"PARKED", "RETRY_AUTHORIZED"}:
            errors.append("NO_EFFECT requires PARKED or RETRY_AUTHORIZED")
        if terminal == "RETRY_AUTHORIZED":
            if not isinstance(approval, dict) or approval.get("decision") != "retry":
                errors.append("RETRY_AUTHORIZED requires an exact human retry decision")
    elif effect == "EFFECT_CONFIRMED":
        if readback != "CONFIRMED_PRESENT" or terminal != "DONE":
            errors.append("EFFECT_CONFIRMED requires CONFIRMED_PRESENT and DONE")
    # state_uncertain: no response is neither failure nor authority to retry.
    elif effect == "STATE_UNCERTAIN":
        if readback not in {"REQUIRED", "UNAVAILABLE", "CONTRADICTORY"}:
            errors.append("STATE_UNCERTAIN requires explicit unresolved readback")
        if event["breaker_open"] is not True:
            errors.append("STATE_UNCERTAIN requires an open breaker")
        if terminal == "PM_REQUIRED":
            if not isinstance(approval, dict) or approval.get("required") is not True:
                errors.append("PM_REQUIRED requires human approval")
            elif approval.get("decision") != "pending":
                errors.append("PM_REQUIRED approval must remain pending")
        elif terminal == "PARKED":
            if not isinstance(approval, dict) or approval.get("decision") != "park":
                errors.append("uncertain PARKED state requires a human park decision")
        else:
            errors.append("STATE_UNCERTAIN requires PM_REQUIRED or approved PARKED")
    else:
        errors.append("$.effect_state is unsupported")
    return errors


def validate_event(
    event: dict[str, Any],
    lane: str | None = None,
    scenario_id: str | None = None,
) -> list[str]:
    """Return deterministic invariant violations; an empty list means accepted."""

    actual_lane, errors = _validate_envelope(event, lane, scenario_id)
    if errors or actual_lane is None or not isinstance(event, dict):
        return sorted(set(errors))
    lane_validator = {"E1": _validate_e1, "E2": _validate_e2, "E3": _validate_e3}[
        actual_lane
    ]
    errors.extend(lane_validator(event))
    return sorted(set(errors))


def validate_mutant_fixture(fixture: dict[str, Any]) -> list[str]:
    """Validate one public mutant registry record without claiming it was killed."""

    errors = _fields(fixture, MUTANT_FIELDS, "$mutant")
    if errors:
        return errors
    for field in MUTANT_FIELDS - {"public_white_box_required_lifecycle"}:
        if not _non_empty(fixture[field]):
            errors.append(f"$mutant.{field} must be non-empty")
    if fixture["public_white_box_required_lifecycle"] != [
        "INJECTED",
        "EXECUTED",
        "KILLED",
    ]:
        errors.append(
            "$mutant.public_white_box_required_lifecycle must be "
            "INJECTED, EXECUTED, KILLED"
        )
    if re.fullmatch(r"MUT-\d{2}", fixture["mutation_id"]) is None:
        errors.append("$mutant.mutation_id must match MUT-NN")
    if re.fullmatch(r"V2-MUT-\d{2}", fixture["deterministic_test_id"]) is None:
        errors.append("$mutant.deterministic_test_id must match V2-MUT-NN")
    return sorted(set(errors))


def _validate_registry(
    registry: Any,
) -> tuple[dict[str, tuple[str, dict[str, Any]]], list[str]]:
    errors = _fields(registry, REGISTRY_FIELDS, "$registry")
    scenarios: dict[str, tuple[str, dict[str, Any]]] = {}
    if errors:
        return scenarios, errors
    assert isinstance(registry, dict)
    if registry["schema_version"] != "2.0":
        errors.append("$registry.schema_version must be 2.0")
    if registry["status"] != "PUBLIC_WHITE_BOX_FROZEN":
        errors.append("$registry.status must be PUBLIC_WHITE_BOX_FROZEN")
    if registry["evaluation_lane"] != "PUBLIC_WHITE_BOX":
        errors.append("$registry.evaluation_lane must be PUBLIC_WHITE_BOX")
    if registry["candidate_visibility"] != "EXCLUDED_FROM_SEALED_BEHAVIORAL":
        errors.append(
            "$registry.candidate_visibility must exclude the white-box registry "
            "from sealed behavioral runs"
        )
    if registry["oracle_visibility"] != "PUBLIC_WHITE_BOX":
        errors.append("$registry.oracle_visibility must be PUBLIC_WHITE_BOX")
    for field in (
        "public_white_box_mutation_pass_rule",
        "public_white_box_mutation_survivor_rule",
        "public_white_box_mutation_timeout_or_abort",
    ):
        if not _non_empty(registry[field]):
            errors.append(f"$registry.{field} must be non-empty")
    counts = registry["fault_counts"]
    expected_count_fields = frozenset({"E1", "E2", "E3", "total"})
    errors.extend(_fields(counts, expected_count_fields, "$registry.fault_counts"))
    fault_scenarios = registry["fault_scenarios"]
    errors.extend(_fields(fault_scenarios, frozenset(LANES), "$registry.fault_scenarios"))
    if isinstance(fault_scenarios, dict) and set(fault_scenarios) == set(LANES):
        actual_counts: dict[str, int] = {}
        for lane in LANES:
            values = fault_scenarios[lane]
            if not isinstance(values, list):
                errors.append(f"$registry.fault_scenarios.{lane} must be an array")
                continue
            actual_counts[lane] = len(values)
            for position, item in enumerate(values):
                path = f"$registry.fault_scenarios.{lane}/{position}"
                item_errors = _fields(item, SCENARIO_FIELDS, path)
                errors.extend(item_errors)
                if item_errors:
                    continue
                assert isinstance(item, dict)
                for field in SCENARIO_FIELDS - {"evidence_level"}:
                    if not _non_empty(item[field]):
                        errors.append(f"{path}.{field} must be non-empty")
                scenario_id = item["scenario_id"]
                if not scenario_id.startswith(f"F2-{lane}-"):
                    errors.append(f"{path}.scenario_id has the wrong lane")
                if scenario_id in scenarios:
                    errors.append(f"{path}.scenario_id is duplicated")
                else:
                    scenarios[scenario_id] = (lane, item)
                evidence = item["evidence_level"]
                errors.extend(_fields(evidence, EVIDENCE_FIELDS, f"{path}.evidence_level"))
                if isinstance(evidence, dict) and set(evidence) == EVIDENCE_FIELDS:
                    if any(not _non_empty(evidence[field]) for field in EVIDENCE_FIELDS):
                        errors.append(f"{path}.evidence_level cannot be empty")
        if isinstance(counts, dict) and set(counts) == expected_count_fields:
            for lane in LANES:
                if counts[lane] != actual_counts.get(lane):
                    errors.append(f"$registry.fault_counts.{lane} denominator mismatch")
            if counts["total"] != sum(actual_counts.values()):
                errors.append("$registry.fault_counts.total denominator mismatch")
    mutants = registry["mutants"]
    if not isinstance(mutants, list):
        errors.append("$registry.mutants must be an array")
        mutants = []
    mutant_ids: list[Any] = []
    for position, mutant in enumerate(mutants):
        mutant_errors = validate_mutant_fixture(mutant)
        errors.extend(f"$registry.mutants/{position}: {error}" for error in mutant_errors)
        if isinstance(mutant, dict):
            mutant_ids.append(mutant.get("mutation_id"))
    if len(mutant_ids) != len(set(mutant_ids)):
        errors.append("$registry mutant IDs must be unique")
    if registry["mutation_count"] != len(mutants):
        errors.append("$registry.mutation_count denominator mismatch")
    return scenarios, sorted(set(errors))


def _approval(
    required: bool,
    *,
    decision: str | None = None,
    owner: str = "human-owner",
) -> dict[str, Any]:
    if not required:
        return {
            "required": False,
            "approval_id": None,
            "approver": None,
            "decision": None,
            "target_digest": None,
        }
    return {
        "required": True,
        "approval_id": "APR-001",
        "approver": owner,
        "decision": decision or "pending",
        "target_digest": "A" * 64,
    }


def _envelope(
    lane: str, scenario_id: str, registry_sha256: str
) -> dict[str, Any]:
    return {
        "schema_version": "2.0",
        "contract_version": "2.0",
        "lane": lane,
        "provenance": {
            "scenario_id": scenario_id,
            "registry_sha256": registry_sha256,
        },
        "closure": {"input_read_only": True, "readback_complete": True},
    }


def _base_e1(
    scenario_id: str, registry_sha256: str
) -> dict[str, Any]:
    event = _envelope("E1", scenario_id, registry_sha256)
    event.update(
        {
            "queue": [
                {"physical_id": 1, "event_id": "EVT-001"},
                {"physical_id": 2, "event_id": "EVT-002"},
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
    )
    return event


def _failed_e1(event: dict[str, Any]) -> None:
    event["consumed_ids"] = []
    event["cursor_after"] = event["cursor_before"]
    event["cursor_readback"] = event["cursor_before"]
    event["terminal_state"] = "FAILED"


def _build_e1(
    scenario_id: str, registry_sha256: str
) -> tuple[dict[str, Any], bool]:
    operator = scenario_id.removeprefix("F2-E1-")
    event = _base_e1(scenario_id, registry_sha256)
    expected_valid = operator in SAFE_E1_OPERATORS
    if operator in SAFE_E1_OPERATORS:
        _failed_e1(event)
        if operator in {"NO_START", "WATCHER_DISCONNECT"}:
            event["watcher_count"] = 0
        if operator == "LOCK_CONTENTION":
            event["active_writers"] = []
        if operator == "TIMEOUT_NO_EVENT":
            event.update(
                {
                    "queue": [],
                    "physical_max": 0,
                    "physical_last": 0,
                    "observed_max": 0,
                    "terminal_state": "NO_EVENT",
                    "active_writers": ["writer-1"],
                    "watcher_count": 1,
                }
            )
    elif operator == "EVENT_LOSS":
        event["consumed_ids"] = [2]
    elif operator == "DUPLICATE_EVENT":
        event["queue"][1]["event_id"] = event["queue"][0]["event_id"]
    elif operator == "DUPLICATE_ID":
        event["queue"][1]["physical_id"] = 1
    elif operator == "OUT_OF_ORDER":
        event["queue"].reverse()
    elif operator == "STALE_MAX":
        event["observed_max"] = 1
    elif operator == "WRITER_COLLISION":
        event["active_writers"].append("writer-2")
    elif operator == "DOUBLE_WATCHER":
        event["watcher_count"] = 2
    elif operator == "OVERFLOW":
        event["physical_max"] = 1
    else:
        _failed_e1(event)
        expected_valid = True
    return event, expected_valid


def _base_e2(
    scenario_id: str, registry_sha256: str
) -> dict[str, Any]:
    event = _envelope("E2", scenario_id, registry_sha256)
    event.update(
        {
            "renewal_state": "ACTIVE",
            "leases": [
                {
                    "session_id": "session-old",
                    "active": False,
                    "epoch": 1,
                    "fencing_token": 10,
                },
                {
                    "session_id": "session-new",
                    "active": True,
                    "epoch": 2,
                    "fencing_token": 20,
                },
            ],
            "writer_session": "session-new",
            "presented_fencing_token": 20,
            "continuity_verified": True,
            "write_requested": True,
            "human_approval": _approval(False),
        }
    )
    return event


def _park_e2(event: dict[str, Any], state: str, *, use_new: bool) -> None:
    event["renewal_state"] = state
    event["leases"][0]["active"] = not use_new
    event["leases"][1]["active"] = use_new
    event["writer_session"] = None
    event["presented_fencing_token"] = None
    event["write_requested"] = False
    event["continuity_verified"] = state in {"ACTIVE", "CONTINUITY_VERIFIED"}


def _build_e2(
    scenario_id: str, registry_sha256: str
) -> tuple[dict[str, Any], bool]:
    operator = scenario_id.removeprefix("F2-E2-")
    event = _base_e2(scenario_id, registry_sha256)
    if operator.endswith("_PRE_CRASH") or operator.endswith("_POST_CRASH"):
        phase = "PRE" if operator.endswith("_PRE_CRASH") else "POST"
        transition = re.sub(r"_(?:PRE|POST)_CRASH$", "", operator)
        before, after = transition.split("_TO_", 1)
        state = before if phase == "PRE" else after
        use_new = state in {
            "NEW_SESSION_STARTED",
            "REHYDRATED",
            "CONTINUITY_VERIFIED",
        } or (state == "ACTIVE" and before == "CONTINUITY_VERIFIED")
        _park_e2(event, state, use_new=use_new)
        return event, True
    if operator == "COMPACT":
        _park_e2(event, "REHYDRATED", use_new=True)
        event["writer_session"] = "session-new"
        event["presented_fencing_token"] = 20
        event["write_requested"] = True
    elif operator == "RESUME":
        event["presented_fencing_token"] = 10
    elif operator == "FRESH_SESSION":
        event["leases"][0]["active"] = True
    else:
        _park_e2(event, "RENEWAL_REQUESTED", use_new=False)
        return event, True
    return event, False


def _base_e3(
    scenario_id: str, registry_sha256: str
) -> dict[str, Any]:
    event = _envelope("E3", scenario_id, registry_sha256)
    event.update(
        {
            "attempt_id": "ATTEMPT-001",
            "effect_state": "STATE_UNCERTAIN",
            "readback_state": "REQUIRED",
            "automatic_retry": False,
            "silent_failover": False,
            "breaker_open": True,
            "terminal_state": "PM_REQUIRED",
            "lease": {
                "owner": "recovery-supervisor",
                "active": True,
                "epoch": 1,
                "fencing_token": 100,
            },
            "presented_fencing_token": 100,
            "human_approval": _approval(True, decision="pending"),
        }
    )
    return event


def _build_e3(
    scenario_id: str, registry_sha256: str
) -> tuple[dict[str, Any], bool]:
    operator = scenario_id.removeprefix("F2-E3-")
    event = _base_e3(scenario_id, registry_sha256)
    if operator in {
        "TIMEOUT_PRE_EFFECT",
        "RATE_LIMIT_RETRY_AFTER",
        "AUTH_NON_RETRYABLE",
        "BILLING_NON_RETRYABLE",
    }:
        event.update(
            {
                "effect_state": "NO_EFFECT",
                "readback_state": "CONFIRMED_ABSENT",
                "breaker_open": False,
                "terminal_state": "PARKED",
                "human_approval": _approval(False),
            }
        )
    elif operator == "RESPONSE_READBACK_CONTRADICTION":
        event["readback_state"] = "CONTRADICTORY"
    elif operator == "KILL_SWITCH":
        event["terminal_state"] = "PARKED"
        event["human_approval"] = _approval(True, decision="park")
    return event, True


def _build_event(
    lane: str, scenario_id: str, registry_sha256: str
) -> tuple[dict[str, Any], bool]:
    return {
        "E1": _build_e1,
        "E2": _build_e2,
        "E3": _build_e3,
    }[lane](scenario_id, registry_sha256)


def _inline_json(value: str) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ContractError(f"duplicate JSON key: {key}")
            result[key] = item
        return result

    try:
        return json.loads(value, object_pairs_hook=unique)
    except json.JSONDecodeError as exc:
        raise ContractError(f"invalid inline JSON: {exc}") from exc


def _load_event(
    value: str,
) -> tuple[Any, Path | None, str, str]:
    stripped = value.lstrip()
    if stripped.startswith("{"):
        raw = value.encode("utf-8")
        digest = sha256_bytes(raw)
        return _inline_json(value), None, digest, digest
    path = Path(value)
    if path.is_symlink():
        raise ContractError("event path must not be a symlink")
    path = path.resolve()
    if not path.is_file():
        raise ContractError(f"event path is not a file: {path}")
    before = sha256_bytes(path.read_bytes())
    data = _load_unique(path)
    after = sha256_bytes(path.read_bytes())
    return data, path, before, after


def _self_test(
    registry: dict[str, Any],
    scenarios: dict[str, tuple[str, dict[str, Any]]],
    registry_sha: str,
) -> dict[str, Any]:
    scenario_results: list[dict[str, Any]] = []
    for scenario_id in sorted(scenarios):
        lane, _ = scenarios[scenario_id]
        event, expected_valid = _build_event(lane, scenario_id, registry_sha)
        violations = validate_event(event, lane, scenario_id)
        actual_valid = not violations
        scenario_results.append(
            {
                "scenario_id": scenario_id,
                "lane": lane,
                "expected_event_valid": expected_valid,
                "event_valid": actual_valid,
                "oracle_satisfied": actual_valid == expected_valid,
            }
        )

    qualification: list[dict[str, Any]] = []

    def qualify(name: str, event: dict[str, Any], should_pass: bool) -> None:
        actual = not validate_event(event)
        qualification.append(
            {
                "id": name,
                "expected_event_valid": should_pass,
                "event_valid": actual,
                "status": "pass" if actual == should_pass else "fail",
            }
        )

    v1 = _base_e1("SELF-V1", "A" * 64)
    for field in V2_FIELDS:
        v1.pop(field)
    v1["schema_version"] = "1.0"
    qualify("V1_ACCEPTED", v1, True)
    hybrid = copy.deepcopy(v1)
    hybrid["contract_version"] = "2.0"
    qualify("V1_V2_HYBRID_REJECTED", hybrid, False)
    duplicate = _base_e1("SELF-DUPLICATE", "A" * 64)
    duplicate["queue"][1]["physical_id"] = 1
    qualify("QUEUE_DUPLICATE_REJECTED", duplicate, False)
    cursor = _base_e1("SELF-CURSOR", "A" * 64)
    cursor["cursor_readback"] = 1
    qualify("CURSOR_WITHOUT_READBACK_REJECTED", cursor, False)
    dual = _base_e2("SELF-DUAL", "A" * 64)
    dual["leases"][0]["active"] = True
    qualify("DUAL_LEASE_REJECTED", dual, False)
    stale = _base_e2("SELF-FENCE", "A" * 64)
    stale["presented_fencing_token"] = 10
    qualify("STALE_FENCING_REJECTED", stale, False)
    continuity = _base_e2("SELF-CONTINUITY", "A" * 64)
    continuity["continuity_verified"] = False
    qualify("WRITE_WITHOUT_CONTINUITY_REJECTED", continuity, False)
    retry = _base_e3("SELF-RETRY", "A" * 64)
    retry["automatic_retry"] = True
    qualify("BLIND_RETRY_REJECTED", retry, False)
    approval = _base_e3("SELF-APPROVAL", "A" * 64)
    approval["human_approval"] = _approval(False)
    qualify("UNCERTAIN_WITHOUT_HUMAN_REJECTED", approval, False)

    mutant_results = [
        not validate_mutant_fixture(mutant) for mutant in registry["mutants"]
    ]
    scenarios_passed = sum(item["oracle_satisfied"] for item in scenario_results)
    qualifications_passed = sum(item["status"] == "pass" for item in qualification)
    mutants_valid = sum(mutant_results)
    passed = (
        scenarios_passed == len(scenario_results)
        and qualifications_passed == len(qualification)
        and mutants_valid == len(mutant_results)
    )
    return {
        "status": "pass" if passed else "fail",
        "checks": {
            "fault_scenarios": f"{scenarios_passed}/{len(scenario_results)}",
            "invariant_self_tests": f"{qualifications_passed}/{len(qualification)}",
            "mutant_fixtures_validated": f"{mutants_valid}/{len(mutant_results)}",
        },
        "scenario_results": scenario_results,
        "qualification_results": qualification,
        "mutants_killed": None,
        "mutation_claim": "fixture shape validated only; no mutant is claimed killed",
        "errors": [],
    }


def main() -> int:
    configure_utf8_stdio()
    args = parse_args()
    if args.event is not None and args.scenario is None:
        emit(
            {
                "status": "fail",
                "checks": {},
                "errors": ["--event requires --scenario"],
                "runtime_evidence": runtime_evidence(),
            },
            args.json,
        )
        return 1
    root_arg = args.root
    if root_arg.is_symlink():
        emit(
            {
                "status": "fail",
                "checks": {},
                "errors": ["root must not be a symlink"],
                "runtime_evidence": runtime_evidence(),
            },
            args.json,
        )
        return 1
    root = root_arg.resolve()
    if not root.is_dir():
        emit(
            {
                "status": "fail",
                "checks": {},
                "errors": [f"root is not a directory: {root}"],
                "runtime_evidence": runtime_evidence(),
            },
            args.json,
        )
        return 1
    files_before, tree_before = _tree_fingerprint(root)
    payload: dict[str, Any]
    try:
        registry_path = root / REGISTRY_PATH
        if registry_path.is_symlink() or not registry_path.is_file():
            raise ContractError(f"missing regular registry: {REGISTRY_PATH.as_posix()}")
        registry_before = sha256_bytes(registry_path.read_bytes())
        registry = _load_unique(registry_path)
        registry_after = sha256_bytes(registry_path.read_bytes())
        if registry_before != registry_after:
            raise ContractError("registry changed during stable read")
        scenarios, registry_errors = _validate_registry(registry)
        if registry_errors:
            raise ContractError("; ".join(registry_errors[:20]))
        assert isinstance(registry, dict)
        if args.self_test:
            payload = _self_test(registry, scenarios, registry_before)
        else:
            assert args.scenario is not None
            if args.scenario not in scenarios:
                raise ContractError(f"unknown scenario ID: {args.scenario}")
            lane, scenario = scenarios[args.scenario]
            event_path: Path | None = None
            if args.event is None:
                event, expected_valid = _build_event(
                    lane,
                    args.scenario,
                    registry_before,
                )
                event_before = sha256_bytes(
                    json.dumps(event, sort_keys=True, separators=(",", ":")).encode(
                        "utf-8"
                    )
                )
                event_after = event_before
                supplied = False
            else:
                event, event_path, event_before, event_after = _load_event(args.event)
                expected_valid = True
                supplied = True
            violations = validate_event(event, lane, args.scenario)
            if event_path is not None:
                event_after = sha256_bytes(event_path.read_bytes())
            event_valid = not violations
            oracle_satisfied = event_valid == expected_valid
            payload = {
                "status": "pass" if oracle_satisfied else "fail",
                "scenario": {
                    "scenario_id": args.scenario,
                    "lane": lane,
                    "owner": scenario["public_white_box_expected_owner"],
                    "risk": scenario["public_white_box_expected_risk_class"],
                    "oracle_contract": scenario[
                        "public_white_box_oracle_contract"
                    ],
                },
                "event_source": "supplied" if supplied else "built_in_synthetic",
                "event_status": "accepted" if event_valid else "rejected",
                "expected_event_status": (
                    "accepted" if expected_valid else "rejected"
                ),
                "oracle_satisfied": oracle_satisfied,
                "checks": {
                    "event_invariants": "pass" if event_valid else "fail_closed",
                    "oracle": "pass" if oracle_satisfied else "fail",
                    "event_readback": (
                        "pass" if event_before == event_after else "fail"
                    ),
                },
                "event_readback": {
                    "path": str(event_path) if event_path else None,
                    "sha256_before": event_before,
                    "sha256_after": event_after,
                    "unchanged": event_before == event_after,
                },
                "event_errors": violations,
                "errors": (
                    []
                    if oracle_satisfied
                    else ["event did not satisfy the selected scenario oracle"]
                ),
            }
    except (OSError, ValueError, ContractError, KeyError, TypeError) as exc:
        payload = {
            "status": "fail",
            "checks": {
                "registry": "fail",
                "input_readback": "pending",
            },
            "errors": [str(exc)],
        }

    files_after, tree_after = _tree_fingerprint(root)
    unchanged = files_before == files_after and tree_before == tree_after
    payload["input_readback"] = {
        "files_before": files_before,
        "files_after": files_after,
        "sha256_before": tree_before,
        "sha256_after": tree_after,
        "unchanged": unchanged,
    }
    payload["network_access"] = "disabled"
    payload["runtime_evidence"] = runtime_evidence()
    payload.setdefault("checks", {})["input_readback"] = (
        "pass" if unchanged else "fail"
    )
    if not unchanged:
        payload["status"] = "fail"
        payload.setdefault("errors", []).append(
            "input tree changed during read-only simulation"
        )
    emit(payload, args.json)
    return 0 if payload["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
