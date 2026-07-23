#!/usr/bin/env python3
"""Compare frozen baseline and candidate runs without rewriting raw outputs."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from _common import ContractError, emit, sha256_file
from eval_corpus_check import (
    _load_unique as load_unique_output,
    forbidden_material_paths,
    validate_v2_public_profile,
)


SCALAR_FIELDS = ["status", "scope_decision", "architecture_mode", "autonomy_level", "risk_class"]
PROVENANCE_FIELDS = ["sources_read", "sections_consulted", "model_synthesis", "limits"]
SHA256_RE = re.compile(r"[0-9A-Fa-f]{64}")
NON_PUBLIC_OUTPUT_MARKERS = (
    "ORIGINATING_PROJECT_ONLY",
    "INTERNAL_WORKSHOP_ONLY",
)
NON_PUBLIC_OUTPUT_PATTERNS = tuple(
    re.compile(re.escape(marker), re.I) for marker in NON_PUBLIC_OUTPUT_MARKERS
) + (
    re.compile("PTE" + "100X", re.I),
    re.compile("Metodo" + r"\s+" + "GC", re.I),
    re.compile("GC-" + "EVID", re.I),
    re.compile(r"\bR-" + "002" + r"\b", re.I),
    re.compile("Source " + "IDs:", re.I),
    re.compile(r"\bGC-" + r"V2-C\d+\b", re.I),
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
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path, help="Explicit candidate skill root")
    parser.add_argument("baseline", type=Path, help="Frozen baseline JSON")
    parser.add_argument("candidate", type=Path, help="Frozen candidate JSON")
    parser.add_argument("--cases", required=True, help="Comma-separated case IDs")
    parser.add_argument(
        "--profile",
        choices=("v1", "v2"),
        type=str.lower,
        default="v2",
        help="Comparison profile; defaults to public, structural-only V2",
    )
    parser.add_argument(
        "--structural-only",
        action="store_true",
        help="Compare only the public V2 envelope and identifiers",
    )
    parser.add_argument(
        "--candidate-freeze-sha256",
        "--candidate-freeze-anchor",
        dest="candidate_freeze_sha256",
        help="Externally recorded SHA-256 of the frozen candidate output file",
    )
    parser.add_argument(
        "--verifier-reveal-sha256",
        "--verifier-reveal",
        dest="verifier_reveal_sha256",
        help=(
            "Opaque SHA-256 attestation for an externally held verifier reveal; "
            "the reveal content is never opened"
        ),
    )
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def results_by_id(path: Path) -> dict[str, dict[str, Any]]:
    raw = load_unique_output(path.resolve())
    values = raw.get("results", []) if isinstance(raw, dict) else raw
    if not isinstance(values, list):
        raise ContractError(f"invalid result list: {path}")
    result: dict[str, dict[str, Any]] = {}
    for item in values:
        if not isinstance(item, dict) or not item.get("case_id"):
            raise ContractError(f"invalid result entry: {path}")
        if item["case_id"] in result:
            raise ContractError(f"duplicate result {item['case_id']}: {path}")
        result[item["case_id"]] = item
    return result


def run_metrics(
    run: dict[str, dict[str, Any]],
    rubric: dict[str, dict[str, Any]],
    case_ids: list[str],
) -> dict[str, Any]:
    rows = []
    scalar_matches = 0
    hard_matches = 0
    provenance_present = 0
    total_bytes = 0
    non_public_markers: list[str] = []
    for case_id in case_ids:
        actual = run.get(case_id)
        if actual is None:
            raise ContractError(f"missing output: {case_id}")
        expected = rubric[case_id]["expected"]
        matched = {
            field: actual.get(field) in rubric[case_id].get("allowed", {}).get(field, [expected[field]])
            for field in SCALAR_FIELDS
        }
        scalar_matches += sum(matched.values())
        hard_matches += sum(matched[field] for field in ("scope_decision", "architecture_mode", "risk_class"))
        provenance = actual.get("provenance", {}) if isinstance(actual.get("provenance"), dict) else {}
        present = sum(bool(provenance.get(field) or field == "limits" and provenance.get(field) == []) for field in PROVENANCE_FIELDS)
        provenance_present += present
        encoded = json.dumps(actual, sort_keys=True, ensure_ascii=False).encode("utf-8")
        total_bytes += len(encoded)
        decoded = encoded.decode("utf-8")
        if any(pattern.search(decoded) for pattern in NON_PUBLIC_OUTPUT_PATTERNS):
            non_public_markers.append(case_id)
        rows.append(
            {
                "case_id": case_id,
                "scalar_matches": sum(matched.values()),
                "scalar_total": len(SCALAR_FIELDS),
                "mismatches": [field for field, passed in matched.items() if not passed],
                "provenance_fields": present,
                "controls": len(actual.get("controls", [])),
                "artifacts": len(actual.get("artifacts", [])),
                "sources": len(provenance.get("sources_read", [])),
                "bytes": len(encoded),
            }
        )
    return {
        "scalar_matches": scalar_matches,
        "scalar_total": len(case_ids) * len(SCALAR_FIELDS),
        "hard_matches": hard_matches,
        "hard_total": len(case_ids) * 3,
        "provenance_fields": provenance_present,
        "provenance_total": len(case_ids) * len(PROVENANCE_FIELDS),
        "bytes": total_bytes,
        "non_public_marker_cases": non_public_markers,
        "cases": rows,
    }


def _normalized_digest(value: str | None) -> str | None:
    if value is None or SHA256_RE.fullmatch(value) is None:
        return None
    return value.upper()


def _v2_validator(schema: dict[str, Any]) -> Any:
    try:
        import jsonschema
    except ImportError as exc:
        raise ContractError("jsonschema is required for V2 output validation") from exc
    wrapper = {
        "$schema": schema["$schema"],
        "$ref": "#/$defs/v2BehavioralOutput",
        "$defs": schema["$defs"],
    }
    jsonschema.Draft202012Validator.check_schema(wrapper)
    return jsonschema.Draft202012Validator(wrapper)


def _v2_results_by_id(path: Path) -> dict[str, dict[str, Any]]:
    raw = load_unique_output(path.resolve())
    material = forbidden_material_paths(raw)
    if material:
        raise ContractError(
            f"V2 output contains forbidden answer/truth material keys: {material}"
        )
    values = raw.get("results", []) if isinstance(raw, dict) else raw
    if not isinstance(values, list):
        raise ContractError(f"invalid V2 result list: {path}")
    result: dict[str, dict[str, Any]] = {}
    attempts: set[str] = set()
    for item in values:
        if not isinstance(item, dict) or not item.get("case_id"):
            raise ContractError(f"invalid V2 result entry: {path}")
        case_id = item["case_id"]
        if case_id in result:
            raise ContractError(f"duplicate V2 result {case_id}: {path}")
        attempt_id = item.get("attempt_id")
        if isinstance(attempt_id, str) and attempt_id in attempts:
            raise ContractError(f"duplicate V2 attempt_id {attempt_id}: {path}")
        if isinstance(attempt_id, str):
            attempts.add(attempt_id)
        result[case_id] = item
    return result


def _v2_structural_metrics(
    run: dict[str, dict[str, Any]],
    public_cases: dict[str, dict[str, Any]],
    case_ids: list[str],
    validator: Any,
) -> tuple[dict[str, Any], list[str]]:
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    total_bytes = 0
    hard_decisions = 0
    for case_id in case_ids:
        actual = run.get(case_id)
        if actual is None:
            errors.append(f"missing V2 output: {case_id}")
            rows.append(
                {
                    "case_id": case_id,
                    "structural_status": "fail",
                    "errors": ["output missing"],
                }
            )
            continue
        schema_errors = sorted(
            validator.iter_errors(actual), key=lambda item: list(item.path)
        )
        decisions = actual.get("hard_decisions", [])
        actual_ids = (
            [
                item.get("decision_id")
                for item in decisions
                if isinstance(item, dict)
            ]
            if isinstance(decisions, list)
            else []
        )
        expected_ids = public_cases[case_id]["hard_check_ids"]
        row_errors = [error.message for error in schema_errors[:5]]
        if actual_ids != expected_ids:
            row_errors.append("hard_decision_ids do not match the public case")
        if (
            actual.get("candidate_state") != "CANDIDATE_UNSCORED"
            or actual.get("scoring_state")
            != "BLOCKED_UNTIL_CANDIDATE_FREEZE_AND_REVEAL"
        ):
            row_errors.append("candidate is not in the public unscored state")
        if actual.get("external_effects_performed") is not False:
            row_errors.append("external_effects_performed must be false")
        encoded = json.dumps(
            actual,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        total_bytes += len(encoded)
        hard_decisions += len(actual_ids)
        if row_errors:
            errors.append(f"{case_id}: " + "; ".join(row_errors))
        rows.append(
            {
                "case_id": case_id,
                "structural_status": "fail" if row_errors else "pass",
                "hard_decisions": len(actual_ids),
                "bytes": len(encoded),
                "errors": row_errors,
            }
        )
    return (
        {
            "structurally_valid_cases": sum(
                item["structural_status"] == "pass" for item in rows
            ),
            "total_cases": len(rows),
            "hard_decisions": hard_decisions,
            "expected_hard_decisions": len(case_ids) * 3,
            "bytes": total_bytes,
            "cases": rows,
        },
        errors,
    )


def _run_v2(args: argparse.Namespace) -> int:
    errors: list[str] = []
    baseline_metrics: dict[str, Any] = {}
    candidate_metrics: dict[str, Any] = {}
    candidate_sha256: str | None = None
    try:
        root = args.root.resolve()
        profile, _profile_checks, profile_errors = validate_v2_public_profile(root)
        if profile_errors:
            raise ContractError(
                "invalid public V2 profile: " + "; ".join(profile_errors[:12])
            )
        public_cases = {
            item["case_id"]: item for item in profile["inputs"].get("cases", [])
        }
        case_ids = [item.strip() for item in args.cases.split(",") if item.strip()]
        if (
            not case_ids
            or len(case_ids) != len(set(case_ids))
            or any(item not in public_cases for item in case_ids)
        ):
            raise ContractError(f"invalid V2 case set: {case_ids}")
        schema = load_unique_output(
            root / "evals" / "behavioral_output.schema.json"
        )
        if not isinstance(schema, dict):
            raise ContractError("behavioral output schema must be an object")
        validator = _v2_validator(schema)
        baseline = _v2_results_by_id(args.baseline)
        candidate = _v2_results_by_id(args.candidate)
        baseline_metrics, baseline_errors = _v2_structural_metrics(
            baseline, public_cases, case_ids, validator
        )
        candidate_metrics, candidate_errors = _v2_structural_metrics(
            candidate, public_cases, case_ids, validator
        )
        errors.extend(f"baseline: {item}" for item in baseline_errors)
        errors.extend(f"candidate: {item}" for item in candidate_errors)
        candidate_sha256 = sha256_file(args.candidate.resolve())
    except (OSError, TypeError, ValueError, KeyError, ContractError) as exc:
        errors.append(str(exc))

    structural_ok = (
        not errors
        and bool(baseline_metrics)
        and bool(candidate_metrics)
        and baseline_metrics.get("structurally_valid_cases")
        == baseline_metrics.get("total_cases")
        and candidate_metrics.get("structurally_valid_cases")
        == candidate_metrics.get("total_cases")
    )
    freeze_digest = _normalized_digest(args.candidate_freeze_sha256)
    reveal_digest = _normalized_digest(args.verifier_reveal_sha256)
    freeze_bound = (
        candidate_sha256 is not None
        and freeze_digest is not None
        and freeze_digest == candidate_sha256
    )
    reveal_attested = reveal_digest is not None
    if args.structural_only:
        status = "pass" if structural_ok else "fail"
        blockers: list[str] = []
    else:
        status = "fail" if not structural_ok else "blocked"
        blockers = []
        if not freeze_bound:
            blockers.append(
                "candidate output is not bound to the supplied freeze SHA-256"
            )
        if not reveal_attested:
            blockers.append("external verifier reveal SHA-256 attestation is absent")
        blockers.append(
            "semantic V2 comparison is external-only; this public tool has no answer material"
        )
    payload = {
        "status": status,
        "profile": "v2-public-oracle-free",
        "validation_scope": "structural-only",
        "baseline": baseline_metrics,
        "candidate": candidate_metrics,
        "delta_bytes": (
            candidate_metrics.get("bytes", 0) - baseline_metrics.get("bytes", 0)
        ),
        "candidate_output_sha256": candidate_sha256,
        "candidate_freeze_bound": freeze_bound,
        "verifier_reveal_attested": reveal_attested,
        "verifier_reveal_content_read": False,
        "semantic_comparison_performed": False,
        "semantic_scoring_state": (
            "READY_FOR_EXTERNAL_VERIFIER"
            if freeze_bound and reveal_attested
            else "BLOCKED_UNTIL_CANDIDATE_FREEZE_AND_REVEAL"
        ),
        "blocking_reasons": blockers,
        "errors": errors,
        "runtime_evidence": runtime_evidence(),
    }
    emit(payload, args.json)
    if args.structural_only:
        return 0 if structural_ok else 1
    return 1


def main() -> int:
    configure_utf8_stdio()
    args = parse_args()
    if args.profile == "v2":
        return _run_v2(args)
    errors: list[str] = []
    baseline_metrics: dict[str, Any] = {}
    candidate_metrics: dict[str, Any] = {}
    try:
        rubric_doc = load_unique_output(
            args.root.resolve() / "evals" / "behavioral_rubric.yaml"
        )
        rubric = {item["id"]: item for item in rubric_doc.get("cases", [])}
        case_ids = [item.strip() for item in args.cases.split(",") if item.strip()]
        if not case_ids or len(case_ids) != len(set(case_ids)) or any(item not in rubric for item in case_ids):
            raise ContractError(f"invalid case set: {case_ids}")
        baseline = results_by_id(args.baseline)
        candidate = results_by_id(args.candidate)
        baseline_metrics = run_metrics(baseline, rubric, case_ids)
        candidate_metrics = run_metrics(candidate, rubric, case_ids)
        if candidate_metrics["hard_matches"] != candidate_metrics["hard_total"]:
            errors.append("candidate has hard decision mismatches")
        if candidate_metrics["scalar_matches"] < baseline_metrics["scalar_matches"]:
            errors.append("candidate scalar accuracy regressed against baseline")
        if candidate_metrics["non_public_marker_cases"]:
            errors.append("candidate contains non-public output markers")
    except (OSError, ValueError, KeyError, ContractError) as exc:
        errors.append(str(exc))

    payload = {
        "status": "pass" if not errors else "fail",
        "baseline": baseline_metrics,
        "candidate": candidate_metrics,
        "delta_scalar_matches": (
            candidate_metrics.get("scalar_matches", 0) - baseline_metrics.get("scalar_matches", 0)
        ),
        "errors": errors,
        "runtime_evidence": runtime_evidence(),
    }
    emit(payload, args.json)
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
