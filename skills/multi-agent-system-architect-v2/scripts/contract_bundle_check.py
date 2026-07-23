#!/usr/bin/env python3
"""Validate the versioned contract bundle and resolve its reference graph.

The checker is deliberately read-only.  It accepts an explicit skill root, reads
only local files, validates every indexed artifact against both its exact
version schema and its V1/V2 dispatcher, then resolves declared contract
references as a closed acyclic graph.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

sys.dont_write_bytecode = True

from _common import ContractError, emit  # noqa: E402


SUPPORTED_VERSIONS = frozenset({"1.0", "2.0"})
INDEX_DEFAULT = "assets/schemas/schema_index.json"
MUTATION_REGISTRY = "evals/v2_fault_injection.yaml"
PACKAGE_ROOT = Path(__file__).resolve().parents[1]
MUTATION_CACHE_PARTS = frozenset(
    {".pytest_cache", "__pycache__", ".mypy_cache", ".ruff_cache"}
)
MUTATION_BYTECODE_SUFFIXES = frozenset({".pyc", ".pyo"})

# Public, hash-bound execution map.  A conceptual locator is never silently
# remapped: every registry target names its operational file, concrete anchor,
# production consumer, and deterministic oracle explicitly.  The SHA-256 binds
# the map to the frozen F5 subject bytes; a changed subject is a hard failure.
MUTATION_EXECUTION_MAP: dict[str, dict[str, str]] = {
    "MUT-01": {
        "frozen_locator": "templates/REQUIREMENTS.yaml#/authority/human_sovereign",
        "operational_path": "templates/REQUIREMENTS.yaml",
        "operational_anchor": "authority.human_sovereign",
        "rationale": "The registry JSON pointer is a literal YAML mapping path.",
        "consumer": "contract_bundle_check.py::validate_governed_contract_tree",
        "oracle_code": "HUMAN_SOVEREIGN_REQUIRED",
        "operational_sha256": "BB468C3D85D1DED0F736ED62B53DA3D3C827E32F4EEE35A22C84E061F6217E99",
    },
    "MUT-02": {
        "frozen_locator": "templates/AUTONOMY_RISK_ENVELOPE.yaml#/approval/actor_type",
        "operational_path": "templates/AUTONOMY_RISK_ENVELOPE.yaml",
        "operational_anchor": "approvals.approvers[].actor_type",
        "rationale": "The singular conceptual approval actor maps explicitly to the V2 approver list.",
        "consumer": "contract_bundle_check.py::validate_governed_contract_tree",
        "oracle_code": "MODEL_SELF_APPROVAL_FORBIDDEN",
        "operational_sha256": "B349AB975168166B8A47C0CC948E045A81B56DDB49F8B913EB373B535787204B",
    },
    "MUT-03": {
        "frozen_locator": "templates/TOOL_CONTRACT.yaml#/approval_binding",
        "operational_path": "templates/TOOL_CONTRACT.yaml",
        "operational_anchor": "approval_policy.{class,draft_tool,commit_tool}+allowed_targets",
        "rationale": "Exact action and target binding is represented by these V2 fields together.",
        "consumer": "contract_bundle_check.py::validate_governed_contract_tree",
        "oracle_code": "APPROVAL_BINDING_REQUIRED",
        "operational_sha256": "00266D7D383AA1AE8E49460578E78B3B271B7F4C74ECEC19E7FFE19D3A40F51A",
    },
    "MUT-04": {
        "frozen_locator": "templates/AUTONOMY_RISK_ENVELOPE.yaml#/approval/expires_at",
        "operational_path": "templates/AUTONOMY_RISK_ENVELOPE.yaml",
        "operational_anchor": "approvals.expiry_seconds",
        "rationale": "V2 stores approval lifetime as a positive duration rather than an absolute timestamp.",
        "consumer": "contract_bundle_check.py::validate_governed_contract_tree",
        "oracle_code": "APPROVAL_EXPIRY_REQUIRED",
        "operational_sha256": "B349AB975168166B8A47C0CC948E045A81B56DDB49F8B913EB373B535787204B",
    },
    "MUT-05": {
        "frozen_locator": "templates/AUTONOMY_RISK_ENVELOPE.yaml#/risk/R4",
        "operational_path": "templates/AUTONOMY_RISK_ENVELOPE.yaml",
        "operational_anchor": "classification.risk+inherited_risks+approvals.required_for",
        "rationale": "The downgrade decision is the relation between inherited R4, current risk, and its human gate.",
        "consumer": "contract_bundle_check.py::validate_governed_contract_tree",
        "oracle_code": "R4_DOWNGRADE_REQUIRES_HUMAN_DECISION",
        "operational_sha256": "B349AB975168166B8A47C0CC948E045A81B56DDB49F8B913EB373B535787204B",
    },
    "MUT-06": {
        "frozen_locator": "templates/RUN_MANIFEST.yaml#/role_inversions",
        "operational_path": "templates/RUN_MANIFEST.yaml",
        "operational_anchor": "trace.spans_recorded+human_interventions",
        "rationale": "Executed role inversion and its ledger entry are represented on separate V2 audit surfaces.",
        "consumer": "contract_bundle_check.py::validate_governed_contract_tree",
        "oracle_code": "ROLE_INVERSION_LEDGER_REQUIRED",
        "operational_sha256": "EBD65F0892A7C3DC8A57D9838590730701C1B2999D200A8BC835C26FA51E642B",
    },
    "MUT-07": {
        "frozen_locator": "templates/AGENT_HAT.yaml#/independence",
        "operational_path": "templates/AGENT_HAT.yaml",
        "operational_anchor": "responsibility.roles.{producer,verifier}",
        "rationale": "Independence is falsified by equality of the explicit producer and verifier roles.",
        "consumer": "contract_bundle_check.py::validate_governed_contract_tree",
        "oracle_code": "VERIFIER_INDEPENDENCE_REQUIRED",
        "operational_sha256": "8DF7E2874E2B00F5B127F16018384C125D690FB1EF8856D790DDA2186BB24DE2",
    },
    "MUT-08": {
        "frozen_locator": "templates/ACCEPTANCE_PLAN.md#Evidence hierarchy",
        "operational_path": "templates/ACCEPTANCE_PLAN.md",
        "operational_anchor": "semantic consensus-versus-evidence clauses",
        "rationale": "The production consumer rejects affirmative consensus-as-proof language while accepting explicit prohibitions and safe paraphrases.",
        "consumer": "contract_bundle_check.py::validate_governed_contract_tree",
        "oracle_code": "EVIDENCE_OUTRANKS_CONSENSUS",
        "operational_sha256": "D586FEFD3F869D060188F000EE698DE3FCA6518B7CBF6ECD108B4B8218AF4919",
    },
    "MUT-09": {
        "frozen_locator": "references/10_verifier_playbook.md#Shared relay",
        "operational_path": "references/10_verifier_playbook.md",
        "operational_anchor": "semantic event-hint and physical-MAX authority clauses",
        "rationale": "The consumer requires physical MAX to remain authoritative, rejects reversed authority, and accepts equivalent safe wording.",
        "consumer": "contract_bundle_check.py::validate_governed_contract_tree",
        "oracle_code": "PHYSICAL_MAX_AUTHORITATIVE",
        "operational_sha256": "68BB236BCAAC4035A01C067ED69247B7CD81F6C92B83A907DEE6F347F8373515",
    },
    "MUT-10": {
        "frozen_locator": "scripts/gc_state_simulator.py#relay_unique_id",
        "operational_path": "scripts/gc_state_simulator.py",
        "operational_anchor": "_validate_e1 physical_ids uniqueness predicate",
        "rationale": "The code predicate is mutated in an isolated copy and the public invariant self-test executes it.",
        "consumer": "gc_state_simulator.py::_self_test",
        "oracle_code": "QUEUE_DUPLICATE_REJECTED",
        "operational_sha256": "A0F5F201B44E4C67345AA7EED49CEF45FF754C613F05A98FF7ABAFEBE44B0B33",
    },
    "MUT-11": {
        "frozen_locator": "scripts/gc_state_simulator.py#relay_order",
        "operational_path": "scripts/gc_state_simulator.py",
        "operational_anchor": "_validate_e1 physical_ids order predicate",
        "rationale": "The code predicate is mutated in an isolated copy and the public scenario oracle executes it.",
        "consumer": "gc_state_simulator.py::_self_test",
        "oracle_code": "QUEUE_ORDER_REJECTED",
        "operational_sha256": "A0F5F201B44E4C67345AA7EED49CEF45FF754C613F05A98FF7ABAFEBE44B0B33",
    },
    "MUT-12": {
        "frozen_locator": "scripts/gc_state_simulator.py#cursor_readback",
        "operational_path": "scripts/gc_state_simulator.py",
        "operational_anchor": "_validate_e1 cursor_after/cursor_readback predicate",
        "rationale": "The exact cursor predicate is mutated and exercised by CURSOR_WITHOUT_READBACK_REJECTED.",
        "consumer": "gc_state_simulator.py::_self_test",
        "oracle_code": "CURSOR_WITHOUT_READBACK_REJECTED",
        "operational_sha256": "A0F5F201B44E4C67345AA7EED49CEF45FF754C613F05A98FF7ABAFEBE44B0B33",
    },
    "MUT-13": {
        "frozen_locator": "scripts/gc_state_simulator.py#writer_lease",
        "operational_path": "scripts/gc_state_simulator.py",
        "operational_anchor": "_validate_e2 active lease cardinality predicate",
        "rationale": "The exact active-writer predicate is mutated and exercised by DUAL_LEASE_REJECTED.",
        "consumer": "gc_state_simulator.py::_self_test",
        "oracle_code": "DUAL_LEASE_REJECTED",
        "operational_sha256": "A0F5F201B44E4C67345AA7EED49CEF45FF754C613F05A98FF7ABAFEBE44B0B33",
    },
    "MUT-14": {
        "frozen_locator": "scripts/gc_state_simulator.py#renewal_quiz",
        "operational_path": "scripts/gc_state_simulator.py",
        "operational_anchor": "_validate_e2 continuity predicates",
        "rationale": "Both write-time and ACTIVE-state continuity checks form one anchored invariant block.",
        "consumer": "gc_state_simulator.py::_self_test",
        "oracle_code": "WRITE_WITHOUT_CONTINUITY_REJECTED",
        "operational_sha256": "A0F5F201B44E4C67345AA7EED49CEF45FF754C613F05A98FF7ABAFEBE44B0B33",
    },
    "MUT-15": {
        "frozen_locator": "scripts/gc_state_simulator.py#state_uncertain",
        "operational_path": "scripts/gc_state_simulator.py",
        "operational_anchor": "_validate_e3 automatic_retry fail-closed predicate",
        "rationale": "The exact retry predicate is mutated and exercised by BLIND_RETRY_REJECTED.",
        "consumer": "gc_state_simulator.py::_self_test",
        "oracle_code": "BLIND_RETRY_REJECTED",
        "operational_sha256": "A0F5F201B44E4C67345AA7EED49CEF45FF754C613F05A98FF7ABAFEBE44B0B33",
    },
    "MUT-16": {
        "frozen_locator": "references/05_runtime_state_bridge_data_security_and_reliability.md#provider_failover",
        "operational_path": "references/05_runtime_state_bridge_data_security_and_reliability.md",
        "operational_anchor": "semantic uncertain-effect retry/failover prohibition",
        "rationale": "The consumer requires a prohibition on both automatic retry and failover when an effect may exist, independent of exact phrasing.",
        "consumer": "contract_bundle_check.py::validate_governed_contract_tree",
        "oracle_code": "SILENT_FAILOVER_FORBIDDEN",
        "operational_sha256": "8BECC62CCD61F77F928B9C98E9A330DC0BAB079FC83B48F130038279FCEEF0C7",
    },
    "MUT-17": {
        "frozen_locator": "templates/MEMORY_RETRIEVAL_POLICY.md#promotion",
        "operational_path": "templates/MEMORY_RETRIEVAL_POLICY.md",
        "operational_anchor": "semantic candidate auto-promotion clauses",
        "rationale": "Affirmative auto-promotion is rejected while explicit must-not/never clauses survive.",
        "consumer": "contract_bundle_check.py::validate_governed_contract_tree",
        "oracle_code": "CANDIDATE_AUTO_PROMOTION_FORBIDDEN",
        "operational_sha256": "B81E5BBD6DE036625D5AA045C98C5820DFBC9090436DD96BAA6D6583A55B1C2F",
    },
    "MUT-18": {
        "frozen_locator": "templates/PROVENANCE_MANIFEST.json#/claims/*/source",
        "operational_path": "templates/PROVENANCE_MANIFEST.json",
        "operational_anchor": "sources_read[].{id,locator}+source_versions[].{source_id,sha256}",
        "rationale": "V2 claim provenance binds source identity and locator to a separate immutable digest record.",
        "consumer": "contract_bundle_check.py::validate_governed_contract_tree",
        "oracle_code": "SOURCE_LOCATOR_AND_HASH_REQUIRED",
        "operational_sha256": "94D0380379FC48F13882489EB271F9D1972EAEF9D000E5D6D2FB45F5D0A557B0",
    },
    "MUT-19": {
        "frozen_locator": "templates/MEMORY_RETRIEVAL_POLICY.md#trust_boundary",
        "operational_path": "templates/MEMORY_RETRIEVAL_POLICY.md",
        "operational_anchor": "semantic retrieved-content trust clauses",
        "rationale": "The consumer requires retrieved material to remain data and rejects unnegated trusted-instruction authority.",
        "consumer": "contract_bundle_check.py::validate_governed_contract_tree",
        "oracle_code": "RETRIEVED_CONTENT_UNTRUSTED",
        "operational_sha256": "B81E5BBD6DE036625D5AA045C98C5820DFBC9090436DD96BAA6D6583A55B1C2F",
    },
    "MUT-20": {
        "frozen_locator": "templates/PROVENANCE_MANIFEST.json#/conflicts",
        "operational_path": "templates/PROVENANCE_MANIFEST.json",
        "operational_anchor": "baseline→candidate conflicts_gaps_limits[].conflict_id",
        "rationale": "The production transition consumer compares public conflict IDs and rejects disappearance from the candidate.",
        "consumer": "contract_bundle_check.py::validate_governed_contract_tree",
        "oracle_code": "SOURCE_CONFLICTS_EXPLICIT",
        "operational_sha256": "94D0380379FC48F13882489EB271F9D1972EAEF9D000E5D6D2FB45F5D0A557B0",
    },
    "MUT-21": {
        "frozen_locator": "evals/v2_behavioral_inputs.yaml#fixture_secret_scan",
        "operational_path": "evals/v2_behavioral_inputs.yaml",
        "operational_anchor": "public fixture bytes",
        "rationale": "A recognizable fake secret signature is injected into the declared fixture and scanned.",
        "consumer": "secret_scan.py",
        "oracle_code": "SECRET_SIGNATURE_REJECTED",
        "operational_sha256": "0A58FF90271FC112B64C7E6A4119CCDE00AB64C32B9C50FBF21A33F3B4AF2F67",
    },
    "MUT-22": {
        "frozen_locator": "templates/MEMORY_RETRIEVAL_POLICY.md#tenant_scope",
        "operational_path": "templates/MEMORY_RETRIEVAL_POLICY.md",
        "operational_anchor": "semantic Tenancy boundary scalar",
        "rationale": "The consumer rejects unnegated shared/cross/foreign context permission while accepting explicit isolation prohibitions.",
        "consumer": "contract_bundle_check.py::validate_governed_contract_tree",
        "oracle_code": "TENANT_CONTEXT_ISOLATION_REQUIRED",
        "operational_sha256": "B81E5BBD6DE036625D5AA045C98C5820DFBC9090436DD96BAA6D6583A55B1C2F",
    },
    "MUT-23": {
        "frozen_locator": "templates/TOOL_CONTRACT.yaml#/target_scope",
        "operational_path": "templates/TOOL_CONTRACT.yaml",
        "operational_anchor": "allowed_targets",
        "rationale": "The conceptual target scope maps explicitly to the V2 allowed-target list.",
        "consumer": "contract_bundle_check.py::validate_governed_contract_tree",
        "oracle_code": "TOOL_TARGET_MUST_BE_BOUNDED",
        "operational_sha256": "00266D7D383AA1AE8E49460578E78B3B271B7F4C74ECEC19E7FFE19D3A40F51A",
    },
    "MUT-24": {
        "frozen_locator": "templates/PROVENANCE_MANIFEST.json#/supersession",
        "operational_path": "templates/PROVENANCE_MANIFEST.json",
        "operational_anchor": "baseline→candidate material_not_used[].evidence_id",
        "rationale": "The production transition consumer compares public evidence IDs and rejects disappearance of superseded history.",
        "consumer": "contract_bundle_check.py::validate_governed_contract_tree",
        "oracle_code": "SUPERSEDED_EVIDENCE_APPEND_ONLY",
        "operational_sha256": "94D0380379FC48F13882489EB271F9D1972EAEF9D000E5D6D2FB45F5D0A557B0",
    },
    "MUT-25": {
        "frozen_locator": "assets/schemas/contracts.schema.json#semantic_minimum",
        "operational_path": "assets/schemas/contracts.schema.json",
        "operational_anchor": "$defs.requirements.required",
        "rationale": "The schema code is mutated in a copy; Draft 2020-12 validation of an empty object is the negative path.",
        "consumer": "jsonschema.Draft202012Validator",
        "oracle_code": "SEMANTICALLY_EMPTY_SCHEMA_REJECTED",
        "operational_sha256": "DECA2AF3CDCB6606534208CBB9206A7798D5E0EBF998996599EF3804B2749EB2",
    },
    "MUT-26": {
        "frozen_locator": "assets/schemas/contracts.schema.json#version_dispatch",
        "operational_path": "assets/schemas/contracts.schema.json",
        "operational_anchor": "$defs.requirementsV2.properties.contract_version",
        "rationale": "The V2 dispatch schema is mutated in a copy and a V2/V1 hybrid is validated through requirementsAny.",
        "consumer": "jsonschema.Draft202012Validator",
        "oracle_code": "VERSION_DISPATCH_HYBRID_REJECTED",
        "operational_sha256": "DECA2AF3CDCB6606534208CBB9206A7798D5E0EBF998996599EF3804B2749EB2",
    },
    "MUT-27": {
        "frozen_locator": "scripts/eval_corpus_check.py#expected_case_ids",
        "operational_path": "scripts/eval_corpus_check.py",
        "operational_anchor": "V2_EXPECTED_CASE_IDS exact denominator/order guard",
        "rationale": "The public checker rejects any removal or silent denominator shrink from the exact 36 opaque behavioral fixtures.",
        "consumer": "eval_corpus_check.py::validate_v2_public_profile",
        "oracle_code": "PUBLIC_CASE_DENOMINATOR_REJECTED",
        "operational_sha256": "B48A8DFCF65F067DDFA068C2B1E94526991C365803C7DD28FD8ECE7ED5436516",
    },
    "MUT-28": {
        "frozen_locator": "templates/ACCEPTANCE_PLAN.md#threshold_lock",
        "operational_path": "templates/ACCEPTANCE_PLAN.md",
        "operational_anchor": "Threshold Lock Receipt: candidate_state+threshold_before+threshold_after",
        "rationale": "A public transition receipt in the copied plan distinguishes post-freeze drift from a pre-freeze near miss without mutation-only markers.",
        "consumer": "contract_bundle_check.py::validate_governed_contract_tree",
        "oracle_code": "POST_OUTPUT_THRESHOLD_DRIFT_REJECTED",
        "operational_sha256": "D586FEFD3F869D060188F000EE698DE3FCA6518B7CBF6ECD108B4B8218AF4919",
    },
    "MUT-29": {
        "frozen_locator": "evals/control_vocabulary.yaml#/v2/failure_outcomes",
        "operational_path": "evals/control_vocabulary.yaml",
        "operational_anchor": "v2.failure_outcomes",
        "rationale": "The public checker rejects a vocabulary that removes TIMEOUT or ABORTED from the failure denominator.",
        "consumer": "eval_corpus_check.py::_validate_public_outcome_contract",
        "oracle_code": "TIMEOUT_ABORT_OUTCOME_REJECTED",
        "operational_sha256": "4A75731E8A83455AA5D1405D12897614108FB6705D3C134C8B8F0C1EFB60C67E",
    },
    "MUT-30": {
        "frozen_locator": "templates/AUTONOMY_RISK_ENVELOPE.yaml#/budgets",
        "operational_path": "templates/AUTONOMY_RISK_ENVELOPE.yaml",
        "operational_anchor": "budgets.{model_calls,money}",
        "rationale": "Call and money limits are literal V2 budget fields.",
        "consumer": "contract_bundle_check.py::validate_governed_contract_tree",
        "oracle_code": "CALL_AND_COST_BOUNDS_REQUIRED",
        "operational_sha256": "B349AB975168166B8A47C0CC948E045A81B56DDB49F8B913EB373B535787204B",
    },
    "MUT-31": {
        "frozen_locator": "references/09_interoperability_and_host_portability.md#install_gate",
        "operational_path": "references/09_interoperability_and_host_portability.md",
        "operational_anchor": "Installation Receipt: install_state+parity+readback",
        "rationale": "A public receipt represents installation state; no live installation is performed by the mutation test.",
        "consumer": "contract_bundle_check.py::validate_governed_contract_tree",
        "oracle_code": "INSTALL_PARITY_AND_READBACK_REQUIRED",
        "operational_sha256": "158C7846869DDA2E59DBAF34E8FF7B16EEE578E00BAC9086B327B2251FE73A9B",
    },
    "MUT-32": {
        "frozen_locator": "templates/EVOLUTION_PROPOSAL.yaml#rollback",
        "operational_path": "templates/EVOLUTION_PROPOSAL.yaml",
        "operational_anchor": "migration_control.{mode,rollback_ref,readback_evidence}",
        "rationale": "The conceptual rollback gate maps explicitly to the V2 promotion transition fields.",
        "consumer": "contract_bundle_check.py::validate_governed_contract_tree",
        "oracle_code": "ROLLBACK_TREE_AND_SMOKE_REQUIRED",
        "operational_sha256": "8FD78B8EAFF262BAE3C642B7D320FA0E0E4924B6CB725CAB2F8D5BDC55BD6144",
    },
}
MUTATION_ORACLE_CODES = {
    mutation_id: entry["oracle_code"]
    for mutation_id, entry in MUTATION_EXECUTION_MAP.items()
}
REFERENCE_FIELDS = frozenset(
    {
        "artifact_type",
        "artifact_id",
        "contract_version",
        "schema_version",
        "relation",
        "expected_owner",
        "expected_risk",
        "required",
    }
)
TYPE_INFO: dict[str, tuple[str, str, tuple[str, ...], tuple[str, ...] | None]] = {
    "requirements": ("requirements", "requirement_id", ("authority", "owner"), None),
    "triageDecision": (
        "triage_decision",
        "decision_id",
        ("owner",),
        ("classification", "risk"),
    ),
    "autonomyRiskEnvelope": (
        "autonomy_risk_envelope",
        "envelope_id",
        ("owner",),
        ("classification", "risk"),
    ),
    "agentHat": ("agent_hat", "hat_id", ("owner",), ("classification", "risk")),
    "toolContract": (
        "tool_contract",
        "tool_id",
        ("owner",),
        ("classification", "risk"),
    ),
    "runManifest": (
        "run_manifest",
        "run_id",
        ("owner",),
        ("classification", "risk"),
    ),
    "provenanceManifest": (
        "provenance_manifest",
        "artifact_id",
        ("owner",),
        None,
    ),
    "evolutionProposal": (
        "evolution_proposal",
        "proposal_id",
        ("owner",),
        ("classification", "risk"),
    ),
}
EXPECTED_BASE_BY_PATH = {
    "templates/REQUIREMENTS.yaml": "requirements",
    "templates/TRIAGE_DECISION.yaml": "triageDecision",
    "templates/AUTONOMY_RISK_ENVELOPE.yaml": "autonomyRiskEnvelope",
    "templates/AGENT_HAT.yaml": "agentHat",
    "templates/TOOL_CONTRACT.yaml": "toolContract",
    "templates/RUN_MANIFEST.yaml": "runManifest",
    "templates/PROVENANCE_MANIFEST.json": "provenanceManifest",
    "templates/EVOLUTION_PROPOSAL.yaml": "evolutionProposal",
    "assets/framework_catalog.yaml": "frameworkCatalog",
}
VERSIONED_PATHS = frozenset(EXPECTED_BASE_BY_PATH) - {
    "assets/framework_catalog.yaml"
}
TYPE_TOKENS = {
    re.sub(r"[^a-z0-9]", "", canonical.lower()): canonical
    for canonical, _, _, _ in TYPE_INFO.values()
}


@dataclass(frozen=True)
class Node:
    path: str
    artifact_type: str
    artifact_id: str
    schema_version: str
    contract_version: str
    owner: Any
    risk: Any
    data: dict[str, Any]

    @property
    def key(self) -> tuple[str, str]:
        return self.artifact_type, self.artifact_id

    @property
    def label(self) -> str:
        return f"{self.artifact_type}:{self.artifact_id or '<draft>'}"


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
        description="Read-only V1/V2 contract graph, provenance, and closure check."
    )
    parser.add_argument("root", type=Path, help="Explicit skill root")
    parser.add_argument(
        "--index",
        default=INDEX_DEFAULT,
        help="POSIX path to the schema index, relative to root",
    )
    parser.add_argument(
        "--artifact",
        help="Validate one indexed artifact instead of the complete 9-artifact set",
    )
    parser.add_argument(
        "--mutation-id",
        choices=tuple(sorted(MUTATION_ORACLE_CODES)),
        help="Run one public, target-specific mutation oracle against root",
    )
    parser.add_argument(
        "--mutation-baseline",
        type=Path,
        help="Unmutated comparison root required with --mutation-id",
    )
    parser.add_argument(
        "--governance-baseline",
        type=Path,
        help=(
            "Optional earlier governed tree for append-only history checks. "
            "This is a normal production transition input, not a mutation ID."
        ),
    )
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def _tree_fingerprint(root: Path) -> tuple[int, str]:
    """Hash paths, entry types, bytes, and symlink text without following links."""

    records: list[str] = []
    files = 0
    for current, directories, names in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        directories.sort()
        names.sort()
        retained: list[str] = []
        for name in directories:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                records.append(f"L\t{relative}\t{os.readlink(path)}\n")
            else:
                records.append(f"D\t{relative}\n")
                retained.append(name)
        directories[:] = retained
        for name in names:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                records.append(f"L\t{relative}\t{os.readlink(path)}\n")
                continue
            data = path.read_bytes()
            records.append(f"F\t{relative}\t{len(data)}\t{_sha256(data)}\n")
            files += 1
    manifest = "".join(records).encode("utf-8")
    return files, _sha256(manifest)


def _mutation_records(root: Path) -> dict[str, tuple[str, int, str]]:
    """Return exact non-cache file/link records for mutation diff binding."""

    records: dict[str, tuple[str, int, str]] = {}
    for current, directories, names in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        directories[:] = sorted(
            name for name in directories if name not in MUTATION_CACHE_PARTS
        )
        for name in sorted(names):
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            if (
                any(part in MUTATION_CACHE_PARTS for part in PurePosixPath(relative).parts)
                or path.suffix.lower() in MUTATION_BYTECODE_SUFFIXES
            ):
                continue
            if path.is_symlink():
                target = os.readlink(path).encode("utf-8")
                records[relative] = ("link", len(target), _sha256(target))
            elif path.is_file():
                data = path.read_bytes()
                records[relative] = ("file", len(data), _sha256(data))
    return records


def _mapping_at(value: Any, *parts: str) -> dict[str, Any]:
    current = value
    for part in parts:
        if not isinstance(current, dict):
            return {}
        current = current.get(part)
    return current if isinstance(current, dict) else {}


def _list_at(value: Any, *parts: str) -> list[Any]:
    current = value
    for part in parts:
        if not isinstance(current, dict):
            return []
        current = current.get(part)
    return current if isinstance(current, list) else []


def _public_mutants(root: Path) -> dict[str, dict[str, Any]]:
    registry_path = _safe_relative(root, MUTATION_REGISTRY, label="mutation registry")
    registry = _load_unique(registry_path)
    if not isinstance(registry, dict):
        raise ContractError("public mutation registry must be an object")
    if any(
        forbidden in registry
        for forbidden in ("answer_key", "truth_map", "hidden_expected_outputs")
    ):
        raise ContractError("public mutation registry exposes forbidden answer material")
    mutants = registry.get("mutants")
    if not isinstance(mutants, list) or len(mutants) != 32:
        raise ContractError("public mutation registry must contain exactly 32 mutants")
    result: dict[str, dict[str, Any]] = {}
    for item in mutants:
        if not isinstance(item, dict):
            raise ContractError("public mutation record must be an object")
        mutation_id = item.get("mutation_id")
        if not isinstance(mutation_id, str) or mutation_id in result:
            raise ContractError("public mutation IDs must be unique strings")
        result[mutation_id] = item
    if set(result) != {f"MUT-{number:02d}" for number in range(1, 33)}:
        raise ContractError("public mutation ID denominator drift")
    return result


def public_mutation_execution_map(root: Path) -> dict[str, Any]:
    """Reproduce the complete public registry-to-consumer execution map."""

    records = _public_mutants(root)
    expected_ids = {f"MUT-{number:02d}" for number in range(1, 33)}
    errors: list[dict[str, str]] = []
    entries: list[dict[str, str]] = []
    if set(MUTATION_EXECUTION_MAP) != expected_ids:
        errors.append(
            {
                "code": "MUTATION_EXECUTION_MAP_DENOMINATOR",
                "path": "$execution_map",
                "message": (
                    "execution map must contain exactly MUT-01 through MUT-32"
                ),
            }
        )
    for mutation_id in sorted(expected_ids):
        mapping = MUTATION_EXECUTION_MAP.get(mutation_id)
        record = records.get(mutation_id)
        if mapping is None or record is None:
            continue
        if mapping["frozen_locator"] != record.get("target_locator"):
            errors.append(
                {
                    "code": "MUTATION_EXECUTION_MAP_LOCATOR",
                    "path": f"$execution_map/{mutation_id}",
                    "message": "frozen locator does not match the public registry",
                }
            )
        operational_path = mapping["operational_path"]
        path = _safe_relative(
            root,
            operational_path,
            label=f"{mutation_id} operational path",
        )
        actual_sha256 = (
            _sha256(path.read_bytes())
            if path.is_file() and not path.is_symlink()
            else ""
        )
        if actual_sha256 != mapping["operational_sha256"]:
            errors.append(
                {
                    "code": "MUTATION_EXECUTION_MAP_HASH",
                    "path": operational_path,
                    "message": (
                        f"{mutation_id} operational SHA-256 drift: "
                        f"expected {mapping['operational_sha256']}, "
                        f"got {actual_sha256 or '<missing>'}"
                    ),
                }
            )
        entries.append(
            {
                "mutation_id": mutation_id,
                **mapping,
                "actual_sha256": actual_sha256,
            }
        )
    mapped = sum(
        1
        for item in entries
        if item["frozen_locator"]
        == records[item["mutation_id"]].get("target_locator")
        and item["actual_sha256"] == item["operational_sha256"]
    )
    return {
        "status": "pass" if mapped == 32 and not errors else "fail",
        "mapped": mapped,
        "total": 32,
        "entries": entries,
        "errors": errors,
    }


def _receipt_value(text: str, name: str) -> str | None:
    """Read one explicit transition-receipt scalar from governed Markdown."""

    match = re.search(
        rf"(?mi)^\s*{re.escape(name)}\s*:\s*([^\r\n]+?)\s*$",
        text,
    )
    return match.group(1).strip() if match else None


def _policy_units(text: str) -> list[str]:
    """Return normalized policy clauses without depending on one frozen sentence."""

    return [
        re.sub(r"\s+", " ", unit.casefold()).strip()
        for unit in re.split(r"(?<=[.!?])\s+|[;\r\n]+", text)
        if unit.strip()
    ]


def _agent_consensus_bypasses_evidence(text: str) -> bool:
    """Detect affirmative consensus-as-proof rules while preserving prohibitions."""

    unsafe = re.compile(
        r"(?:satisf(?:y|ies|ied)|replace|outrank|override|"
        r"(?:is|remains)\s+sufficient|(?:is|becomes)\s+authoritative|"
        r"without\s+(?:independent\s+)?evidence)"
    )
    prohibited = re.compile(
        r"(?:must\s+not|may\s+not|cannot|can\s+not|does\s+not|never|"
        r"forbidden|prohibited|insufficient)"
    )
    for unit in _policy_units(text):
        if "consensus" not in unit or unsafe.search(unit) is None:
            continue
        if prohibited.search(unit) is None:
            return True
    return False


def _physical_max_policy_is_safe(text: str) -> bool:
    """Accept equivalent MAX-authority wording and reject reversed authority."""

    positive = False
    contradictory = False
    for unit in _policy_units(text):
        has_physical_max = bool(
            re.search(r"\bphysical\s+(?:max|maximum)\b", unit)
        )
        has_event_hint = bool(
            re.search(r"\b(?:event|notification)\s+(?:is\s+)?(?:a\s+)?hint\b", unit)
            or "event hint" in unit
        )
        if has_physical_max and re.search(
            r"\b(?:authoritative|truth|source\s+of\s+truth|prevails|governs)\b",
            unit,
        ):
            positive = True
        if (
            has_physical_max
            and re.search(r"\b(?:advisory|non-authoritative|secondary)\b", unit)
        ) or (
            has_event_hint
            and re.search(r"\b(?:authoritative|truth|prevails|governs)\b", unit)
        ):
            contradictory = True
    return positive and not contradictory


def _uncertain_effect_retry_policy_is_safe(text: str) -> bool:
    """Require a semantic prohibition on automatic retry/failover under uncertainty."""

    protected = False
    contradictory = False
    for unit in _policy_units(text):
        uncertain_effect = bool(
            re.search(r"\beffect\s+(?:may|might|could)\s+(?:already\s+)?exist\b", unit)
        )
        has_retry = "retry" in unit
        has_failover = bool(re.search(r"\bfail[\s-]?over\b", unit))
        if not (uncertain_effect and has_retry and has_failover):
            continue
        if re.search(
            r"\b(?:never|prohibited|forbidden|disallowed|cannot|"
            r"must\s+not|may\s+not|do\s+not)\b",
            unit,
        ):
            protected = True
        if re.search(
            r"\b(?:allowed|permitted|authorized|automatic(?:ally)?)\b",
            unit,
        ) and re.search(
            r"\b(?:allowed|permitted|authorized)\b",
            unit,
        ):
            contradictory = True
    return protected and not contradictory


def _candidate_auto_promotion_is_allowed(text: str) -> bool:
    """Detect affirmative candidate auto-promotion without flagging a prohibition."""

    promotion = re.compile(r"\b(?:auto[\s-]?promote|automatically\s+promote)\w*\b")
    prohibited = re.compile(
        r"\b(?:must\s+not|may\s+not|cannot|can\s+not|does\s+not|never|"
        r"forbidden|prohibited|disallowed)\b"
    )
    for unit in _policy_units(text):
        if (
            promotion.search(unit)
            and re.search(r"\b(?:candidate|lesson|knowledge|memory)\w*\b", unit)
            and prohibited.search(unit) is None
        ):
            return True
    return False


def _retrieved_content_policy_is_safe(text: str) -> bool:
    """Require retrieved material to remain data and never trusted instructions."""

    positive = False
    contradictory = False
    for unit in _policy_units(text):
        if "retriev" not in unit:
            continue
        if re.search(
            r"\b(?:as|remains?|is)\s+(?:untrusted\s+)?data\b",
            unit,
        ):
            positive = True
        if re.search(r"\btrusted\s+instructions?\b", unit) and re.search(
            r"\b(?:not|never|cannot|must\s+not|may\s+not)\b",
            unit,
        ) is None:
            contradictory = True
    return positive and not contradictory


def _tenancy_boundary_allows_cross_context(text: str) -> bool:
    """Interpret an explicit tenancy-boundary scalar with negation awareness."""

    values = [
        line.split(":", 1)[1].strip().casefold()
        for line in text.splitlines()
        if line.casefold().startswith("tenancy boundary:")
    ]
    for value in values:
        if not value:
            continue
        cross_context = re.search(
            r"\b(?:shared|cross[\s-]?(?:tenant|context)|"
            r"foreign[\s-]?context)\b",
            value,
        )
        if cross_context is None:
            continue
        prohibited = re.search(
            r"\b(?:no|not|never|cannot|must\s+not|may\s+not|"
            r"forbidden|prohibited|disallowed|isolated)\b",
            value,
        )
        if prohibited is None:
            return True
    return False


def validate_governed_contract_tree(
    root: Path,
    governance_baseline: Path | None = None,
) -> list[dict[str, str]]:
    """Production hard gate for cross-artifact governance invariants.

    This validator is part of the normal bundle check.  It has no mutation IDs
    and does not compare a mutant with a baseline.  Mutation tests merely inject
    a public fault and require this same consumer to reject it with the matching
    governance code.
    """

    findings: list[dict[str, str]] = []

    def reject(code: str, path: str, message: str) -> None:
        findings.append({"code": code, "path": path, "message": message})

    def load(relative: str) -> Any:
        path = _safe_relative(root, relative, label="governed surface")
        if not path.is_file():
            raise ContractError(f"missing governed surface: {relative}")
        return _load_unique(path)

    def text(relative: str) -> str:
        path = _safe_relative(root, relative, label="governed document")
        if not path.is_file():
            raise ContractError(f"missing governed document: {relative}")
        return path.read_text(encoding="utf-8")

    requirements = load("templates/REQUIREMENTS.yaml")
    envelope = load("templates/AUTONOMY_RISK_ENVELOPE.yaml")
    tool = load("templates/TOOL_CONTRACT.yaml")
    run = load("templates/RUN_MANIFEST.yaml")
    hat = load("templates/AGENT_HAT.yaml")
    provenance = load("templates/PROVENANCE_MANIFEST.json")
    evolution = load("templates/EVOLUTION_PROPOSAL.yaml")
    acceptance = text("templates/ACCEPTANCE_PLAN.md")
    memory = text("templates/MEMORY_RETRIEVAL_POLICY.md")
    runtime = text(
        "references/05_runtime_state_bridge_data_security_and_reliability.md"
    )
    verifier = text("references/10_verifier_playbook.md")
    portability = text("references/09_interoperability_and_host_portability.md")

    baseline_provenance: Any = None
    if governance_baseline is not None:
        baseline_root_arg = governance_baseline
        if baseline_root_arg.is_symlink():
            raise ContractError("governance baseline root must not be a symlink")
        baseline_root = baseline_root_arg.resolve()
        if not baseline_root.is_dir():
            raise ContractError("governance baseline root must be a directory")
        baseline_path = _safe_relative(
            baseline_root,
            "templates/PROVENANCE_MANIFEST.json",
            label="governance baseline provenance",
        )
        baseline_provenance = _load_unique(baseline_path)

    authority = _mapping_at(requirements, "authority")
    if "human_sovereign" not in authority:
        reject(
            "HUMAN_SOVEREIGN_REQUIRED",
            "templates/REQUIREMENTS.yaml#/authority/human_sovereign",
            "authority.human_sovereign is required",
        )

    approvers = _list_at(envelope, "approvals", "approvers")
    if any(
        (
            isinstance(item, dict)
            and str(item.get("actor_type", "")).strip().lower() == "model"
        )
        or (isinstance(item, str) and "model" in item.lower())
        for item in approvers
    ):
        reject(
            "MODEL_SELF_APPROVAL_FORBIDDEN",
            "templates/AUTONOMY_RISK_ENVELOPE.yaml#/approvals/approvers",
            "a model cannot serve as its own approval actor",
        )

    approval_policy = _mapping_at(tool, "approval_policy")
    allowed_targets = tool.get("allowed_targets", []) if isinstance(tool, dict) else []
    if approval_policy.get("required") is True and (
        not str(approval_policy.get("class", "")).strip()
        or not str(approval_policy.get("draft_tool", "")).strip()
        or not str(approval_policy.get("commit_tool", "")).strip()
        or not isinstance(allowed_targets, list)
        or not allowed_targets
    ):
        reject(
            "APPROVAL_BINDING_REQUIRED",
            "templates/TOOL_CONTRACT.yaml#/approval_policy",
            "required approval must bind class, draft/commit action, and target",
        )
    if isinstance(allowed_targets, list) and any(
        isinstance(item, str) and ("*" in item or item.strip().lower() == "all")
        for item in allowed_targets
    ):
        reject(
            "TOOL_TARGET_MUST_BE_BOUNDED",
            "templates/TOOL_CONTRACT.yaml#/allowed_targets",
            "allowed_targets cannot contain an unbounded wildcard",
        )

    expiry = _mapping_at(envelope, "approvals").get("expiry_seconds")
    if (
        isinstance(expiry, (int, float))
        and not isinstance(expiry, bool)
        and expiry <= 0
    ):
        reject(
            "APPROVAL_EXPIRY_REQUIRED",
            "templates/AUTONOMY_RISK_ENVELOPE.yaml#/approvals/expiry_seconds",
            "approval lifetime must be positive when supplied",
        )
    inherited = (
        envelope.get("inherited_risks", []) if isinstance(envelope, dict) else []
    )
    inherited_risk_values = {
        (
            item
            if isinstance(item, str)
            else item.get("risk")
            if isinstance(item, dict)
            else None
        )
        for item in inherited
    }
    risk = _mapping_at(envelope, "classification").get("risk")
    required_for = _list_at(envelope, "approvals", "required_for")
    downgrade_bound = any(
        isinstance(item, str)
        and "r4" in item.lower()
        and ("downgrade" in item.lower() or "human" in item.lower())
        for item in required_for
    )
    if risk == "R2" and "R4" in inherited_risk_values and not downgrade_bound:
        reject(
            "R4_DOWNGRADE_REQUIRES_HUMAN_DECISION",
            "templates/AUTONOMY_RISK_ENVELOPE.yaml#/classification/risk",
            "an inherited R4 risk cannot become R2 without a bound human decision",
        )
    budgets = _mapping_at(envelope, "budgets")
    if "model_calls" not in budgets or "money" not in budgets:
        reject(
            "CALL_AND_COST_BOUNDS_REQUIRED",
            "templates/AUTONOMY_RISK_ENVELOPE.yaml#/budgets",
            "model-call and money bounds are mandatory governance surfaces",
        )

    spans = _list_at(run, "trace", "spans_recorded")
    interventions = run.get("human_interventions", []) if isinstance(run, dict) else []
    inversion_executed = any(
        isinstance(item, str) and "role_inversion" in item.lower() for item in spans
    )
    inversion_logged = any(
        (
            isinstance(item, dict)
            and str(item.get("type", item.get("kind", ""))).lower()
            == "role_inversion"
        )
        or (isinstance(item, str) and "role_inversion" in item.lower())
        for item in interventions
    )
    if inversion_executed and not inversion_logged:
        reject(
            "ROLE_INVERSION_LEDGER_REQUIRED",
            "templates/RUN_MANIFEST.yaml#/human_interventions",
            "an executed role inversion needs a ledger entry",
        )

    roles = _mapping_at(hat, "responsibility", "roles")
    producer = roles.get("producer")
    verifier_role = roles.get("verifier")
    if (
        isinstance(producer, str)
        and producer
        and producer == verifier_role
    ):
        reject(
            "VERIFIER_INDEPENDENCE_REQUIRED",
            "templates/AGENT_HAT.yaml#/responsibility/roles",
            "producer and verifier cannot be the same actor",
        )

    if _agent_consensus_bypasses_evidence(acceptance):
        reject(
            "EVIDENCE_OUTRANKS_CONSENSUS",
            "templates/ACCEPTANCE_PLAN.md#Completion Rule",
            "agent consensus cannot replace independent evidence",
        )
    if not _physical_max_policy_is_safe(verifier):
        reject(
            "PHYSICAL_MAX_AUTHORITATIVE",
            "references/10_verifier_playbook.md#Optional Read-Only Watcher Profile",
            "the physical maximum must remain authoritative over event hints",
        )
    if not _uncertain_effect_retry_policy_is_safe(runtime):
        reject(
            "SILENT_FAILOVER_FORBIDDEN",
            "references/05_runtime_state_bridge_data_security_and_reliability.md",
            "automatic failover for a possible effect must remain forbidden",
        )
    if _candidate_auto_promotion_is_allowed(memory):
        reject(
            "CANDIDATE_AUTO_PROMOTION_FORBIDDEN",
            "templates/MEMORY_RETRIEVAL_POLICY.md#Source Governance",
            "candidate knowledge cannot auto-promote",
        )
    if not _retrieved_content_policy_is_safe(memory):
        reject(
            "RETRIEVED_CONTENT_UNTRUSTED",
            "templates/MEMORY_RETRIEVAL_POLICY.md#Untrusted Content",
            "retrieved content must remain untrusted data",
        )
    if _tenancy_boundary_allows_cross_context(memory):
        reject(
            "TENANT_CONTEXT_ISOLATION_REQUIRED",
            "templates/MEMORY_RETRIEVAL_POLICY.md#Tenancy boundary",
            "tenant/context boundary cannot permit shared or foreign context",
        )

    sources = provenance.get("sources_read", []) if isinstance(provenance, dict) else []
    versions = (
        provenance.get("source_versions", []) if isinstance(provenance, dict) else []
    )
    version_by_id = {
        item.get("source_id"): item
        for item in versions
        if isinstance(item, dict) and isinstance(item.get("source_id"), str)
    }
    missing_binding = False
    for source in sources if isinstance(sources, list) else []:
        if not isinstance(source, dict):
            missing_binding = True
            continue
        source_id = source.get("id")
        locator = source.get("locator")
        version = version_by_id.get(source_id)
        digest = version.get("sha256") if isinstance(version, dict) else None
        if (
            not isinstance(source_id, str)
            or not source_id
            or not isinstance(locator, str)
            or not locator
            or not isinstance(digest, str)
            or re.fullmatch(r"[A-Fa-f0-9]{64}", digest) is None
        ):
            missing_binding = True
    if sources and missing_binding:
        reject(
            "SOURCE_LOCATOR_AND_HASH_REQUIRED",
            "templates/PROVENANCE_MANIFEST.json#/sources_read",
            "each source needs a locator and matching SHA-256 version binding",
        )
    if not isinstance(provenance, dict) or "conflicts_gaps_limits" not in provenance:
        reject(
            "SOURCE_CONFLICTS_EXPLICIT",
            "templates/PROVENANCE_MANIFEST.json#/conflicts_gaps_limits",
            "the explicit conflicts/gaps/limits surface is required",
        )
    if isinstance(baseline_provenance, dict) and isinstance(provenance, dict):
        baseline_conflict_ids = {
            str(item["conflict_id"])
            for item in baseline_provenance.get("conflicts_gaps_limits", [])
            if isinstance(item, dict) and item.get("conflict_id")
        }
        current_conflict_ids = {
            str(item["conflict_id"])
            for item in provenance.get("conflicts_gaps_limits", [])
            if isinstance(item, dict) and item.get("conflict_id")
        }
        missing_conflicts = sorted(baseline_conflict_ids - current_conflict_ids)
        if missing_conflicts:
            reject(
                "SOURCE_CONFLICTS_EXPLICIT",
                "templates/PROVENANCE_MANIFEST.json#/conflicts_gaps_limits",
                "conflict history IDs disappeared: " + ", ".join(missing_conflicts),
            )
    material_not_used = (
        provenance.get("material_not_used", [])
        if isinstance(provenance, dict)
        else []
    )
    if any(
        isinstance(item, dict)
        and str(item.get("status", "")).lower()
        in {"deleted", "superseded_deleted"}
        for item in material_not_used
    ):
        reject(
            "SUPERSEDED_EVIDENCE_APPEND_ONLY",
            "templates/PROVENANCE_MANIFEST.json#/material_not_used",
            "superseded evidence history cannot be marked deleted",
        )
    if isinstance(baseline_provenance, dict) and isinstance(provenance, dict):
        baseline_evidence_ids = {
            str(item["evidence_id"])
            for item in baseline_provenance.get("material_not_used", [])
            if isinstance(item, dict) and item.get("evidence_id")
        }
        current_evidence_ids = {
            str(item["evidence_id"])
            for item in provenance.get("material_not_used", [])
            if isinstance(item, dict) and item.get("evidence_id")
        }
        missing_evidence = sorted(baseline_evidence_ids - current_evidence_ids)
        if missing_evidence:
            reject(
                "SUPERSEDED_EVIDENCE_APPEND_ONLY",
                "templates/PROVENANCE_MANIFEST.json#/material_not_used",
                "superseded evidence IDs disappeared: "
                + ", ".join(missing_evidence),
            )

    for relative in sorted(EXPECTED_BASE_BY_PATH):
        artifact = load(relative)
        if isinstance(artifact, dict) and not artifact:
            reject(
                "SEMANTICALLY_EMPTY_ARTIFACT_REJECTED",
                relative,
                "an indexed governed artifact cannot be an empty object",
            )
        if (
            relative in VERSIONED_PATHS
            and isinstance(artifact, dict)
            and {artifact.get("schema_version"), artifact.get("contract_version")}
            == {"1.0", "2.0"}
            and artifact.get("schema_version") != artifact.get("contract_version")
        ):
            reject(
                "V1_V2_HYBRID_REJECTED",
                relative,
                "schema_version and contract_version cannot form a V1/V2 hybrid",
            )

    candidate_state = _receipt_value(acceptance, "candidate_state")
    threshold_before = _receipt_value(acceptance, "threshold_before")
    threshold_after = _receipt_value(acceptance, "threshold_after")
    if (
        candidate_state == "FROZEN"
        and threshold_before is not None
        and threshold_after is not None
        and threshold_before != threshold_after
    ):
        reject(
            "POST_OUTPUT_THRESHOLD_DRIFT_REJECTED",
            "templates/ACCEPTANCE_PLAN.md#Release Gate",
            "threshold changed after candidate outputs were frozen",
        )

    install_state = _receipt_value(portability, "install_state")
    parity = _receipt_value(portability, "parity")
    readback = _receipt_value(portability, "readback")
    if install_state == "INSTALLED" and (parity != "PASS" or readback != "PASS"):
        reject(
            "INSTALL_PARITY_AND_READBACK_REQUIRED",
            "references/09_interoperability_and_host_portability.md#Installation",
            "installed state requires PASS parity and readback",
        )

    migration = _mapping_at(evolution, "migration_control")
    # Load-bearing legacy rollback anchor: MUT-32 proves that promotion cannot
    # substitute a merely plausible prior tree for this frozen V1 identity.
    exact_v1_tree = (
        "D6CB63284D77AB71922D2C56699FB9AEE2BAA0E2110E22C100B806CC522B723F"
    )
    readback_evidence = migration.get("readback_evidence")
    smoke_pass = (
        isinstance(readback_evidence, list)
        and any(
            isinstance(item, str)
            and "smoke" in item.lower()
            and "pass" in item.lower()
            for item in readback_evidence
        )
    )
    if migration.get("mode") == "promote" and (
        migration.get("rollback_ref") != exact_v1_tree
        or not smoke_pass
    ):
        reject(
            "ROLLBACK_TREE_AND_SMOKE_REQUIRED",
            "templates/EVOLUTION_PROPOSAL.yaml#/migration_control",
            "promotion rollback needs the exact V1 tree and PASS smoke/readback",
        )
    return sorted(
        findings, key=lambda item: (item["path"], item["code"], item["message"])
    )


def check_public_mutation(
    baseline_root: Path,
    mutant_root: Path,
    mutation_id: str,
) -> dict[str, Any]:
    """Prove one public mutant was injected, executed, and specifically killed."""

    if baseline_root.is_symlink() or mutant_root.is_symlink():
        raise ContractError("mutation roots must not be symlinks")
    baseline = baseline_root.resolve()
    mutant = mutant_root.resolve()
    if not baseline.is_dir() or not mutant.is_dir():
        raise ContractError("mutation baseline and mutant roots must be directories")

    baseline_files_before, baseline_tree_before = _tree_fingerprint(baseline)
    mutant_files_before, mutant_tree_before = _tree_fingerprint(mutant)
    records_before = _mutation_records(baseline)
    records_after = _mutation_records(mutant)
    changed_paths = sorted(
        path
        for path in set(records_before) | set(records_after)
        if records_before.get(path) != records_after.get(path)
    )

    mutants = _public_mutants(baseline)
    record = mutants.get(mutation_id)
    if record is None:
        raise ContractError(f"unknown public mutation ID: {mutation_id}")
    mapping = MUTATION_EXECUTION_MAP[mutation_id]
    if (
        mapping["consumer"]
        != "contract_bundle_check.py::validate_governed_contract_tree"
    ):
        raise ContractError(
            f"{mutation_id} must execute its mapped external consumer "
            f"{mapping['consumer']}; bundle mutation mode is not applicable"
        )
    target_locator = record.get("target_locator")
    if not isinstance(target_locator, str) or "#" not in target_locator:
        raise ContractError(f"invalid public target locator for {mutation_id}")
    if target_locator != mapping["frozen_locator"]:
        raise ContractError(f"execution-map locator mismatch for {mutation_id}")
    injection_path = mapping["operational_path"]
    injected = changed_paths == [injection_path]
    oracle_code = mapping["oracle_code"]
    baseline_report = check_bundle(baseline, enforce_execution_map=False)
    mutant_report = check_bundle(
        mutant,
        governance_baseline=baseline,
        enforce_execution_map=False,
    )
    baseline_codes = {
        item.get("code")
        for item in baseline_report.get("errors", [])
        if isinstance(item, dict)
    }
    mutant_errors = [
        item
        for item in mutant_report.get("errors", [])
        if isinstance(item, dict)
    ]
    mutant_codes = {item.get("code") for item in mutant_errors}
    baseline_clean = baseline_report.get("status") == "pass"
    executed = injected and baseline_clean
    killed = (
        executed
        and mutant_report.get("status") == "fail"
        and oracle_code in mutant_codes
        and oracle_code not in baseline_codes
    )
    witness = next(
        (
            str(item.get("message"))
            for item in mutant_errors
            if item.get("code") == oracle_code
        ),
        "production validator did not emit the required target-specific code",
    )

    baseline_files_after, baseline_tree_after = _tree_fingerprint(baseline)
    mutant_files_after, mutant_tree_after = _tree_fingerprint(mutant)
    readback_unchanged = (
        baseline_files_before == baseline_files_after
        and baseline_tree_before == baseline_tree_after
        and mutant_files_before == mutant_files_after
        and mutant_tree_before == mutant_tree_after
    )
    lifecycle = [
        state
        for state, reached in (
            ("INJECTED", injected),
            ("EXECUTED", executed),
            ("KILLED", killed),
        )
        if reached
    ]
    status = (
        "pass"
        if lifecycle == ["INJECTED", "EXECUTED", "KILLED"] and readback_unchanged
        else "fail"
    )
    errors: list[str] = []
    if not injected:
        errors.append(
            f"expected exactly one changed target {injection_path!r}; "
            f"got {changed_paths!r}"
        )
    if injected and not baseline_clean:
        errors.append(
            "unmutated baseline failed the production contract-tree validator"
        )
    if executed and not killed:
        errors.append(
            f"production validator did not uniquely kill the mutant with {oracle_code}"
        )
    if not readback_unchanged:
        errors.append("mutation oracle changed a protected input tree")
    return {
        "status": status,
        "mutation": {
            "mutation_id": mutation_id,
            "target_locator": target_locator,
            "injection_path": injection_path,
            "operational_anchor": mapping["operational_anchor"],
            "mapping_rationale": mapping["rationale"],
            "injection_operator": record.get("injection_operator"),
            "public_white_box_kill_oracle": record.get(
                "public_white_box_kill_oracle"
            ),
            "oracle_code": oracle_code,
            "witness": witness,
            "changed_paths": changed_paths,
            "lifecycle": lifecycle,
            "states": {
                "INJECTED": injected,
                "EXECUTED": executed,
                "KILLED": killed,
            },
            "consumer": mapping["consumer"],
            "baseline_consumer_status": baseline_report.get("status"),
            "mutant_consumer_status": mutant_report.get("status"),
            "baseline_error_codes": sorted(
                str(code) for code in baseline_codes if code is not None
            ),
            "mutant_error_codes": sorted(
                str(code) for code in mutant_codes if code is not None
            ),
        },
        "input_readback": {
            "baseline": {
                "files_before": baseline_files_before,
                "files_after": baseline_files_after,
                "sha256_before": baseline_tree_before,
                "sha256_after": baseline_tree_after,
            },
            "mutant": {
                "files_before": mutant_files_before,
                "files_after": mutant_files_after,
                "sha256_before": mutant_tree_before,
                "sha256_after": mutant_tree_after,
            },
            "unchanged": readback_unchanged,
        },
        "network_access": "disabled",
        "errors": errors,
    }


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_unique(path: Path) -> Any:
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ContractError(f"UTF-8 BOM is not allowed: {path.name}")
    if b"\r" in raw:
        raise ContractError(f"line endings must be LF: {path.name}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError(f"invalid UTF-8: {path.name}: {exc}") from exc
    if path.suffix.lower() == ".json":
        try:
            return json.loads(text, object_pairs_hook=_unique_pairs)
        except json.JSONDecodeError as exc:
            raise ContractError(f"invalid JSON: {path.name}: {exc}") from exc
    try:
        import yaml
    except ImportError as exc:
        raise ContractError("PyYAML is required for YAML contracts") from exc

    class UniqueSafeLoader(yaml.SafeLoader):
        pass

    def construct_mapping(
        loader: UniqueSafeLoader, node: Any, deep: bool = False
    ) -> dict[Any, Any]:
        loader.flatten_mapping(node)
        result: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            try:
                duplicate = key in result
            except TypeError as exc:
                raise ContractError(f"unhashable YAML key: {path.name}") from exc
            if duplicate:
                raise ContractError(f"duplicate YAML key: {key}")
            result[key] = loader.construct_object(value_node, deep=deep)
        return result

    UniqueSafeLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping
    )
    try:
        return yaml.load(text, Loader=UniqueSafeLoader)
    except yaml.YAMLError as exc:
        raise ContractError(f"invalid YAML: {path.name}: {exc}") from exc


def _safe_relative(root: Path, relative: str, *, label: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ContractError(f"{label} must be a non-empty POSIX relative path")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ContractError(f"{label} escapes or is not canonical: {relative!r}")
    lexical = root.joinpath(*pure.parts)
    current = root
    for part in pure.parts:
        current = current / part
        if current.is_symlink():
            raise ContractError(f"{label} contains a symlink: {relative}")
    resolved = lexical.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ContractError(f"{label} escapes root: {relative}") from exc
    return resolved


def _definition(reference: Any) -> str:
    prefix = "#/$defs/"
    if not isinstance(reference, str) or not reference.startswith(prefix):
        raise ContractError(f"invalid local schema reference: {reference!r}")
    name = reference[len(prefix) :]
    if not name or "/" in name:
        raise ContractError(f"invalid local schema definition: {reference!r}")
    return name


def _value_at(data: dict[str, Any], parts: tuple[str, ...] | None) -> Any:
    if parts is None:
        return None
    value: Any = data
    for part in parts:
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _canonical_type(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    token = re.sub(r"[^a-z0-9]", "", value.lower())
    return TYPE_TOKENS.get(token)


def _schema_errors(
    data: Any, definition: str, schema: dict[str, Any]
) -> list[str]:
    try:
        import jsonschema
    except ImportError as exc:
        raise ContractError("jsonschema is required for contract validation") from exc
    if definition not in schema.get("$defs", {}):
        raise ContractError(f"unknown schema definition: {definition}")
    wrapper = {
        "$schema": schema["$schema"],
        "$ref": f"#/$defs/{definition}",
        "$defs": schema["$defs"],
    }
    validator = jsonschema.Draft202012Validator(
        wrapper, format_checker=jsonschema.FormatChecker()
    )
    errors = sorted(
        validator.iter_errors(data),
        key=lambda item: (
            "/".join(str(part) for part in item.absolute_path),
            item.message,
        ),
    )
    return [
        f"{'/'.join(str(part) for part in error.absolute_path) or '$'}: {error.message}"
        for error in errors
    ]


def _cycles(
    nodes: list[Node], adjacency: dict[str, set[str]]
) -> list[list[str]]:
    by_path = {node.path: node for node in nodes}
    state: dict[str, int] = {}
    stack: list[str] = []
    found: set[tuple[str, ...]] = set()

    def visit(path: str) -> None:
        state[path] = 1
        stack.append(path)
        for target in sorted(adjacency.get(path, set())):
            if state.get(target, 0) == 0:
                visit(target)
            elif state.get(target) == 1:
                start = stack.index(target)
                ring = stack[start:] + [target]
                core = ring[:-1]
                rotations = [tuple(core[index:] + core[:index]) for index in range(len(core))]
                found.add(min(rotations))
        stack.pop()
        state[path] = 2

    for path in sorted(by_path):
        if state.get(path, 0) == 0:
            visit(path)
    return [
        [by_path[path].label for path in cycle] + [by_path[cycle[0]].label]
        for cycle in sorted(found)
    ]


def _validate_index(index: Any) -> tuple[str, dict[str, Any]]:
    if not isinstance(index, dict):
        raise ContractError("schema index must be an object")
    required = {"schema_version", "bundle", "artifacts", "versioned_artifacts"}
    if set(index) != required:
        raise ContractError(
            f"schema index fields mismatch: expected {sorted(required)}, got {sorted(index)}"
        )
    if index["schema_version"] != "1.0":
        raise ContractError("schema index version must be 1.0")
    if not isinstance(index["bundle"], str) or not index["bundle"]:
        raise ContractError("schema index bundle must be a non-empty string")
    if not isinstance(index["artifacts"], dict):
        raise ContractError("schema index artifacts must be an object")
    if set(index["artifacts"]) != set(EXPECTED_BASE_BY_PATH):
        raise ContractError(
            "schema index must enumerate the frozen 9-artifact denominator"
        )
    versioned = index["versioned_artifacts"]
    if not isinstance(versioned, dict) or not versioned:
        raise ContractError("versioned_artifacts must be a non-empty object")
    if set(versioned) != VERSIONED_PATHS:
        raise ContractError(
            "versioned_artifacts must enumerate the frozen 8-contract denominator"
        )
    for relative, base in EXPECTED_BASE_BY_PATH.items():
        if index["artifacts"].get(relative) != f"#/$defs/{base}":
            raise ContractError(f"legacy schema pointer drift: {relative}")
    return index["bundle"], versioned


def check_bundle(
    root: Path,
    index_relative: str = INDEX_DEFAULT,
    artifact_relative: str | None = None,
    governance_baseline: Path | None = None,
    enforce_execution_map: bool = True,
) -> dict[str, Any]:
    """Return a deterministic read-only report for an indexed contract bundle."""

    errors: list[dict[str, str]] = []

    def issue(code: str, path: str, message: str) -> None:
        errors.append({"code": code, "path": path, "message": message})

    root_arg = root
    if root_arg.is_symlink():
        raise ContractError("root must not be a symlink")
    root = root_arg.resolve()
    if not root.is_dir():
        raise ContractError(f"root is not a directory: {root}")
    files_before, fingerprint_before = _tree_fingerprint(root)
    nodes: list[Node] = []
    edges: list[dict[str, Any]] = []
    artifacts_expected = 0
    artifacts_loaded = 0
    versions_seen = {version: 0 for version in sorted(SUPPORTED_VERSIONS)}
    schema_checks = 0
    schema_passed = 0
    references_total = 0
    references_resolved = 0
    cycles: list[list[str]] = []
    execution_map_report: dict[str, Any] = {
        "status": "not_run",
        "mapped": 0,
        "total": 32,
        "entries": [],
        "errors": [],
    }

    try:
        index_path = _safe_relative(root, index_relative, label="index")
        if not index_path.is_file():
            raise ContractError(f"missing schema index: {index_relative}")
        index = _load_unique(index_path)
        bundle_relative, versioned = _validate_index(index)
        schema_relative = (
            PurePosixPath(index_relative).parent / PurePosixPath(bundle_relative)
        ).as_posix()
        schema_path = _safe_relative(root, schema_relative, label="schema bundle")
        if not schema_path.is_file():
            raise ContractError(f"missing schema bundle: {schema_relative}")
        schema = _load_unique(schema_path)
        if not isinstance(schema, dict):
            raise ContractError("schema bundle must be an object")
        try:
            import jsonschema
        except ImportError as exc:
            raise ContractError("jsonschema is required for contract validation") from exc
        jsonschema.Draft202012Validator.check_schema(schema)
        artifact_index = index["artifacts"]
        if not artifact_index:
            raise ContractError("schema index artifacts must be non-empty")
        selected = sorted(artifact_index)
        if artifact_relative is not None:
            if (
                not isinstance(artifact_relative, str)
                or PurePosixPath(artifact_relative).as_posix() != artifact_relative
                or artifact_relative not in artifact_index
            ):
                raise ContractError(
                    f"--artifact is not an indexed canonical path: {artifact_relative!r}"
                )
            selected = [artifact_relative]
        artifacts_expected = len(selected)

        for relative in (item for item in selected if item in versioned):
            spec = versioned[relative]
            if not isinstance(spec, dict) or set(spec) != {
                "current_write",
                "versions",
                "dispatcher",
            }:
                issue("INDEX_SPEC", relative, "invalid versioned artifact entry")
                continue
            versions = spec.get("versions")
            if not isinstance(versions, dict) or set(versions) != SUPPORTED_VERSIONS:
                issue(
                    "INDEX_VERSIONS",
                    relative,
                    "versions must contain exactly 1.0 and 2.0",
                )
                continue
            if spec.get("current_write") != "2.0":
                issue("INDEX_CURRENT_WRITE", relative, "current_write must be 2.0")
            try:
                v1_definition = _definition(versions["1.0"])
                _definition(versions["2.0"])
                _definition(spec["dispatcher"])
            except ContractError as exc:
                issue("INDEX_REFERENCE", relative, str(exc))
                continue
            if index["artifacts"].get(relative) != versions["1.0"]:
                issue(
                    "INDEX_V1_DRIFT",
                    relative,
                    "legacy artifact pointer must equal versions.1.0",
                )
            expected_base = EXPECTED_BASE_BY_PATH[relative]
            expected_refs = {
                "1.0": f"#/$defs/{expected_base}",
                "2.0": f"#/$defs/{expected_base}V2",
                "dispatcher": f"#/$defs/{expected_base}Any",
            }
            if (
                versions != {
                    "1.0": expected_refs["1.0"],
                    "2.0": expected_refs["2.0"],
                }
                or spec["dispatcher"] != expected_refs["dispatcher"]
            ):
                issue(
                    "INDEX_REFERENCE_DRIFT",
                    relative,
                    "version or dispatcher pointer differs from the frozen contract",
                )
            type_info = TYPE_INFO.get(v1_definition)
            if type_info is None:
                issue(
                    "UNKNOWN_ARTIFACT_TYPE",
                    relative,
                    f"unsupported V1 definition: {v1_definition}",
                )
                continue
            try:
                artifact_path = _safe_relative(root, relative, label="artifact")
                if not artifact_path.is_file():
                    raise ContractError(f"missing artifact: {relative}")
                data = _load_unique(artifact_path)
            except (OSError, ContractError) as exc:
                issue("ARTIFACT_READ", relative, str(exc))
                continue
            if not isinstance(data, dict):
                issue("ARTIFACT_TYPE", relative, "artifact must be an object")
                continue
            artifacts_loaded += 1
            schema_version = data.get("schema_version")
            if schema_version not in SUPPORTED_VERSIONS:
                issue(
                    "UNSUPPORTED_VERSION",
                    relative,
                    f"schema_version must be 1.0 or 2.0, got {schema_version!r}",
                )
                continue
            versions_seen[schema_version] += 1
            exact_definition = _definition(versions[schema_version])
            dispatcher_definition = _definition(spec["dispatcher"])
            for lane, definition in (
                ("version", exact_definition),
                ("dispatcher", dispatcher_definition),
            ):
                schema_checks += 1
                try:
                    validation_errors = _schema_errors(data, definition, schema)
                except ContractError as exc:
                    issue("SCHEMA_CONFIGURATION", relative, str(exc))
                    continue
                if validation_errors:
                    for message in validation_errors[:12]:
                        issue(f"SCHEMA_{lane.upper()}", relative, message)
                else:
                    schema_passed += 1

            canonical, id_field, owner_path, risk_path = type_info
            artifact_id = data.get(id_field)
            if not isinstance(artifact_id, str):
                issue("IDENTITY", relative, f"{id_field} must be a string")
                artifact_id = ""
            contract_version = data.get("contract_version", schema_version)
            if not isinstance(contract_version, str):
                issue("IDENTITY", relative, "contract_version must be a string")
                contract_version = ""
            nodes.append(
                Node(
                    path=relative,
                    artifact_type=canonical,
                    artifact_id=artifact_id,
                    schema_version=schema_version,
                    contract_version=contract_version,
                    owner=_value_at(data, owner_path),
                    risk=_value_at(data, risk_path),
                    data=data,
                )
            )

        for relative in (item for item in selected if item not in versioned):
            try:
                artifact_path = _safe_relative(root, relative, label="artifact")
                if not artifact_path.is_file():
                    raise ContractError(f"missing artifact: {relative}")
                data = _load_unique(artifact_path)
            except (OSError, ContractError) as exc:
                issue("ARTIFACT_READ", relative, str(exc))
                continue
            if not isinstance(data, dict):
                issue("ARTIFACT_TYPE", relative, "artifact must be an object")
                continue
            artifacts_loaded += 1
            schema_version = data.get("schema_version")
            if schema_version in SUPPORTED_VERSIONS:
                versions_seen[schema_version] += 1
            try:
                definition = _definition(artifact_index[relative])
                schema_checks += 1
                validation_errors = _schema_errors(data, definition, schema)
            except ContractError as exc:
                issue("SCHEMA_CONFIGURATION", relative, str(exc))
                continue
            if validation_errors:
                for message in validation_errors[:12]:
                    issue("SCHEMA_VERSION", relative, message)
            else:
                schema_passed += 1

        node_by_key: dict[tuple[str, str], Node] = {}
        for node in sorted(nodes, key=lambda item: item.path):
            if node.key in node_by_key:
                issue(
                    "DUPLICATE_IDENTITY",
                    node.path,
                    f"duplicates {node_by_key[node.key].path}: {node.label}",
                )
            else:
                node_by_key[node.key] = node

        adjacency: dict[str, set[str]] = {node.path: set() for node in nodes}
        seen_edges: set[tuple[str, str, str]] = set()
        for source in sorted(nodes, key=lambda item: item.path):
            refs = source.data.get("contract_refs", [])
            if source.schema_version == "1.0":
                refs = []
            if not isinstance(refs, list):
                continue
            for position, ref in enumerate(refs):
                references_total += 1
                ref_path = f"{source.path}#contract_refs/{position}"
                if not isinstance(ref, dict) or set(ref) != REFERENCE_FIELDS:
                    issue("REFERENCE_SHAPE", ref_path, "invalid contract reference")
                    continue
                target_type = _canonical_type(ref.get("artifact_type"))
                artifact_id = ref.get("artifact_id")
                if target_type is None or not isinstance(artifact_id, str):
                    issue("REFERENCE_IDENTITY", ref_path, "unknown type or invalid ID")
                    continue
                target = node_by_key.get((target_type, artifact_id))
                if target is None:
                    issue(
                        "REFERENCE_MISSING",
                        ref_path,
                        f"unresolved target {target_type}:{artifact_id}",
                    )
                    continue
                mismatches: list[str] = []
                expected = {
                    "contract_version": target.contract_version,
                    "schema_version": target.schema_version,
                    "expected_owner": target.owner,
                    "expected_risk": target.risk,
                }
                for field, actual in expected.items():
                    if ref.get(field) != actual:
                        mismatches.append(
                            f"{field} expected {actual!r}, got {ref.get(field)!r}"
                        )
                if mismatches:
                    issue("REFERENCE_MISMATCH", ref_path, "; ".join(mismatches))
                    continue
                relation = ref.get("relation")
                edge_key = (source.path, target.path, str(relation))
                if edge_key in seen_edges:
                    issue(
                        "REFERENCE_DUPLICATE",
                        ref_path,
                        "duplicate source, target, and relation",
                    )
                    continue
                seen_edges.add(edge_key)
                adjacency[source.path].add(target.path)
                references_resolved += 1
                edges.append(
                    {
                        "from": source.label,
                        "relation": relation,
                        "required": ref.get("required"),
                        "to": target.label,
                    }
                )

        cycles = _cycles(nodes, adjacency)
        for cycle in cycles:
            issue("GRAPH_CYCLE", "$graph", " -> ".join(cycle))
        if artifact_relative is None:
            for finding in validate_governed_contract_tree(
                root,
                governance_baseline,
            ):
                issue(
                    finding["code"],
                    finding["path"],
                    finding["message"],
                )
            # The public execution map attests the verifier package that owns
            # the consumers and registry, not the independently supplied
            # contract instance being validated.  Compiled instances are
            # expected to populate their governed templates without changing
            # the verifier's frozen mutation subject.
            execution_map_report = public_mutation_execution_map(PACKAGE_ROOT)
            if enforce_execution_map:
                for finding in execution_map_report["errors"]:
                    issue(
                        finding["code"],
                        finding["path"],
                        finding["message"],
                    )
    except (OSError, ValueError, ContractError, KeyError) as exc:
        issue("BUNDLE_INPUT", "$", str(exc))

    files_after, fingerprint_after = _tree_fingerprint(root)
    unchanged = (
        files_before == files_after and fingerprint_before == fingerprint_after
    )
    if not unchanged:
        issue("INPUT_MUTATION", "$", "input tree changed during read-only check")
    errors.sort(key=lambda item: (item["path"], item["code"], item["message"]))
    provenance_nodes = [
        node for node in nodes if node.artifact_type == "provenance_manifest"
    ]
    payload: dict[str, Any] = {
        "status": "pass" if not errors else "fail",
        "artifacts": {
            "checked": artifacts_loaded,
            "expected": artifacts_expected,
            "versions": versions_seen,
        },
        "schema": {"passed": schema_passed, "total": schema_checks},
        "graph": {
            "nodes": len(nodes),
            "edges": sorted(
                edges, key=lambda item: (item["from"], str(item["relation"]), item["to"])
            ),
            "references_resolved": references_resolved,
            "references_total": references_total,
            "cycles": cycles,
            "cycle_policy": "all_declared_cycles_rejected",
        },
        "provenance": {
            "manifests": len(provenance_nodes),
            "manifest_paths": sorted(node.path for node in provenance_nodes),
        },
        "mutation_execution_map": execution_map_report,
        "closure": {
            "acyclic": not cycles,
            "all_artifacts_loaded": artifacts_loaded == artifacts_expected,
            "all_references_resolved": references_resolved == references_total,
            "closed": not errors,
        },
        "input_readback": {
            "files_before": files_before,
            "files_after": files_after,
            "sha256_before": fingerprint_before,
            "sha256_after": fingerprint_after,
            "unchanged": unchanged,
        },
        "network_access": "disabled",
        "errors": errors,
    }
    payload["checks"] = {
        "artifacts": f"{artifacts_loaded}/{artifacts_expected}",
        "schema": f"{schema_passed}/{schema_checks}",
        "references": f"{references_resolved}/{references_total}",
        "closure": "pass" if payload["closure"]["closed"] else "fail",
        "input_readback": "pass" if unchanged else "fail",
        "mutation_execution_map": (
            f"{execution_map_report['mapped']}/{execution_map_report['total']}"
            if artifact_relative is None
            else "not_run"
        ),
    }
    return payload


def validate_artifact(root: Path, artifact: Path) -> dict[str, Any]:
    """Validate one indexed artifact and return the normal deterministic report."""

    if artifact.is_symlink():
        raise ContractError("artifact must not be a symlink")
    resolved_root = root.resolve()
    candidate = artifact if artifact.is_absolute() else resolved_root / artifact
    resolved_artifact = candidate.resolve()
    try:
        relative = resolved_artifact.relative_to(resolved_root).as_posix()
    except ValueError as exc:
        raise ContractError("artifact must remain within root") from exc
    return check_bundle(resolved_root, INDEX_DEFAULT, relative)


validate_artifact_document = validate_artifact


def main() -> int:
    configure_utf8_stdio()
    args = parse_args()
    try:
        if args.mutation_id is not None:
            if args.mutation_baseline is None:
                raise ContractError(
                    "--mutation-baseline is required with --mutation-id"
                )
            if (
                args.artifact is not None
                or args.index != INDEX_DEFAULT
                or args.governance_baseline is not None
            ):
                raise ContractError(
                    "--mutation-id cannot be combined with --artifact, --index, "
                    "or --governance-baseline"
                )
            payload = check_public_mutation(
                args.mutation_baseline,
                args.root,
                args.mutation_id,
            )
        elif args.mutation_baseline is not None:
            raise ContractError("--mutation-baseline requires --mutation-id")
        else:
            payload = check_bundle(
                args.root,
                args.index,
                args.artifact,
                args.governance_baseline,
            )
    except (OSError, ContractError, ValueError) as exc:
        payload = {
            "status": "fail",
            "artifacts": {"checked": 0, "expected": 0, "versions": {}},
            "schema": {"passed": 0, "total": 0},
            "graph": {
                "nodes": 0,
                "edges": [],
                "references_resolved": 0,
                "references_total": 0,
                "cycles": [],
                "cycle_policy": "all_declared_cycles_rejected",
            },
            "provenance": {"manifests": 0, "manifest_paths": []},
            "closure": {
                "acyclic": False,
                "all_artifacts_loaded": False,
                "all_references_resolved": False,
                "closed": False,
            },
            "input_readback": {"unchanged": None},
            "network_access": "disabled",
            "checks": {
                "artifacts": "0/0",
                "schema": "0/0",
                "references": "0/0",
                "closure": "fail",
                "input_readback": "not_run",
            },
            "errors": [{"code": "ROOT_INPUT", "path": "$", "message": str(exc)}],
        }
    payload["runtime_evidence"] = runtime_evidence()
    emit(payload, args.json)
    return 0 if payload["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
