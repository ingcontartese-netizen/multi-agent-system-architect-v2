#!/usr/bin/env python3
"""Validate requirements and enforce the design-only hard stop."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from _common import ContractError, emit, read_utf8, validate_bundle


RISK_ORDER = {f"R{value}": value for value in range(6)}


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


def _unique_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ContractError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def load_requirements_strict(path: Path) -> Any:
    """Load JSON or YAML without allowing last-key-wins ambiguity."""

    text = read_utf8(path)
    if path.suffix.lower() == ".json":
        try:
            return json.loads(text, object_pairs_hook=_unique_json_pairs)
        except json.JSONDecodeError as exc:
            raise ContractError(f"Invalid JSON in {path}: {exc}") from exc
    try:
        import yaml
    except ImportError as exc:
        raise ContractError(f"PyYAML is required for YAML requirements: {path}") from exc

    class UniqueSafeLoader(yaml.SafeLoader):
        pass

    def construct_mapping(
        loader: UniqueSafeLoader, node: Any, deep: bool = False
    ) -> dict[Any, Any]:
        loader.flatten_mapping(node)
        value: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            try:
                duplicate = key in value
            except TypeError as exc:
                raise ContractError(f"unhashable YAML mapping key in {path}") from exc
            if duplicate:
                raise ContractError(f"duplicate YAML key: {key}")
            value[key] = loader.construct_object(value_node, deep=deep)
        return value

    UniqueSafeLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        construct_mapping,
    )
    try:
        return yaml.load(text, Loader=UniqueSafeLoader)
    except yaml.YAMLError as exc:
        raise ContractError(f"Invalid YAML in {path}: {exc}") from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("requirements", type=Path)
    parser.add_argument("--skill-root", type=Path)
    parser.add_argument("--allow-draft", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def main() -> int:
    configure_utf8_stdio()
    args = parse_args()
    root = (args.skill_root or Path(__file__).resolve().parents[1]).resolve()
    errors: list[str] = []
    decisions: list[str] = []
    try:
        data = load_requirements_strict(args.requirements.resolve())
        validate_bundle(data, "requirementsAny", root)
        status = data.get("document_status")
        if status == "draft" and not args.allow_draft:
            errors.append("draft requirements require --allow-draft")
        if data.get("data", {}).get("sensitivity") == "unknown":
            decisions.append("data.sensitivity")
        if not data.get("authority", {}).get("owner"):
            decisions.append("authority.owner")
        if not data.get("authority", {}).get("human_sovereign"):
            decisions.append("authority.human_sovereign")
        if not data.get("success_checks"):
            decisions.append("success_checks")
        if not data.get("non_agentic_baseline", {}).get("approach"):
            decisions.append("non_agentic_baseline.approach")
        for index, effect in enumerate(data.get("side_effects", [])):
            if not isinstance(effect, dict):
                errors.append(f"side_effects[{index}] must be an object")
                continue
            for field in ("action", "target", "reversibility", "risk"):
                if not effect.get(field):
                    decisions.append(f"side_effects[{index}].{field}")
            risk = effect.get("risk")
            if risk in RISK_ORDER and RISK_ORDER[risk] >= 3 and not data.get("human_approval", {}).get("approvers"):
                decisions.append(f"side_effects[{index}].approver")
        for index, assumption in enumerate(data.get("assumptions", [])):
            if not isinstance(assumption, dict):
                errors.append(f"assumptions[{index}] must be an object")
                continue
            for field in ("value", "source", "owner", "reversible", "impact_if_wrong"):
                if field not in assumption or assumption[field] in (None, ""):
                    errors.append(f"assumptions[{index}] missing {field}")
        declared = data.get("unresolved_critical", [])
        if declared and not data.get("design_only"):
            errors.append("unresolved_critical requires design_only=true")
        if decisions and not data.get("design_only"):
            errors.append("critical missing facts require design_only=true")
    except (OSError, ContractError) as exc:
        errors.append(str(exc))

    payload = {
        "status": "fail" if errors else "design_only" if decisions else "pass",
        "errors": errors,
        "missing_decisions": sorted(set(decisions)),
        "design_only": data.get("design_only") if "data" in locals() else None,
        "runtime_evidence": runtime_evidence(),
    }
    emit(payload, args.json)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
