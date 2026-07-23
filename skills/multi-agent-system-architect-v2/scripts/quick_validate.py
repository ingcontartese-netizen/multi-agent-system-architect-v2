#!/usr/bin/env python3
"""Validate package shape, contracts, links, boundaries, and text hygiene."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import re
import stat
import subprocess
import sys
import urllib.parse
from pathlib import Path, PurePosixPath


class ContractError(ValueError):
    """Public-profile contract failure without importing local modules."""


ALLOWED_FRONTMATTER = {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}
REQUIRED_REFERENCES = {
    "01_doctrine_scope_and_necessity_triage.md",
    "02_knowledge_memory_retrieval_and_provenance.md",
    "03_operating_modes_hats_and_orchestration.md",
    "04_governance_autonomy_risk_approval_and_rollback.md",
    "05_runtime_state_bridge_data_security_and_reliability.md",
    "06_reports_artifacts_and_visual_qa.md",
    "07_observability_evals_opex_and_learning.md",
    "08_case_patterns_and_antipatterns.md",
    "09_interoperability_and_host_portability.md",
    "10_verifier_playbook.md",
    "11_system_planes_and_stack_selection.md",
}
REQUIRED_TEMPLATES = {
    "PURPOSE_CANON.md", "REQUIREMENTS.yaml", "TRIAGE_DECISION.yaml", "ADR.md",
    "ARCHITECTURE_PLANES.md", "AUTONOMY_RISK_ENVELOPE.yaml", "AGENT_HAT.yaml",
    "TOOL_CONTRACT.yaml", "MEMORY_RETRIEVAL_POLICY.md", "THREAT_MODEL.md",
    "RUN_MANIFEST.yaml", "PROVENANCE_MANIFEST.json", "REPORT_ENVELOPE.md",
    "ACCEPTANCE_PLAN.md", "EVOLUTION_PROPOSAL.yaml",
}
REQUIRED_SCRIPTS = {
    "_common.py", "_release_guard.py", "quick_validate.py", "release_qa.py",
    "security_matrix.py", "secret_scan.py", "source_manifest.py",
    "structured_payload_audit.py", "provenance_check.py", "validate_requirements.py",
    "score_options.py", "generate_host_adapters.py", "adapter_parity_check.py",
    "content_retention.py", "contract_bundle_check.py", "gc_state_simulator.py",
    "compare_behavioral_runs.py", "eval_corpus_check.py", "score_behavioral_outputs.py",
}
REQUIRED_EVALS = {
    "EVAL_PROTOCOL.md",
    "behavioral_inputs.yaml",
    "behavioral_output.schema.json",
    "behavioral_rubric.yaml",
    "control_vocabulary.yaml",
    "v2_behavioral_inputs.yaml",
    "v2_behavioral_rubric.yaml",
    "v2_fault_injection.yaml",
}
TEXT_SUFFIXES = {".md", ".py", ".json", ".yaml", ".yml", ".txt", ".toml"}
PUBLIC_FORBIDDEN_MARKERS = (
    ("originating-project codename", re.compile("PTE" + "100X", re.I)),
    ("originating-method name", re.compile("Metodo" + r"\s+" + "GC", re.I)),
    ("internal evidence identifier", re.compile("GC-" + "EVID", re.I)),
    ("internal source binding", re.compile(r"\bR-" + "002" + r"\b", re.I)),
    ("opaque source footer", re.compile("Source " + "IDs:", re.I)),
    ("internal profile identifier", re.compile(r"\bGC-" + r"V2-C\d+\b", re.I)),
)
DETERMINISTIC_EXPECTATIONS: dict[str, tuple[tuple[tuple[str, ...], object], ...]] = {
    "contract_bundle": (
        (("checks", "artifacts"), "9/9"),
    ),
    "eval_v1": (
        (("cases",), 20),
        (("checks",), 214),
    ),
    "eval_v2": (
        (("cases",), 36),
        (("hard_check_ids",), 108),
        (("fault_scenarios",), 47),
        (("mutants",), 32),
    ),
    "gc_state_self_test": (
        (("checks", "fault_scenarios"), "47/47"),
        (("checks", "invariant_self_tests"), "9/9"),
        (("checks", "mutant_fixtures_validated"), "32/32"),
    ),
}

PUBLIC_ONLY_FILES = (
    "SKILL.md",
    "LICENSE.txt",
    "NOTICE.txt",
    "adapters/antigravity/adapter.yaml",
    "adapters/claude/adapter.yaml",
    "adapters/codex/adapter.yaml",
    "adapters/host_generation.yaml",
    "agents/openai.yaml",
    "assets/framework_catalog.yaml",
    "assets/schemas/contracts.schema.json",
    "assets/schemas/schema_index.json",
    "evals/EVAL_PROTOCOL.md",
    "evals/behavioral_inputs.yaml",
    "evals/behavioral_output.schema.json",
    "evals/control_vocabulary.yaml",
    "evals/v2_behavioral_inputs.yaml",
    "evals/v2_fault_injection.yaml",
    "pyproject.toml",
    "references/01_doctrine_scope_and_necessity_triage.md",
    "references/02_knowledge_memory_retrieval_and_provenance.md",
    "references/03_operating_modes_hats_and_orchestration.md",
    "references/04_governance_autonomy_risk_approval_and_rollback.md",
    "references/05_runtime_state_bridge_data_security_and_reliability.md",
    "references/06_reports_artifacts_and_visual_qa.md",
    "references/07_observability_evals_opex_and_learning.md",
    "references/08_case_patterns_and_antipatterns.md",
    "references/09_interoperability_and_host_portability.md",
    "references/10_verifier_playbook.md",
    "references/11_system_planes_and_stack_selection.md",
    "scripts/_common.py",
    "scripts/_release_guard.py",
    "scripts/adapter_parity_check.py",
    "scripts/compare_behavioral_runs.py",
    "scripts/content_retention.py",
    "scripts/contract_bundle_check.py",
    "scripts/eval_corpus_check.py",
    "scripts/gc_state_simulator.py",
    "scripts/generate_host_adapters.py",
    "scripts/provenance_check.py",
    "scripts/quick_validate.py",
    "scripts/release_qa.py",
    "scripts/score_options.py",
    "scripts/security_matrix.py",
    "scripts/secret_scan.py",
    "scripts/source_manifest.py",
    "scripts/structured_payload_audit.py",
    "scripts/validate_requirements.py",
    "templates/ACCEPTANCE_PLAN.md",
    "templates/ADR.md",
    "templates/AGENT_HAT.yaml",
    "templates/ARCHITECTURE_PLANES.md",
    "templates/AUTONOMY_RISK_ENVELOPE.yaml",
    "templates/EVOLUTION_PROPOSAL.yaml",
    "templates/MEMORY_RETRIEVAL_POLICY.md",
    "templates/PROVENANCE_MANIFEST.json",
    "templates/PURPOSE_CANON.md",
    "templates/REPORT_ENVELOPE.md",
    "templates/REQUIREMENTS.yaml",
    "templates/RUN_MANIFEST.yaml",
    "templates/THREAT_MODEL.md",
    "templates/TOOL_CONTRACT.yaml",
    "templates/TRIAGE_DECISION.yaml",
    "tests/conftest.py",
    "tests/test_catalog.py",
    "tests/test_contracts.py",
    "tests/test_evals.py",
    "tests/test_release_qa.py",
    "tests/test_secret_scan_21.py",
    "tests/test_security_matrix.py",
    "tests/test_scripts.py",
)
PUBLIC_ONLY_EXPECTED_FILES = 70
PUBLIC_ONLY_FILE_SET = frozenset(PUBLIC_ONLY_FILES)
PUBLIC_ONLY_PROTECTED_NAMES = frozenset(
    {
        "evals/behavioral_rubric.yaml",
        "evals/v2_behavioral_rubric.yaml",
        "scripts/score_behavioral_outputs.py",
    }
)
PUBLIC_ONLY_DIRECTORIES = (
    "",
    "adapters",
    "adapters/antigravity",
    "adapters/claude",
    "adapters/codex",
    "agents",
    "assets",
    "assets/schemas",
    "evals",
    "references",
    "scripts",
    "templates",
    "tests",
)
PUBLIC_ONLY_DIRECTORY_SET = frozenset(PUBLIC_ONLY_DIRECTORIES)
PUBLIC_ONLY_EXPECTED_NAME = "multi-agent-system-architect-v2"
PUBLIC_ONLY_EXPECTED_DESCRIPTION = (
    "Design, audit, build, verify, or port governed agentic systems for one host "
    "or optional teams. Triage no-system, workflow, agents; govern authority, "
    "state, tools, security, evals. Not for one-offs."
)
PUBLIC_ONLY_EXPECTED_LICENSE = "Apache-2.0"
PUBLIC_ONLY_FRONTMATTER_KEYS = frozenset({"name", "description", "license"})
PUBLIC_ONLY_MAX_FILE_BYTES = 16 * 1024 * 1024

_PUBLIC_INLINE_LINK_RE = re.compile(
    r"!?\[[^\]\n]*\]\(\s*(<[^>\n]*>|[^)\n]*?)\s*\)"
)
_PUBLIC_REFERENCE_LINK_RE = re.compile(
    r"(?m)^[ \t]{0,3}\[[^\]\n]+\]:[ \t]*(<[^>\n]*>|\S+)"
)


def configure_utf8_stdio() -> None:
    """Make the public text protocol UTF-8 even outside Python UTF-8 mode."""

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="strict")


def _emit_public(payload: dict[str, object], as_json: bool) -> None:
    """Emit without importing the full-profile helper module."""

    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    print(f"status: {payload.get('status', 'unknown')}")
    for key in sorted(payload):
        if key == "status":
            continue
        value = payload[key]
        if isinstance(value, (list, dict)):
            print(f"{key}: {json.dumps(value, sort_keys=True)}")
        else:
            print(f"{key}: {value}")


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


def _unique_json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject ambiguous JSON instead of accepting last-key-wins semantics."""

    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ContractError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def load_unique_json_payload(raw: str, label: str) -> object:
    """Decode one delegated JSON payload with duplicate-key rejection."""

    try:
        return json.loads(raw, object_pairs_hook=_unique_json_pairs)
    except json.JSONDecodeError as exc:
        raise ContractError(f"invalid JSON from {label}: {exc}") from exc


def deterministic_child_errors(
    check_id: str,
    returncode: int,
    payload: object,
) -> list[str]:
    """Reject rc-only success and denominator drift in delegated validators."""

    failures: list[str] = []
    if returncode != 0:
        failures.append(f"{check_id} exited with rc={returncode}")
    if not isinstance(payload, dict):
        return [*failures, f"{check_id} returned a non-object JSON payload"]
    if payload.get("status") != "pass":
        failures.append(
            f"{check_id} status mismatch: expected 'pass', "
            f"got {payload.get('status')!r}"
        )
    for path, expected in DETERMINISTIC_EXPECTATIONS[check_id]:
        actual: object = payload
        for key in path:
            if not isinstance(actual, dict) or key not in actual:
                actual = None
                break
            actual = actual[key]
        if actual != expected:
            failures.append(
                f"{check_id} denominator {'.'.join(path)} mismatch: "
                f"expected {expected!r}, got {actual!r}"
            )
    return failures


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path, help="Explicit skill root")
    parser.add_argument(
        "--profile",
        choices=("full", "public-only"),
        default="public-only",
        help="Validation profile; defaults to the installable public-only package",
    )
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def parse_frontmatter(raw: str) -> tuple[dict, str]:
    match = re.match(r"^---\n(.*?)\n---\n", raw, re.S)
    if not match:
        raise ContractError("SKILL.md frontmatter is missing")
    try:
        import yaml
    except ImportError as exc:
        raise ContractError("PyYAML is required to validate SKILL.md") from exc

    class UniqueSafeLoader(yaml.SafeLoader):
        """Safe YAML loader that rejects duplicate mapping keys."""

    def construct_unique_mapping(
        loader: UniqueSafeLoader,
        node: yaml.MappingNode,
        deep: bool = False,
    ) -> dict[object, object]:
        loader.flatten_mapping(node)
        value: dict[object, object] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            try:
                duplicate = key in value
            except TypeError as exc:
                raise ContractError(
                    "unhashable YAML key in SKILL.md frontmatter"
                ) from exc
            if duplicate:
                raise ContractError(f"duplicate YAML key in SKILL.md frontmatter: {key}")
            value[key] = loader.construct_object(value_node, deep=deep)
        return value

    UniqueSafeLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        construct_unique_mapping,
    )
    try:
        data = yaml.load(match.group(1), Loader=UniqueSafeLoader)
    except yaml.YAMLError as exc:
        raise ContractError(f"invalid SKILL.md frontmatter YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ContractError("SKILL.md frontmatter must be a mapping")
    return data, raw[match.end():]


def local_links(path: Path, text: str) -> list[Path]:
    links = []
    for raw in re.findall(r"(?<!!)\[[^\]]+\]\(([^)]+)\)", text):
        target = raw.strip().strip("<>")
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        target = urllib.parse.unquote(target.split()[0].split("#", 1)[0])
        if target:
            links.append((path.parent / target).resolve())
    return links


def _public_native_path(root: Path, relative: str) -> Path:
    if not relative:
        return root
    return root.joinpath(*PurePosixPath(relative).parts)


def _public_stat_token(
    value: os.stat_result,
) -> tuple[int, int, int, int, int, int, int]:
    """Return stable metadata while excluding read-sensitive access time."""

    mtime_ns = getattr(value, "st_mtime_ns", None)
    ctime_ns = getattr(value, "st_ctime_ns", None)
    return (
        stat.S_IFMT(value.st_mode),
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_nlink),
        int(value.st_size),
        int(value.st_mtime * 1_000_000_000 if mtime_ns is None else mtime_ns),
        int(value.st_ctime * 1_000_000_000 if ctime_ns is None else ctime_ns),
    )


def _public_path_token(value: os.stat_result) -> tuple[int, int, int, int]:
    """Portable identity used only across path and open-handle APIs."""

    return (
        stat.S_IFMT(value.st_mode),
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_size),
    )


def _public_os_error(action: str, relative: str, exc: OSError) -> str:
    code = "unknown" if exc.errno is None else str(exc.errno)
    return f"{action} failed for {relative or '.'} (errno={code})"


def _public_policy_errors() -> list[str]:
    """Fail closed before filesystem access if the frozen scope drifts."""

    errors: list[str] = []
    if len(PUBLIC_ONLY_FILES) != PUBLIC_ONLY_EXPECTED_FILES:
        errors.append(
            "internal public allowlist count mismatch: "
            f"expected {PUBLIC_ONLY_EXPECTED_FILES}, got {len(PUBLIC_ONLY_FILES)}"
        )
    if len(PUBLIC_ONLY_FILE_SET) != PUBLIC_ONLY_EXPECTED_FILES:
        errors.append("internal public allowlist contains duplicate paths")
    overlap = PUBLIC_ONLY_FILE_SET & PUBLIC_ONLY_PROTECTED_NAMES
    if overlap:
        errors.append(f"public/protected path overlap: {sorted(overlap)}")

    for relative in (*PUBLIC_ONLY_FILES, *sorted(PUBLIC_ONLY_PROTECTED_NAMES)):
        parsed = PurePosixPath(relative)
        if (
            not relative
            or relative.startswith("/")
            or "\\" in relative
            or parsed.as_posix() != relative
            or any(part in {"", ".", ".."} for part in parsed.parts)
        ):
            errors.append(f"non-canonical frozen path: {relative!r}")

    for relative in PUBLIC_ONLY_DIRECTORIES:
        if not relative:
            continue
        parsed = PurePosixPath(relative)
        if (
            relative.startswith("/")
            or "\\" in relative
            or parsed.as_posix() != relative
            or any(part in {"", ".", ".."} for part in parsed.parts)
        ):
            errors.append(f"non-canonical inventory directory: {relative!r}")

    derived_directories: set[str] = set()
    for relative in PUBLIC_ONLY_FILES:
        parent = PurePosixPath(relative).parent
        while parent != PurePosixPath("."):
            derived_directories.add(parent.as_posix())
            parent = parent.parent

    declared_directories = set(PUBLIC_ONLY_DIRECTORIES) - {""}
    if derived_directories != declared_directories:
        errors.append(
            "internal inventory-directory mismatch: "
            f"missing={sorted(derived_directories - declared_directories)} "
            f"extra={sorted(declared_directories - derived_directories)}"
        )
    return sorted(errors)


def _inventory_public_tree(
    root: Path,
) -> tuple[set[str], set[str], set[str], list[str]]:
    """Inventory only frozen directories; never dynamically recurse."""

    public_files: set[str] = set()
    valid_directories: set[str] = {""}
    protected_seen: set[str] = set()
    errors: list[str] = []

    try:
        root_state = os.lstat(root)
    except OSError as exc:
        return (
            public_files,
            valid_directories,
            protected_seen,
            [_public_os_error("root lstat", ".", exc)],
        )
    if stat.S_ISLNK(root_state.st_mode) or not stat.S_ISDIR(root_state.st_mode):
        return (
            public_files,
            valid_directories,
            protected_seen,
            ["public root must be a real directory, not a symlink or special file"],
        )

    for directory in PUBLIC_ONLY_DIRECTORIES:
        if directory not in valid_directories:
            continue

        directory_path = _public_native_path(root, directory)
        try:
            before = os.lstat(directory_path)
        except OSError as exc:
            errors.append(_public_os_error("directory lstat", directory, exc))
            continue
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
            errors.append(
                f"inventory directory is not a real directory: {directory or '.'}"
            )
            continue

        try:
            with os.scandir(directory_path) as iterator:
                entries = sorted(iterator, key=lambda item: item.name)
                for entry in entries:
                    relative = (
                        entry.name if not directory else f"{directory}/{entry.name}"
                    )

                    # The opaque-name comparison must precede every type/stat query.
                    if relative in PUBLIC_ONLY_PROTECTED_NAMES:
                        protected_seen.add(relative)
                        continue

                    if relative in PUBLIC_ONLY_FILE_SET:
                        try:
                            is_regular = entry.is_file(follow_symlinks=False)
                        except OSError as exc:
                            errors.append(
                                _public_os_error(
                                    "public-file type check", relative, exc
                                )
                            )
                            continue
                        if is_regular:
                            public_files.add(relative)
                        else:
                            errors.append(
                                f"public path is not a regular file: {relative}"
                            )
                        continue

                    if relative in PUBLIC_ONLY_DIRECTORY_SET:
                        try:
                            is_directory = entry.is_dir(follow_symlinks=False)
                        except OSError as exc:
                            errors.append(
                                _public_os_error(
                                    "directory type check", relative, exc
                                )
                            )
                            continue
                        if is_directory:
                            valid_directories.add(relative)
                        else:
                            errors.append(
                                f"inventory path is not a real directory: {relative}"
                            )
                        continue

                    # An unexpected entry is reported by name only and never traversed.
                    errors.append(f"unexpected path in public tree: {relative}")
        except OSError as exc:
            errors.append(_public_os_error("bounded directory scan", directory, exc))
            continue

        try:
            after = os.lstat(directory_path)
        except OSError as exc:
            errors.append(
                _public_os_error("post-scan directory lstat", directory, exc)
            )
            continue
        if _public_stat_token(before) != _public_stat_token(after):
            errors.append(f"directory changed during inventory: {directory or '.'}")

    missing_directories = PUBLIC_ONLY_DIRECTORY_SET - {""} - valid_directories
    for relative in sorted(missing_directories):
        errors.append(f"missing public directory: {relative}")
    for relative in sorted(PUBLIC_ONLY_FILE_SET - public_files):
        errors.append(f"missing public file: {relative}")
    return public_files, valid_directories, protected_seen, errors


def _read_stable_public_text(
    root: Path,
    relative: str,
) -> tuple[str, bytes, tuple[int, int, int, int, int, int, int]]:
    """Read one public file with stable descriptor and path readback."""

    path = _public_native_path(root, relative)
    try:
        path_before = os.lstat(path)
        if stat.S_ISLNK(path_before.st_mode) or not stat.S_ISREG(
            path_before.st_mode
        ):
            raise ContractError(f"public path is not a regular file: {relative}")

        flags = os.O_RDONLY
        for flag_name in ("O_BINARY", "O_CLOEXEC", "O_NOINHERIT", "O_NOFOLLOW"):
            flags |= int(getattr(os, flag_name, 0))

        descriptor = os.open(path, flags)
        try:
            handle_before = os.fstat(descriptor)
            if not stat.S_ISREG(handle_before.st_mode):
                raise ContractError(
                    f"opened public path is not a regular file: {relative}"
                )
            if _public_path_token(path_before) != _public_path_token(handle_before):
                raise ContractError(f"public path changed before read: {relative}")

            oversized_before_read = (
                handle_before.st_size > PUBLIC_ONLY_MAX_FILE_BYTES
            )
            chunks: list[bytes] = []
            byte_count = 0
            if not oversized_before_read:
                while True:
                    remaining = PUBLIC_ONLY_MAX_FILE_BYTES + 1 - byte_count
                    block = os.read(descriptor, min(128 * 1024, remaining))
                    if not block:
                        break
                    chunks.append(block)
                    byte_count += len(block)
                    if byte_count > PUBLIC_ONLY_MAX_FILE_BYTES:
                        break
            handle_after = os.fstat(descriptor)
        finally:
            os.close(descriptor)

        if _public_stat_token(handle_before) != _public_stat_token(handle_after):
            raise ContractError(f"public file changed during read: {relative}")
        path_after = os.lstat(path)
        if _public_path_token(handle_after) != _public_path_token(path_after):
            raise ContractError(f"public path changed after read: {relative}")
    except OSError as exc:
        raise ContractError(
            _public_os_error("stable public read", relative, exc)
        ) from exc

    if oversized_before_read:
        raise ContractError(
            f"public file exceeds {PUBLIC_ONLY_MAX_FILE_BYTES} bytes: {relative}"
        )
    data = b"".join(chunks)
    if len(data) > PUBLIC_ONLY_MAX_FILE_BYTES:
        raise ContractError(
            f"public file exceeds {PUBLIC_ONLY_MAX_FILE_BYTES} bytes: {relative}"
        )
    if len(data) != handle_after.st_size:
        raise ContractError(f"public file size/read mismatch: {relative}")
    if data.startswith(b"\xef\xbb\xbf"):
        raise ContractError(f"UTF-8 BOM is not allowed: {relative}")
    if b"\r" in data:
        raise ContractError(f"line endings must be LF: {relative}")
    if b"\x00" in data:
        raise ContractError(f"NUL byte is not allowed: {relative}")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ContractError(
            f"invalid UTF-8 in {relative} at byte {exc.start}"
        ) from exc
    return text, data, _public_stat_token(handle_after)


def _public_frontmatter_errors(text: str) -> list[str]:
    errors: list[str] = []
    try:
        frontmatter, _ = parse_frontmatter(text)
    except ContractError as exc:
        return [str(exc)]

    actual_keys = set(frontmatter)
    if actual_keys != PUBLIC_ONLY_FRONTMATTER_KEYS:
        rendered_keys = sorted(repr(key) for key in actual_keys)
        errors.append(
            "SKILL.md frontmatter key mismatch: "
            f"expected={sorted(PUBLIC_ONLY_FRONTMATTER_KEYS)} "
            f"actual={rendered_keys}"
        )

    name = frontmatter.get("name")
    if name != PUBLIC_ONLY_EXPECTED_NAME:
        errors.append(
            "SKILL.md frontmatter name mismatch: "
            f"expected={PUBLIC_ONLY_EXPECTED_NAME!r} actual={name!r}"
        )

    description = frontmatter.get("description")
    if type(description) is not str:
        errors.append("SKILL.md frontmatter description must be one scalar string")
    else:
        if not description.strip():
            errors.append("SKILL.md frontmatter description must be nonblank")
        if description != description.strip():
            errors.append("SKILL.md frontmatter description must be trimmed")
        if len(description) > 1024:
            errors.append(
                "SKILL.md frontmatter description exceeds 1024 characters"
            )
        if description != PUBLIC_ONLY_EXPECTED_DESCRIPTION:
            errors.append("SKILL.md frontmatter description drifted")
        if len(description) > 200:
            errors.append("SKILL.md frontmatter description exceeds 200 characters")
    if frontmatter.get("license") != PUBLIC_ONLY_EXPECTED_LICENSE:
        errors.append(
            "SKILL.md frontmatter license mismatch: "
            f"expected={PUBLIC_ONLY_EXPECTED_LICENSE!r} "
            f"actual={frontmatter.get('license')!r}"
        )
    return errors


def _public_markdown_targets(text: str) -> list[str]:
    targets = [match.group(1) for match in _PUBLIC_INLINE_LINK_RE.finditer(text)]
    targets.extend(
        match.group(1) for match in _PUBLIC_REFERENCE_LINK_RE.finditer(text)
    )
    return sorted(targets)


def _resolve_public_link(
    source: str,
    raw_target: str,
) -> tuple[str | None, str | None]:
    value = raw_target.strip()
    if not value:
        return None, f"empty local link target in {source}"
    if value.startswith("<"):
        close = value.find(">")
        if close < 0:
            return None, f"malformed angle-bracket link in {source}"
        destination = value[1:close]
    else:
        destination = value.split(None, 1)[0]

    if not destination:
        return None, f"empty local link target in {source}"
    if destination.startswith("#"):
        return None, None
    try:
        parsed = urllib.parse.urlsplit(destination)
    except ValueError:
        return None, f"malformed link target in {source}: {destination!r}"

    if parsed.scheme:
        if parsed.scheme.lower() in {"http", "https", "mailto"}:
            return None, None
        return None, f"unsupported link scheme in {source}: {parsed.scheme!r}"
    if parsed.netloc or not parsed.path:
        return None, None
    if re.search(r"%(?![0-9A-Fa-f]{2})", parsed.path):
        return (
            None,
            f"invalid percent escape in local link from {source}: {destination!r}",
        )
    try:
        decoded = urllib.parse.unquote(
            parsed.path,
            encoding="utf-8",
            errors="strict",
        )
    except UnicodeDecodeError:
        return (
            None,
            f"invalid UTF-8 escape in local link from {source}: {destination!r}",
        )
    if "\x00" in decoded or "\\" in decoded:
        return None, f"non-portable local link from {source}: {destination!r}"
    if decoded.startswith("/"):
        return (
            None,
            f"absolute local link is forbidden in {source}: {destination!r}",
        )

    normalized = posixpath.normpath(
        posixpath.join(posixpath.dirname(source), decoded)
    )
    if normalized == ".":
        normalized = ""
    if normalized == ".." or normalized.startswith("../"):
        return (
            None,
            f"local link escapes public root from {source}: {destination!r}",
        )
    return normalized, None


def _public_link_errors(
    texts: dict[str, str],
    public_files: set[str],
    valid_directories: set[str],
) -> tuple[list[str], int]:
    errors: list[str] = []
    checked = 0
    markdown_files = sorted(
        relative for relative in texts if relative.lower().endswith(".md")
    )
    for source in markdown_files:
        for raw_target in _public_markdown_targets(texts[source]):
            target, error = _resolve_public_link(source, raw_target)
            if error:
                errors.append(error)
                continue
            if target is None:
                continue
            checked += 1
            if target in PUBLIC_ONLY_PROTECTED_NAMES:
                errors.append(
                    f"public link targets opaque protected path: {source} -> {target}"
                )
            elif target in PUBLIC_ONLY_FILE_SET:
                if target not in public_files:
                    errors.append(f"broken public local link: {source} -> {target}")
            elif target in PUBLIC_ONLY_DIRECTORY_SET:
                if target not in valid_directories:
                    errors.append(
                        f"broken public directory link: {source} -> {target}"
                    )
            else:
                errors.append(
                    f"local link targets undeclared path: {source} -> {target}"
                )
    return errors, checked


def _load_unique_public_yaml(text: str, label: str) -> object:
    try:
        import yaml
    except ImportError as exc:
        raise ContractError("PyYAML is required for public contract validation") from exc

    class UniqueSafeLoader(yaml.SafeLoader):
        """Safe loader with fail-closed duplicate mapping keys."""

    def construct_unique_mapping(
        loader: UniqueSafeLoader,
        node: yaml.MappingNode,
        deep: bool = False,
    ) -> dict[object, object]:
        loader.flatten_mapping(node)
        value: dict[object, object] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            try:
                duplicate = key in value
            except TypeError as exc:
                raise ContractError(f"unhashable YAML key in {label}") from exc
            if duplicate:
                raise ContractError(f"duplicate YAML key in {label}: {key}")
            value[key] = loader.construct_object(value_node, deep=deep)
        return value

    UniqueSafeLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        construct_unique_mapping,
    )
    try:
        return yaml.load(text, Loader=UniqueSafeLoader)
    except yaml.YAMLError as exc:
        raise ContractError(f"invalid YAML in {label}: {exc}") from exc


def _public_contract_errors(
    texts: dict[str, str],
) -> tuple[list[str], dict[str, str]]:
    """Validate public V2 carriers without consulting sealed material."""

    errors: list[str] = []
    checks = {
        "v2_behavioral_inputs": "0/36",
        "v2_fault_scenarios": "0/47",
        "v2_mutants": "0/32",
        "control_vocabulary_lanes": "0/3",
        "behavioral_output_shapes": "0/2",
    }

    inputs_label = "evals/v2_behavioral_inputs.yaml"
    try:
        inputs = _load_unique_public_yaml(texts[inputs_label], inputs_label)
    except (KeyError, ContractError) as exc:
        errors.append(str(exc))
    else:
        expected_ids = [f"F2-BHV-{index:03d}" for index in range(1, 37)]
        cases = inputs.get("cases") if isinstance(inputs, dict) else None
        if not isinstance(inputs, dict) or inputs.get("case_count") != 36:
            errors.append("V2 public behavioral case_count must be 36")
        if not isinstance(cases, list):
            errors.append("V2 public behavioral cases must be a list")
        else:
            actual_ids: list[object] = []
            valid_cases = 0
            direct_answer_keys = {
                "answer",
                "answer_key",
                "classification",
                "direct_answer",
                "direct_answer_label",
                "expected",
                "expected_output",
                "hard_decisions",
                "label",
                "oracle",
            }
            for index, item in enumerate(cases):
                if not isinstance(item, dict):
                    actual_ids.append(None)
                    continue
                actual_ids.append(item.get("case_id"))
                keys = set(item)
                expected_keys = {"case_id", "evidence_level", "fixture_prompt"}
                overlap = keys & direct_answer_keys
                if overlap:
                    errors.append(
                        "direct-answer labels are forbidden in V2 public inputs: "
                        f"{sorted(overlap)}"
                    )
                case_valid = (
                    index < 36
                    and item.get("case_id") == expected_ids[index]
                    and keys == expected_keys
                    and isinstance(item.get("evidence_level"), dict)
                    and isinstance(item.get("fixture_prompt"), str)
                    and bool(item.get("fixture_prompt", "").strip())
                )
                if case_valid:
                    valid_cases += 1
            checks["v2_behavioral_inputs"] = f"{valid_cases}/36"
            if actual_ids != expected_ids:
                errors.append(
                    "V2 public behavioral IDs must be exactly F2-BHV-001..036"
                )
            if any(
                isinstance(item, dict)
                and set(item) != {"case_id", "evidence_level", "fixture_prompt"}
                for item in cases
            ):
                errors.append(
                    "V2 public behavioral case keys must be exactly "
                    "case_id/evidence_level/fixture_prompt"
                )

    fault_label = "evals/v2_fault_injection.yaml"
    try:
        fault = _load_unique_public_yaml(texts[fault_label], fault_label)
    except (KeyError, ContractError) as exc:
        errors.append(str(exc))
    else:
        expected_counts = {"E1": 15, "E2": 17, "E3": 15, "total": 47}
        if not isinstance(fault, dict) or fault.get("fault_counts") != expected_counts:
            errors.append("V2 public fault counts must be E1=15 E2=17 E3=15 total=47")
        scenarios = fault.get("fault_scenarios") if isinstance(fault, dict) else None
        valid_scenarios = 0
        scenario_ids: list[object] = []
        if not isinstance(scenarios, dict) or set(scenarios) != {"E1", "E2", "E3"}:
            errors.append("V2 public fault lanes must be exactly E1/E2/E3")
        else:
            for lane, expected_count in (("E1", 15), ("E2", 17), ("E3", 15)):
                items = scenarios.get(lane)
                if not isinstance(items, list) or len(items) != expected_count:
                    errors.append(
                        f"V2 public fault lane {lane} must contain {expected_count} scenarios"
                    )
                    continue
                for item in items:
                    scenario_id = item.get("scenario_id") if isinstance(item, dict) else None
                    scenario_ids.append(scenario_id)
                    if isinstance(scenario_id, str) and scenario_id.startswith(
                        f"F2-{lane}-"
                    ):
                        valid_scenarios += 1
            if len(set(scenario_ids)) != len(scenario_ids):
                errors.append("V2 public fault scenario IDs must be unique")
        checks["v2_fault_scenarios"] = f"{valid_scenarios}/47"

        mutants = fault.get("mutants") if isinstance(fault, dict) else None
        expected_mutation_ids = [f"MUT-{index:02d}" for index in range(1, 33)]
        mutation_ids = (
            [item.get("mutation_id") if isinstance(item, dict) else None for item in mutants]
            if isinstance(mutants, list)
            else []
        )
        valid_mutants = sum(
            actual == expected
            for actual, expected in zip(mutation_ids, expected_mutation_ids)
        )
        checks["v2_mutants"] = f"{valid_mutants}/32"
        if (
            not isinstance(fault, dict)
            or fault.get("mutation_count") != 32
            or not isinstance(mutants, list)
            or len(mutants) != 32
            or mutation_ids != expected_mutation_ids
        ):
            errors.append("V2 public mutants must be exactly MUT-01..MUT-32")

    vocabulary_label = "evals/control_vocabulary.yaml"
    try:
        vocabulary = _load_unique_public_yaml(texts[vocabulary_label], vocabulary_label)
    except (KeyError, ContractError) as exc:
        errors.append(str(exc))
    else:
        v2 = vocabulary.get("v2") if isinstance(vocabulary, dict) else None
        expected_lanes = {"SEALED_BEHAVIORAL", "PUBLIC_WHITE_BOX", "VERIFIER_SEALED"}
        lanes = v2.get("evaluation_lanes") if isinstance(v2, dict) else None
        lane_set = set(lanes) if isinstance(lanes, list) else set()
        checks["control_vocabulary_lanes"] = (
            f"{len(expected_lanes & lane_set)}/3"
        )
        if not expected_lanes <= lane_set:
            errors.append("V2 control vocabulary must include all three evaluation lanes")
        classification = v2.get("classification") if isinstance(v2, dict) else None
        classification_keys = {
            "scope_decision",
            "architecture_mode",
            "autonomy_level",
            "risk_class",
        }
        if (
            not isinstance(classification, dict)
            or set(classification) != classification_keys
            or not all(
                isinstance(classification.get(key), list) and classification[key]
                for key in classification_keys
            )
        ):
            errors.append("V2 control vocabulary classification shape drifted")
        hard_keys = v2.get("hard_decision_keys") if isinstance(v2, dict) else None
        if hard_keys != ["route", "hard_gate", "evidence_recovery"]:
            errors.append("V2 control vocabulary hard_decisions shape drifted")

    schema_label = "evals/behavioral_output.schema.json"
    try:
        schema = load_unique_json_payload(texts[schema_label], schema_label)
    except (KeyError, ContractError) as exc:
        errors.append(str(exc))
    else:
        definitions = schema.get("$defs") if isinstance(schema, dict) else None
        one_of = schema.get("oneOf") if isinstance(schema, dict) else None
        dispatcher_refs = (
            {item.get("$ref") for item in one_of if isinstance(item, dict)}
            if isinstance(one_of, list)
            else set()
        )
        required_dispatchers = {
            "#/$defs/v1BehavioralOutput",
            "#/$defs/v2BehavioralOutput",
        }
        if dispatcher_refs != required_dispatchers:
            errors.append("behavioral output schema must dispatch exactly V1 and V2")
        valid_shapes = 0
        for definition_name in ("v1BehavioralOutput", "v2BehavioralOutput"):
            definition = (
                definitions.get(definition_name)
                if isinstance(definitions, dict)
                else None
            )
            required = definition.get("required") if isinstance(definition, dict) else None
            properties = (
                definition.get("properties") if isinstance(definition, dict) else None
            )
            shape_valid = (
                isinstance(definition, dict)
                and definition.get("type") == "object"
                and definition.get("additionalProperties") is False
                and isinstance(required, list)
                and bool(required)
                and isinstance(properties, dict)
                and set(required) <= set(properties)
            )
            if definition_name == "v2BehavioralOutput":
                shape_valid = shape_valid and {
                    "classification",
                    "hard_decisions",
                } <= set(required or [])
            if shape_valid:
                valid_shapes += 1
            else:
                errors.append(f"behavioral output {definition_name} shape drifted")

        classification = (
            definitions.get("v2Classification")
            if isinstance(definitions, dict)
            else None
        )
        hard_decisions = (
            definitions.get("v2HardDecisions")
            if isinstance(definitions, dict)
            else None
        )
        classification_keys = {
            "scope_decision",
            "architecture_mode",
            "autonomy_level",
            "risk_class",
        }
        hard_keys = {"route", "hard_gate", "evidence_recovery"}
        classification_shape_valid = (
            isinstance(classification, dict)
            and set(classification.get("required", [])) == classification_keys
            and set(classification.get("properties", {})) == classification_keys
        )
        hard_decisions_shape_valid = (
            isinstance(hard_decisions, dict)
            and set(hard_decisions.get("required", [])) == hard_keys
            and set(hard_decisions.get("properties", {})) == hard_keys
        )
        if not classification_shape_valid:
            errors.append("behavioral output V2 classification definition drifted")
        if not hard_decisions_shape_valid:
            errors.append("behavioral output V2 hard_decisions definition drifted")
        if valid_shapes == 2 and not (
            classification_shape_valid and hard_decisions_shape_valid
        ):
            valid_shapes -= 1
        checks["behavioral_output_shapes"] = f"{valid_shapes}/2"

    return errors, checks


def _public_hygiene_errors(texts: dict[str, str]) -> list[str]:
    errors: list[str] = []
    leaks: dict[str, list[str]] = {}
    for relative in sorted(texts):
        text = texts[relative]
        if (
            relative != "scripts/quick_validate.py"
            and re.search(r"\b(?:TODO|FIXME|XXX)\b", text)
        ):
            errors.append(f"active placeholder marker in {relative}")
        for label, pattern in PUBLIC_FORBIDDEN_MARKERS:
            if pattern.search(text):
                leaks.setdefault(label, []).append(relative)
    if leaks:
        for label in sorted(leaks):
            errors.append(
                f"public sanitation marker ({label}) found in "
                f"{sorted(leaks[label])}"
            )
    return errors


def _public_tree_sha256(digests: dict[str, str]) -> str | None:
    if set(digests) != PUBLIC_ONLY_FILE_SET:
        return None
    digest = hashlib.sha256()
    digest.update(b"public-only-tree-v1\n")
    for relative in sorted(PUBLIC_ONLY_FILES):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(bytes.fromhex(digests[relative]))
        digest.update(b"\n")
    return digest.hexdigest().upper()


def _public_final_readback(
    root: Path,
    initial_public_files: set[str],
    initial_directories: set[str],
    initial_protected_names: set[str],
    initial_inventory_errors: list[str],
    initial_tokens: dict[str, tuple[int, int, int, int, int, int, int]],
    initial_digests: dict[str, str],
    initial_tree_sha256: str | None,
) -> dict[str, object]:
    """Repeat inventory and byte reads, then compare every frozen signal."""

    errors: list[str] = []
    (
        final_public_files,
        final_directories,
        final_protected_names,
        final_inventory_errors,
    ) = _inventory_public_tree(root)
    errors.extend(final_inventory_errors)

    public_set_unchanged = final_public_files == initial_public_files
    directory_set_unchanged = final_directories == initial_directories
    protected_set_unchanged = final_protected_names == initial_protected_names
    exact_initial_inventory = (
        not initial_inventory_errors
        and initial_public_files == PUBLIC_ONLY_FILE_SET
        and initial_directories == PUBLIC_ONLY_DIRECTORY_SET
    )
    exact_final_inventory = (
        not final_inventory_errors
        and final_public_files == PUBLIC_ONLY_FILE_SET
        and final_directories == PUBLIC_ONLY_DIRECTORY_SET
    )
    if not public_set_unchanged or not directory_set_unchanged:
        errors.append("public inventory changed before final readback")
    if not protected_set_unchanged:
        errors.append("protected-name set changed before final readback")

    final_tokens: dict[str, tuple[int, int, int, int, int, int, int]] = {}
    final_digests: dict[str, str] = {}
    for relative in sorted(PUBLIC_ONLY_FILE_SET & final_public_files):
        try:
            _text, data, token = _read_stable_public_text(root, relative)
        except ContractError as exc:
            errors.append(f"final readback: {exc}")
            continue
        final_tokens[relative] = token
        final_digests[relative] = hashlib.sha256(data).hexdigest().upper()

    matching_files = 0
    for relative in sorted(PUBLIC_ONLY_FILE_SET):
        initial_token = initial_tokens.get(relative)
        final_token = final_tokens.get(relative)
        initial_digest = initial_digests.get(relative)
        final_digest = final_digests.get(relative)
        token_matches = initial_token is not None and initial_token == final_token
        digest_matches = (
            initial_digest is not None and initial_digest == final_digest
        )
        if initial_token is not None and final_token is not None and not token_matches:
            errors.append(
                f"public file metadata changed before final readback: {relative}"
            )
        if (
            initial_digest is not None
            and final_digest is not None
            and not digest_matches
        ):
            errors.append(
                f"public file bytes changed before final readback: {relative}"
            )
        if token_matches and digest_matches:
            matching_files += 1

    final_tree_sha256 = _public_tree_sha256(final_digests)
    tree_unchanged = (
        initial_tree_sha256 is not None
        and final_tree_sha256 is not None
        and initial_tree_sha256 == final_tree_sha256
    )
    if not tree_unchanged:
        errors.append("public tree digest changed before final readback")

    token_set_complete = set(initial_tokens) == set(final_tokens) == PUBLIC_ONLY_FILE_SET
    digest_set_complete = (
        set(initial_digests) == set(final_digests) == PUBLIC_ONLY_FILE_SET
    )
    inventory_unchanged = (
        exact_initial_inventory
        and exact_final_inventory
        and public_set_unchanged
        and directory_set_unchanged
    )
    unchanged = (
        inventory_unchanged
        and protected_set_unchanged
        and token_set_complete
        and digest_set_complete
        and matching_files == PUBLIC_ONLY_EXPECTED_FILES
        and tree_unchanged
    )
    return {
        "errors": errors,
        "final_public_files": final_public_files,
        "final_protected_names": final_protected_names,
        "final_reads": len(final_digests),
        "matching_files": matching_files,
        "initial_tree_sha256": initial_tree_sha256,
        "final_tree_sha256": final_tree_sha256,
        "inventory_unchanged": inventory_unchanged,
        "protected_names_unchanged": protected_set_unchanged,
        "token_set_complete": token_set_complete,
        "digest_set_complete": digest_set_complete,
        "tree_unchanged": tree_unchanged,
        "unchanged": unchanged,
    }


def validate_public_only(root_arg: Path) -> dict[str, object]:
    errors = _public_policy_errors()
    public_files: set[str] = set()
    valid_directories: set[str] = set()
    protected_seen: set[str] = set()
    texts: dict[str, str] = {}
    digests: dict[str, str] = {}
    read_tokens: dict[str, tuple[int, int, int, int, int, int, int]] = {}
    inventory_errors: list[str] = []
    local_links_checked = 0
    public_contract_checks = {
        "v2_behavioral_inputs": "0/36",
        "v2_fault_scenarios": "0/47",
        "v2_mutants": "0/32",
        "control_vocabulary_lanes": "0/3",
        "behavioral_output_shapes": "0/2",
    }
    readback: dict[str, object] = {
        "errors": [],
        "final_public_files": set(),
        "final_protected_names": set(),
        "final_reads": 0,
        "matching_files": 0,
        "initial_tree_sha256": None,
        "final_tree_sha256": None,
        "inventory_unchanged": False,
        "protected_names_unchanged": False,
        "token_set_complete": False,
        "digest_set_complete": False,
        "tree_unchanged": False,
        "unchanged": False,
    }

    # abspath is lexical and does not follow the final path like resolve().
    root = Path(os.path.abspath(os.fspath(root_arg)))
    if not errors:
        (
            public_files,
            valid_directories,
            protected_seen,
            inventory_errors,
        ) = _inventory_public_tree(root)
        errors.extend(inventory_errors)

        for relative in sorted(public_files):
            try:
                text, data, read_token = _read_stable_public_text(root, relative)
            except ContractError as exc:
                errors.append(str(exc))
                continue
            texts[relative] = text
            digests[relative] = hashlib.sha256(data).hexdigest().upper()
            read_tokens[relative] = read_token

        skill_text = texts.get("SKILL.md")
        if skill_text is not None:
            errors.extend(_public_frontmatter_errors(skill_text))

        link_errors, local_links_checked = _public_link_errors(
            texts,
            public_files,
            valid_directories,
        )
        errors.extend(link_errors)
        errors.extend(_public_hygiene_errors(texts))
        try:
            contract_errors, public_contract_checks = _public_contract_errors(texts)
        except (ContractError, KeyError, TypeError, ValueError) as exc:
            errors.append(f"public contract validation failed closed: {exc}")
        else:
            errors.extend(contract_errors)
        initial_tree_sha256 = _public_tree_sha256(digests)
        readback = _public_final_readback(
            root,
            public_files,
            valid_directories,
            protected_seen,
            inventory_errors,
            read_tokens,
            digests,
            initial_tree_sha256,
        )
        errors.extend(readback["errors"])

    errors = sorted(set(errors))
    tree_sha256 = _public_tree_sha256(digests)
    final_public_files = readback["final_public_files"]
    return {
        "status": "pass" if not errors else "fail",
        "profile": "public-only",
        "checks": {
            "public_inventory": f"{len(public_files)}/{PUBLIC_ONLY_EXPECTED_FILES}",
            "stable_text_reads": f"{len(texts)}/{PUBLIC_ONLY_EXPECTED_FILES}",
            "final_public_inventory": f"{len(final_public_files)}/{PUBLIC_ONLY_EXPECTED_FILES}",
            "final_stable_text_reads": f"{readback['final_reads']}/{PUBLIC_ONLY_EXPECTED_FILES}",
            "final_readback": f"{readback['matching_files']}/{PUBLIC_ONLY_EXPECTED_FILES}",
            "local_links_checked": local_links_checked,
            **public_contract_checks,
        },
        "expected_public_files": PUBLIC_ONLY_EXPECTED_FILES,
        "observed_public_files": len(public_files),
        "validated_public_files": len(texts),
        "checked_units": len(texts),
        "opaque_protected_names_seen": sorted(protected_seen),
        "public_tree_sha256": tree_sha256,
        "input_readback": {
            "unchanged": readback["unchanged"],
            "inventory_unchanged": readback["inventory_unchanged"],
            "protected_names_unchanged": readback[
                "protected_names_unchanged"
            ],
            "token_set_complete": readback["token_set_complete"],
            "digest_set_complete": readback["digest_set_complete"],
            "tree_unchanged": readback["tree_unchanged"],
            "initial_tree_sha256": readback["initial_tree_sha256"],
            "final_tree_sha256": readback["final_tree_sha256"],
        },
        "runtime_evidence": runtime_evidence(),
        "network_access": "disabled",
        "subprocesses_started": 0,
        "errors": errors,
        "warnings": [],
    }


def run_public_only(root: Path, as_json: bool) -> int:
    payload = validate_public_only(root)
    _emit_public(payload, as_json)
    return 0 if payload["status"] == "pass" else 1


def main() -> int:
    configure_utf8_stdio()
    args = parse_args()
    if args.profile == "public-only":
        return run_public_only(args.root, args.json)

    from _common import ContractError as FullContractError
    from _common import emit, read_utf8

    root = args.root.resolve()
    errors: list[str] = []
    warnings: list[str] = []
    checked = 0
    if not root.is_dir():
        emit(
            {
                "status": "error",
                "errors": [f"not a directory: {root}"],
                "runtime_evidence": runtime_evidence(),
            },
            args.json,
        )
        return 2

    try:
        raw = read_utf8(root / "SKILL.md")
        frontmatter, body = parse_frontmatter(raw)
        checked += 1
        extra = set(frontmatter) - ALLOWED_FRONTMATTER
        if extra:
            errors.append(f"unexpected frontmatter keys: {sorted(extra)}")
        name = frontmatter.get("name", "")
        if name != root.name:
            errors.append(f"name/parent mismatch: {name!r} != {root.name!r}")
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name) or len(name) > 64:
            errors.append("name violates Agent Skills naming rules")
        description = frontmatter.get("description", "")
        if not isinstance(description, str) or not 1 <= len(description) <= 1024:
            errors.append("description must be 1-1024 characters")
        compatibility = frontmatter.get("compatibility")
        if compatibility is not None and (not isinstance(compatibility, str) or not 1 <= len(compatibility) <= 500):
            errors.append("compatibility must be 1-500 characters")
        metadata = frontmatter.get("metadata", {})
        if metadata and (not isinstance(metadata, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in metadata.items())):
            errors.append("metadata must map strings to strings")
        body_lines = body.count("\n") + 1
        estimated_tokens = (len(body) + 3) // 4
        if body_lines >= 500:
            errors.append(f"SKILL body has {body_lines} lines; limit is <500")
        if estimated_tokens > 5000:
            errors.append(f"SKILL body estimated at {estimated_tokens} tokens; target is <=5000")

        refs = {path.name for path in (root / "references").glob("*.md")}
        templates = {path.name for path in (root / "templates").iterdir() if path.is_file()}
        scripts = {path.name for path in (root / "scripts").glob("*.py")}
        if refs != REQUIRED_REFERENCES:
            errors.append(f"reference set mismatch: missing={sorted(REQUIRED_REFERENCES-refs)} extra={sorted(refs-REQUIRED_REFERENCES)}")
        if templates != REQUIRED_TEMPLATES:
            errors.append(f"template set mismatch: missing={sorted(REQUIRED_TEMPLATES-templates)} extra={sorted(templates-REQUIRED_TEMPLATES)}")
        if not REQUIRED_SCRIPTS.issubset(scripts):
            errors.append(f"script set missing: {sorted(REQUIRED_SCRIPTS-scripts)}")
        for reference in REQUIRED_REFERENCES:
            if f"references/{reference}" not in raw:
                errors.append(f"reference not directly routed from SKILL.md: {reference}")

        for path in [root / "SKILL.md", *sorted((root / "references").glob("*.md"))]:
            text = read_utf8(path)
            for link in local_links(path, text):
                if not link.exists():
                    errors.append(f"broken local link: {path.relative_to(root)} -> {link}")
            checked += 1

        evals = {path.name for path in (root / "evals").iterdir() if path.is_file()}
        if not REQUIRED_EVALS.issubset(evals):
            errors.append(f"eval set missing: {sorted(REQUIRED_EVALS-evals)}")

        deterministic_checks = (
            ("contract_bundle", "contract_bundle_check.py", [str(root)]),
            ("eval_v1", "eval_corpus_check.py", [str(root), "--profile", "v1"]),
            ("eval_v2", "eval_corpus_check.py", [str(root), "--profile", "v2"]),
            ("gc_state_self_test", "gc_state_simulator.py", [str(root), "--self-test"]),
        )
        for check_id, script_name, script_args in deterministic_checks:
            child_env = dict(os.environ)
            child_env["PYTHONDONTWRITEBYTECODE"] = "1"
            child_env["PYTHONUTF8"] = "1"
            child_env["PYTHONIOENCODING"] = "utf-8"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(root / "scripts" / script_name),
                    *script_args,
                    "--json",
                ],
                cwd=root,
                text=True,
                encoding="utf-8",
                errors="strict",
                capture_output=True,
                timeout=60,
                env=child_env,
            )
            try:
                payload = load_unique_json_payload(completed.stdout, check_id)
            except ContractError as exc:
                payload = {
                    "errors": [
                        str(exc),
                        completed.stdout or completed.stderr or "no output",
                    ]
                }
            errors.extend(
                deterministic_child_errors(
                    check_id,
                    completed.returncode,
                    payload,
                )
            )
            checked += 1

        scanned_texts: dict[str, str] = {}
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            relative = path.relative_to(root).as_posix()
            text = read_utf8(path)
            scanned_texts[relative] = text
            if path.name.lower() in {"readme.md", "changelog.md"}:
                errors.append(f"forbidden auxiliary file inside skill: {relative}")
            checked += 1
        errors.extend(_public_hygiene_errors(scanned_texts))
    except (OSError, ContractError, FullContractError, json.JSONDecodeError) as exc:
        errors.append(str(exc))

    payload = {
        "status": "pass" if not errors else "fail",
        "checked_units": checked,
        "errors": errors,
        "warnings": warnings,
        "runtime_evidence": runtime_evidence(),
    }
    emit(payload, args.json)
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
