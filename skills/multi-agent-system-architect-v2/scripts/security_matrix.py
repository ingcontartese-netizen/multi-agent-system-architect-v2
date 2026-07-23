#!/usr/bin/env python3
"""Run the fixed, public, oracle-free security compatibility matrix."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

sys.dont_write_bytecode = True

from _common import (  # noqa: E402
    ContractError,
    canonical_relative_posix_path,
    parse_project_version,
    parse_structured_text,
    validate_host_config,
)
from adapter_parity_check import (  # noqa: E402
    parse_manifest_bytes,
    validate_manifest,
)
from source_manifest import collect_records, fingerprint  # noqa: E402


SUITE_VERSION = "2.1.2"
SUITE_SEED = 210001
GENERATOR_CASES = 95
PARITY_CASES = 111
NEGATIVE_CASES = GENERATOR_CASES + PARITY_CASES
SCANNER_CASES = 17
ENTROPY_PRECISION_CASES = 12
SHA_FUZZ_CASES = 12
MAX_FUZZ_PATH_CODEPOINTS = 48
PORTABLE_PROPERTY_CASES = 58
TOTAL_CASES = (
    NEGATIVE_CASES
    + SCANNER_CASES
    + ENTROPY_PRECISION_CASES
    + PORTABLE_PROPERTY_CASES
)
MAX_CASES = 300
MAX_TOTAL_SECONDS = 120.0
SUBPROCESS_TIMEOUT_SECONDS = 5.0
MAX_FIXTURE_BYTES = 4096
MAX_TEMP_FILES = 32
CANONICAL_BASENAME = "multi-agent-system-architect-v2"


@dataclass(frozen=True)
class NegativeCase:
    case_id: str
    lane: str
    category: str
    probe: str
    payload: Any


@dataclass(frozen=True)
class PropertyCase:
    case_id: str
    category: str
    evaluator: str
    payload: Any
    expected: bool


def _base_config() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "canonical_source": CANONICAL_BASENAME,
        "canonical_version": "2.1.2",
        "doctrine_forks": False,
        "installation": "forbidden-before-pm-gate",
        "hosts": [
            {
                "id": "codex",
                "relative_path": "codex/multi-agent-system-architect-v2",
            },
            {
                "id": "claude",
                "relative_path": "claude/multi-agent-system-architect-v2",
            },
            {
                "id": "antigravity",
                "relative_path": "antigravity/multi-agent-system-architect-v2",
            },
        ],
    }


def _base_manifest() -> dict[str, Any]:
    digest = "A" * 64
    return {
        "schema_version": "1.0",
        "canonical_name": CANONICAL_BASENAME,
        "canonical_version": "2.1.2",
        "canonical_files": 70,
        "canonical_tree_sha256": digest,
        "entries": [
            {
                "host": "codex",
                "relative_path": "codex/multi-agent-system-architect-v2",
                "files": 70,
                "tree_sha256": digest,
            },
            {
                "host": "claude",
                "relative_path": "claude/multi-agent-system-architect-v2",
                "files": 70,
                "tree_sha256": digest,
            },
            {
                "host": "antigravity",
                "relative_path": "antigravity/multi-agent-system-architect-v2",
                "files": 70,
                "tree_sha256": digest,
            },
        ],
        "doctrine_forks": False,
    }


def _mutated(value: Any, mutate: Callable[[Any], None]) -> Any:
    candidate = copy.deepcopy(value)
    mutate(candidate)
    return candidate


def _generator_config_cases() -> list[NegativeCase]:
    cases: list[NegativeCase] = []

    def add(value: Any) -> None:
        cases.append(
            NegativeCase(
                f"G-CFG-{len(cases) + 1:03d}",
                "generator",
                "config",
                "host_config",
                value,
            )
        )

    for value in (None, [], "config", {}):
        add(value)
    for key in (
        "schema_version",
        "canonical_source",
        "canonical_version",
        "doctrine_forks",
        "installation",
        "hosts",
    ):
        add(_mutated(_base_config(), lambda item, key=key: item.pop(key)))
    add(_mutated(_base_config(), lambda item: item.update(extra=True)))
    add(_mutated(_base_config(), lambda item: item.update(schema_version="2.0")))
    add(_mutated(_base_config(), lambda item: item.update(schema_version=1)))
    add(_mutated(_base_config(), lambda item: item.update(canonical_source="")))
    add(_mutated(_base_config(), lambda item: item.update(canonical_source=" name")))
    add(_mutated(_base_config(), lambda item: item.update(canonical_source=7)))
    add(_mutated(_base_config(), lambda item: item.update(canonical_version="")))
    add(_mutated(_base_config(), lambda item: item.update(canonical_version="v2.1.0")))
    add(_mutated(_base_config(), lambda item: item.update(canonical_version="2.1")))
    add(_mutated(_base_config(), lambda item: item.update(canonical_version=210)))
    add(_mutated(_base_config(), lambda item: item.update(doctrine_forks=True)))
    add(_mutated(_base_config(), lambda item: item.update(doctrine_forks=None)))
    add(_mutated(_base_config(), lambda item: item.update(installation="allowed")))
    add(_mutated(_base_config(), lambda item: item.update(installation=None)))
    add(_mutated(_base_config(), lambda item: item.update(hosts=None)))
    add(_mutated(_base_config(), lambda item: item.update(hosts={})))
    add(_mutated(_base_config(), lambda item: item.update(hosts=[])))
    add(_mutated(_base_config(), lambda item: item.update(hosts=item["hosts"][:2])))
    add(
        _mutated(
            _base_config(),
            lambda item: item["hosts"].append(copy.deepcopy(item["hosts"][-1])),
        )
    )
    add(_mutated(_base_config(), lambda item: item["hosts"].__setitem__(0, None)))
    add(_mutated(_base_config(), lambda item: item["hosts"].__setitem__(0, [])))
    add(_mutated(_base_config(), lambda item: item["hosts"][0].pop("id")))
    add(
        _mutated(
            _base_config(), lambda item: item["hosts"][0].pop("relative_path")
        )
    )
    add(_mutated(_base_config(), lambda item: item["hosts"][0].update(extra=True)))
    add(_mutated(_base_config(), lambda item: item["hosts"][0].update(id="other")))
    add(
        _mutated(
            _base_config(),
            lambda item: item["hosts"][1].update(id=item["hosts"][0]["id"]),
        )
    )
    add(_mutated(_base_config(), lambda item: item["hosts"].reverse()))
    add(_mutated(_base_config(), lambda item: item["hosts"][0].update(id="")))
    add(_mutated(_base_config(), lambda item: item["hosts"][0].update(id=" codex")))
    add(_mutated(_base_config(), lambda item: item["hosts"][0].update(id=1)))
    assert len(cases) == 40
    return cases


def _negative_paths() -> list[Any]:
    return [
        None,
        1,
        True,
        "",
        " ",
        " a",
        "a ",
        ".",
        "..",
        "./a",
        "a/.",
        "a/..",
        "../a",
        "a/../b",
        "a//b",
        "/a",
        "//server/share",
        "C:/a",
        "C:\\a",
        "a\\b",
        "a:b",
        "a\x00b",
        "a\x01b",
        "a\x1fb",
        "con",
        "CON",
        "con.txt",
        "prn",
        "aux.log",
        "nul",
        "com1",
        "COM9.txt",
        "lpt1",
        "LPT9.log",
        "a/con/b",
        "a/prn.txt",
        "a/nul ",
        "a.",
        "a/b.",
        "a/b ",
        "a//",
        "///",
        "\\",
        "\\\\server",
        "a\tb",
    ]


def _generator_path_cases() -> list[NegativeCase]:
    cases = [
        NegativeCase(
            f"G-PATH-{index:03d}",
            "generator",
            "path",
            "canonical_path",
            value,
        )
        for index, value in enumerate(_negative_paths(), start=1)
    ]
    assert len(cases) == 45
    return cases


def _generator_parser_cases() -> list[NegativeCase]:
    valid = json.dumps(_base_config(), sort_keys=True)
    values: list[str] = [
        "\ufeff" + valid,
        valid.replace("{", "{\r\n", 1),
        valid + "\r",
        "{",
        '{"schema_version":"1.0","schema_version":"1.0"}',
        "[]",
        "null",
        '"config"',
        "210",
        '{"hosts":[{"id":"codex","id":"claude"}]}',
    ]
    return [
        NegativeCase(
            f"G-PARSE-{index:03d}",
            "generator",
            "parser_encoding",
            "structured_config",
            value,
        )
        for index, value in enumerate(values, start=1)
    ]


def generator_negative_cases() -> list[NegativeCase]:
    cases = (
        _generator_config_cases()
        + _generator_path_cases()
        + _generator_parser_cases()
    )
    assert len(cases) == GENERATOR_CASES
    return cases


def _parity_manifest_cases() -> list[NegativeCase]:
    cases: list[NegativeCase] = []

    def add(value: Any) -> None:
        cases.append(
            NegativeCase(
                f"P-MAN-{len(cases) + 1:03d}",
                "parity",
                "manifest",
                "manifest",
                value,
            )
        )

    for value in (None, [], "manifest"):
        add(value)
    for key in (
        "schema_version",
        "canonical_name",
        "canonical_version",
        "canonical_files",
        "canonical_tree_sha256",
        "entries",
        "doctrine_forks",
    ):
        add(_mutated(_base_manifest(), lambda item, key=key: item.pop(key)))
    add(_mutated(_base_manifest(), lambda item: item.update(extra=True)))
    for value in ("", None, 7, False):
        add(_mutated(_base_manifest(), lambda item, value=value: item.update(canonical_name=value)))
    for value in ("", "2", "2.1", "v2.1.0", "2.1.0.0", 210, None, False, [], {}):
        add(_mutated(_base_manifest(), lambda item, value=value: item.update(canonical_version=value)))
    for value in (-1, "70", None, 1.2, True):
        add(_mutated(_base_manifest(), lambda item, value=value: item.update(canonical_files=value)))
    for value in ("", "a" * 64, "G" * 64, "A" * 63, "A" * 65, None, 64):
        add(_mutated(_base_manifest(), lambda item, value=value: item.update(canonical_tree_sha256=value)))
    for value in (None, "false", 0, 1, []):
        add(_mutated(_base_manifest(), lambda item, value=value: item.update(doctrine_forks=value)))
    for value in (None, {}, "entries", [], _base_manifest()["entries"][:2], _base_manifest()["entries"] + [_base_manifest()["entries"][-1]]):
        add(_mutated(_base_manifest(), lambda item, value=value: item.update(entries=copy.deepcopy(value))))
    add(_mutated(_base_manifest(), lambda item: item["entries"].__setitem__(0, None)))
    add(_mutated(_base_manifest(), lambda item: item["entries"].__setitem__(0, [])))
    for key in ("host", "relative_path", "files", "tree_sha256"):
        add(_mutated(_base_manifest(), lambda item, key=key: item["entries"][0].pop(key)))
    add(_mutated(_base_manifest(), lambda item: item["entries"][0].update(extra=True)))
    assert len(cases) == 55
    return cases


def _parity_host_path_cases() -> list[NegativeCase]:
    cases: list[NegativeCase] = []

    def add(value: Any) -> None:
        cases.append(
            NegativeCase(
                f"P-HOSTPATH-{len(cases) + 1:03d}",
                "parity",
                "host_path",
                "manifest",
                value,
            )
        )

    add(_mutated(_base_manifest(), lambda item: item["entries"][0].update(host="other")))
    add(_mutated(_base_manifest(), lambda item: item["entries"][1].update(host="codex")))
    add(_mutated(_base_manifest(), lambda item: item["entries"].reverse()))
    add(_mutated(_base_manifest(), lambda item: item["entries"][0].update(host="")))
    add(_mutated(_base_manifest(), lambda item: item["entries"][0].update(host=" codex")))
    add(_mutated(_base_manifest(), lambda item: item["entries"][0].update(host=1)))
    for path in _negative_paths()[:30]:
        add(
            _mutated(
                _base_manifest(),
                lambda item, path=path: item["entries"][0].update(relative_path=path),
            )
        )
    assert len(cases) == 36
    return cases


def _parity_encoding_cases() -> list[NegativeCase]:
    valid = json.dumps(_base_manifest(), sort_keys=True).encode("utf-8")
    values = [
        b"\xef\xbb\xbf" + valid,
        valid.replace(b"{", b"{\r\n", 1),
        valid + b"\r",
        b"\xff\xfe\xfa",
        "{}".encode("utf-16-le"),
        "{}".encode("utf-16-be"),
        b'{"a":\x00}',
        b'{"a":\x0c}',
        b'{"a":1,"a":2}',
        b'{"a":',
    ]
    return [
        NegativeCase(
            f"P-ENC-{index:03d}",
            "parity",
            "encoding",
            "manifest_bytes",
            value,
        )
        for index, value in enumerate(values, start=1)
    ]


def _parity_project_cases() -> list[NegativeCase]:
    values = [
        "",
        "[tool]\nname = \"x\"\n",
        '[project]\nversion = "2.1.0"\nversion = "2.1.2"\n',
        "[project]\nversion = '2.1.0'\n",
        '[project]\nversion = "v2.1.0"\n',
        '[project]\nversion = "2.1"\n',
        "[project]\nversion = 210\n",
        '[tool]\nversion = "2.1.0"\n',
        '[project]\r\nversion = "2.1.0"\r\n',
        '\ufeff[project]\nversion = "2.1.0"\n',
    ]
    return [
        NegativeCase(
            f"P-PROJECT-{index:03d}",
            "parity",
            "project_config",
            "project_version",
            value,
        )
        for index, value in enumerate(values, start=1)
    ]


def parity_negative_cases() -> list[NegativeCase]:
    cases = (
        _parity_manifest_cases()
        + _parity_host_path_cases()
        + _parity_encoding_cases()
        + _parity_project_cases()
    )
    assert len(cases) == PARITY_CASES
    return cases


def _value_digest(value: Any) -> str:
    if isinstance(value, bytes):
        data = value
    else:
        data = json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    return hashlib.sha256(data).hexdigest().upper()


def _run_negative(case: NegativeCase) -> tuple[bool, bool, str | None]:
    payload = copy.deepcopy(case.payload)
    before = _value_digest(payload)
    rejected = False
    reason: str | None = None
    try:
        if case.probe == "host_config":
            validate_host_config(payload, label=case.case_id)
        elif case.probe == "canonical_path":
            canonical_relative_posix_path(payload, label=case.case_id)
        elif case.probe == "structured_config":
            parsed = parse_structured_text(payload, path=Path("fixture.json"))
            validate_host_config(parsed, label=case.case_id)
        elif case.probe == "manifest":
            validate_manifest(payload)
        elif case.probe == "manifest_bytes":
            parse_manifest_bytes(Path("ADAPTER_MANIFEST.json"), payload)
        elif case.probe == "project_version":
            parse_project_version(payload, path=Path("pyproject.toml"))
        else:
            reason = "unknown_probe"
    except ContractError:
        rejected = True
    except Exception as exc:  # deterministic type-only diagnostic
        reason = f"unexpected_{type(exc).__name__}"
    preserved = before == _value_digest(payload)
    return rejected, preserved, reason


FUZZ_ALPHABET = tuple(
    "abcXYZ019-_. /\\:<>?*"
    "\x00\x1f\x7f"
    "\u0301\u200b\u2044\u2215\u2216\u29f8\uff0f\uff3c"
)


def _sha_fuzz_path(index: int) -> str:
    """Return one finite SHA-derived path probe without runtime randomness."""

    if not 1 <= index <= SHA_FUZZ_CASES:
        raise ValueError("fuzz index outside declared finite scope")
    seed = hashlib.sha256(
        f"{SUITE_VERSION}:{SUITE_SEED}:portable-path:{index}".encode("utf-8")
    ).digest()
    length = 1 + seed[0] % MAX_FUZZ_PATH_CODEPOINTS
    stream = bytearray()
    counter = 0
    while len(stream) < length:
        stream.extend(hashlib.sha256(seed + counter.to_bytes(2, "big")).digest())
        counter += 1
    return "".join(FUZZ_ALPHABET[value % len(FUZZ_ALPHABET)] for value in stream[:length])


def _canonical_path_probe(value: Any, *, label: str) -> tuple[bool, bool, str | None]:
    """Call the shipped predicate and distinguish rejection from unexpected crash."""

    try:
        result = canonical_relative_posix_path(value, label=label)
    except ContractError:
        return False, True, None
    except Exception:
        return False, False, None
    return True, result == value, result


def _portable_text_valid(data: bytes) -> bool:
    if data.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")):
        return False
    if b"\r" in data or b"\x00" in data or b"\x0c" in data:
        return False
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def portable_property_cases() -> list[PropertyCase]:
    path_values: list[tuple[str, str, bool]] = [
        ("PROP-PATH-ALIAS-001", "./alpha", False),
        ("PROP-PATH-ALIAS-002", "alpha/../beta", False),
        ("PROP-PATH-ALIAS-003", "alpha//beta", False),
        ("PROP-PATH-ALIAS-004", "/alpha", False),
        ("PROP-PATH-ALIAS-005", "C:/alpha", False),
        ("PROP-PATH-ALIAS-006", "alpha\\beta", False),
        ("PROP-PATH-RESERVED-001", "con", False),
        ("PROP-PATH-RESERVED-002", "PRN.txt", False),
        ("PROP-PATH-RESERVED-003", "aux", False),
        ("PROP-PATH-RESERVED-004", "nul.log", False),
        ("PROP-PATH-RESERVED-005", "COM1", False),
        ("PROP-PATH-RESERVED-006", "folder/LPT9.txt", False),
        ("PROP-PATH-NFC-001", "caf\u00e9/file", True),
        ("PROP-PATH-NFC-002", "cafe\u0301/file", False),
        ("PROP-PATH-WINCHAR-001", "alpha<beta", False),
        ("PROP-PATH-WINCHAR-002", "alpha>beta", False),
        ("PROP-PATH-WINCHAR-003", 'alpha"beta', False),
        ("PROP-PATH-WINCHAR-004", "alpha|beta", False),
        ("PROP-PATH-WINCHAR-005", "alpha?beta", False),
        ("PROP-PATH-WINCHAR-006", "alpha*beta", False),
        ("PROP-PATH-WINCHAR-007", "alpha:beta", False),
        ("PROP-PATH-WINCHAR-008", "alpha.", False),
        ("PROP-PATH-WINCHAR-009", "alpha ", False),
        ("PROP-PATH-WINCHAR-010", "folder/beta*", False),
        ("PROP-PATH-UNICODE-001", "alpha\u2215beta", False),
        ("PROP-PATH-UNICODE-002", "alpha\u200bbeta", False),
        ("PROP-PATH-UNICODE-003", "alpha\x1fbeta", False),
        ("PROP-PATH-UNICODE-004", "alpha\x7fbeta", False),
        ("PROP-PATH-UNICODE-005", "alpha\u2044beta", False),
        ("PROP-PATH-UNICODE-006", "alpha\u2216beta", False),
        ("PROP-PATH-UNICODE-007", "alpha\u29f8beta", False),
        ("PROP-PATH-UNICODE-008", "alpha\uff0fbeta", False),
    ]
    cases = [
        PropertyCase(case_id, "path_portability", "portable_path", value, expected)
        for case_id, value, expected in path_values
    ]
    encoding_values: list[tuple[str, bytes, bool]] = [
        ("PROP-ENC-001", b"valid utf-8\n", True),
        ("PROP-ENC-002", b"\xef\xbb\xbftext\n", False),
        ("PROP-ENC-003", b"text\r\n", False),
        ("PROP-ENC-004", b"text\r", False),
        ("PROP-ENC-005", b"text\x00tail", False),
        ("PROP-ENC-006", b"text\x0ctail", False),
        ("PROP-ENC-007", "text".encode("utf-16-le"), False),
        ("PROP-ENC-008", b"\xfe\xff\x00t\x00e\x00x\x00t", False),
    ]
    cases.extend(
        PropertyCase(case_id, "encoding", "portable_text", value, expected)
        for case_id, value, expected in encoding_values
    )
    parser_values: list[tuple[str, Any, bool]] = [
        ("PROP-SHAPE-001", _base_config(), True),
        ("PROP-SHAPE-002", [], False),
        (
            "PROP-SHAPE-003",
            _mutated(_base_config(), lambda item: item.pop("hosts")),
            False,
        ),
        (
            "PROP-SHAPE-004",
            _mutated(_base_config(), lambda item: item.update(extra=True)),
            False,
        ),
        (
            "PROP-SHAPE-005",
            _mutated(
                _base_config(),
                lambda item: item["hosts"][1].update(id="codex"),
            ),
            False,
        ),
        ("PROP-SHAPE-006", _base_manifest(), True),
    ]
    cases.extend(
        PropertyCase(case_id, "parser_shape", "structured_shape", value, expected)
        for case_id, value, expected in parser_values
    )
    cases.extend(
        PropertyCase(
            f"PROP-PATH-FUZZ-{index:03d}",
            "path_fuzz_no_crash",
            "portable_path_no_crash",
            _sha_fuzz_path(index),
            True,
        )
        for index in range(1, SHA_FUZZ_CASES + 1)
    )
    assert len(cases) == PORTABLE_PROPERTY_CASES
    return cases


def _run_property(case: PropertyCase) -> tuple[bool, bool]:
    payload = copy.deepcopy(case.payload)
    before = _value_digest(payload)
    if case.evaluator == "portable_path":
        accepted, completed, _ = _canonical_path_probe(payload, label=case.case_id)
        actual = completed and accepted == case.expected
        return actual, before == _value_digest(payload)
    elif case.evaluator == "portable_path_no_crash":
        first = _canonical_path_probe(payload, label=case.case_id)
        second = _canonical_path_probe(payload, label=case.case_id)
        actual = (
            first[1]
            and second[1]
            and first == second
            and (not first[0] or first[2] == payload)
        )
    elif case.evaluator == "portable_text":
        actual = _portable_text_valid(payload)
    elif case.evaluator == "structured_shape":
        try:
            if isinstance(payload, dict) and "entries" in payload:
                validate_manifest(payload)
            else:
                validate_host_config(payload, label=case.case_id)
            actual = True
        except ContractError:
            actual = False
    else:
        actual = not case.expected
    return actual == case.expected, before == _value_digest(payload)


def scanner_case_ids() -> list[str]:
    return [f"SCAN-COMPAT-{index:03d}" for index in range(1, SCANNER_CASES + 1)]


def entropy_precision_case_ids() -> list[str]:
    return [
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


def _scanner_specs() -> list[tuple[str, str | None, str, bool]]:
    alpha = "A1" * 12
    beta = "B2" * 12
    specs = [
        ("openai_key", "sk-" + alpha, True),
        ("anthropic_key", "sk-" + "ant-" + beta, True),
        ("google_key", "AI" + "za" + ("C3" * 16), True),
        ("github_token", "gh" + "p_" + ("D4" * 16), True),
        ("github_fine_grained_token", "github_" + "pat_" + ("E5" * 12), True),
        ("gitlab_token", "gl" + "pat-" + ("F6" * 12), True),
        ("stripe_secret_key", "sk_" + "live_" + ("G7" * 8), True),
        ("slack_token", "xox" + "b-" + ("H8" * 10), True),
        ("aws_access_key", "AK" + "IA" + ("J9" * 8), True),
        ("private_key", "-----BEGIN " + "PRIVATE KEY-----", True),
        ("jwt", "eyJabcde" + "." + "ABCDE12" + "." + "FGHIJ34", True),
        (
            "database_url",
            "postgres" + "ql://user:" + "passW0rd" + "@db.example",
            True,
        ),
        (
            "azure_storage_connection",
            "DefaultEndpointsProtocol=https;AccountName=test;AccountKey="
            + ("K0" * 10),
            True,
        ),
        (
            "bearer_token",
            "Authorization: " + "Bearer " + ("L1" * 10),
            True,
        ),
        ("generic_secret", "client_" + "secret=" + ("M2" * 10), True),
        (None, "ordinary documentation without credentials", False),
        (None, "api_key=short\ntoken=${TOKEN}\npassword=example", False),
    ]
    assert len(specs) == SCANNER_CASES
    return [
        (case_id, pattern, content, should_find)
        for case_id, (pattern, content, should_find) in zip(
            scanner_case_ids(), specs, strict=True
        )
    ]


def _run_scanner_matrix(
    root: Path,
    temp_root: Path,
    deadline: float,
) -> tuple[list[str], list[str], int]:
    scanner = root / "scripts" / "secret_scan.py"
    failures: list[str] = []
    passed: list[str] = []
    preserved = 0
    specs = _scanner_specs()
    if len(specs) > MAX_TEMP_FILES:
        return passed, ["scanner:temp_file_cap"], preserved
    for index, (case_id, expected_pattern, content, should_find) in enumerate(specs):
        if time.monotonic() >= deadline:
            failures.append(f"{case_id}:time_cap")
            continue
        fixture_dir = temp_root / f"scanner-{index + 1:03d}"
        fixture_dir.mkdir()
        fixture = fixture_dir / "fixture.txt"
        data = (content + "\n").encode("utf-8")
        if len(data) > MAX_FIXTURE_BYTES:
            failures.append(f"{case_id}:fixture_cap")
            continue
        fixture.write_bytes(data)
        before = fixture.read_bytes()
        try:
            completed = subprocess.run(
                [sys.executable, os.fspath(scanner), os.fspath(fixture_dir), "--json"],
                cwd=temp_root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=SUBPROCESS_TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired:
            failures.append(f"{case_id}:timeout")
            continue
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError:
            failures.append(f"{case_id}:invalid_json")
            continue
        leaked = content in completed.stdout or content in completed.stderr
        findings = payload.get("findings", [])
        matching = [
            item
            for item in findings
            if isinstance(item, dict) and item.get("pattern") == expected_pattern
        ]
        if should_find:
            behavior_ok = (
                completed.returncode == 1
                and payload.get("status") == "fail"
                and any(
                    set(item) == {"pattern", "path", "line"}
                    and item["path"] == "fixture.txt"
                    and item["line"] == 1
                    for item in matching
                )
            )
        else:
            behavior_ok = (
                completed.returncode == 0
                and payload.get("status") == "pass"
                and findings == []
            )
        files = sorted(
            path.relative_to(fixture_dir).as_posix()
            for path in fixture_dir.rglob("*")
            if path.is_file()
        )
        input_preserved = fixture.read_bytes() == before
        outputs_absent = files == ["fixture.txt"]
        if behavior_ok and not leaked and input_preserved and outputs_absent:
            passed.append(case_id)
            preserved += 1
        else:
            failures.append(f"{case_id}:compatibility_failure")
    return passed, failures, preserved


def _entropy_specs() -> list[tuple[str, str, str | None, str, str, bool]]:
    semantic = "aB3d" + "E5fG" + "7hJ9" + "kLmN" + "2pQr" + "StUv"
    semantic_two = "zY8x" + "W6vU" + "4tSr" + "Q2pO" + "nM7l" + "K5jI"
    bare_hex = ("01234567" + "89abcdef") * 3
    bare_base64 = "Ab3+/Cd5" + "_Ef7-Gh9" + "/Ij2+Kl4="
    common_digest = ("01234567" + "89abcdef") * 4
    uuid = "123e4567" + "-e89b-12d3-a456-" + "426614174000"
    return [
        (
            "SCAN-ENTROPY-SEMANTIC-ASSIGNMENT",
            "fixture.env",
            "entropy_semantic_assignment",
            "client_secret=" + semantic,
            semantic,
            True,
        ),
        (
            "SCAN-ENTROPY-NATIVE-NPMRC",
            ".npmrc",
            "entropy_native_npmrc",
            "//registry.example/:_authToken=" + semantic_two,
            semantic_two,
            True,
        ),
        (
            "SCAN-ENTROPY-NATIVE-NETRC",
            ".netrc",
            "entropy_native_netrc",
            "machine example login user password " + semantic,
            semantic,
            True,
        ),
        (
            "SCAN-ENTROPY-NATIVE-PGPASS",
            ".pgpass",
            "entropy_native_pgpass",
            "db.example:5432:app:user:" + semantic_two,
            semantic_two,
            True,
        ),
        (
            "SCAN-ENTROPY-BARE-HEX",
            "fixture.key",
            "entropy_bare_hex",
            bare_hex,
            bare_hex,
            True,
        ),
        (
            "SCAN-ENTROPY-BARE-BASE64",
            "fixture.pem",
            "entropy_bare_base64",
            bare_base64,
            bare_base64,
            True,
        ),
        (
            "SCAN-PRECISION-COMMON-DIGEST",
            "fixture.key",
            None,
            common_digest,
            common_digest,
            False,
        ),
        (
            "SCAN-PRECISION-UUID",
            "fixture.env",
            None,
            "session_id=" + uuid,
            uuid,
            False,
        ),
        (
            "SCAN-PRECISION-PLACEHOLDER",
            "fixture.env",
            None,
            "client_secret=replace_me_with_your_secret",
            "replace_me_with_your_secret",
            False,
        ),
        (
            "SCAN-PRECISION-NONSECRET-SUFFIX",
            "fixture.env",
            None,
            "api_key_hash=" + semantic,
            semantic,
            False,
        ),
        (
            "SCAN-PRECISION-GENERIC-NAME",
            "fixture.env",
            None,
            "session_id=" + semantic_two,
            semantic_two,
            False,
        ),
        (
            "SCAN-PRECISION-LOW-ENTROPY",
            "fixture.env",
            None,
            "session_id=" + ("A" * 32),
            "A" * 32,
            False,
        ),
    ]


def _run_entropy_matrix(
    root: Path,
    temp_root: Path,
    deadline: float,
) -> tuple[list[str], list[str], int]:
    scanner = root / "scripts" / "secret_scan.py"
    failures: list[str] = []
    passed: list[str] = []
    preserved = 0
    specs = _entropy_specs()
    if [item[0] for item in specs] != entropy_precision_case_ids():
        return passed, ["entropy:case_registry_drift"], preserved
    for index, (case_id, filename, expected_kind, content, token, should_find) in enumerate(specs):
        if time.monotonic() >= deadline:
            failures.append(f"{case_id}:time_cap")
            continue
        fixture_dir = temp_root / f"entropy-{index + 1:03d}"
        fixture_dir.mkdir()
        fixture = fixture_dir / filename
        data = (content + "\n").encode("utf-8")
        if len(data) > MAX_FIXTURE_BYTES:
            failures.append(f"{case_id}:fixture_cap")
            continue
        fixture.write_bytes(data)
        before = fixture.read_bytes()
        expected_hash = hashlib.sha256(token.encode("utf-8")).hexdigest().upper()
        try:
            completed = subprocess.run(
                [
                    sys.executable,
                    os.fspath(scanner),
                    os.fspath(fixture_dir),
                    "--entropy",
                    "--json",
                ],
                cwd=temp_root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=SUBPROCESS_TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired:
            failures.append(f"{case_id}:timeout")
            continue
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError:
            failures.append(f"{case_id}:invalid_json")
            continue
        leaked = content in completed.stdout or content in completed.stderr
        regex_findings = payload.get("findings", [])
        entropy_findings = payload.get("entropy_findings", [])
        matching = [
            item
            for item in entropy_findings
            if isinstance(item, dict) and item.get("kind") == expected_kind
        ]
        if should_find:
            behavior_ok = (
                completed.returncode == 1
                and payload.get("status") == "fail"
                and any(
                    {"kind", "path", "line", "token_sha256", "length"}
                    <= set(item)
                    and item["path"] == filename
                    and item["line"] == 1
                    and item["token_sha256"] == expected_hash
                    and item["length"] == len(token)
                    for item in matching
                )
            )
        else:
            behavior_ok = (
                completed.returncode == 0
                and payload.get("status") == "pass"
                and regex_findings == []
                and entropy_findings == []
            )
        files = sorted(
            path.relative_to(fixture_dir).as_posix()
            for path in fixture_dir.rglob("*")
            if path.is_file()
        )
        input_preserved = fixture.read_bytes() == before
        outputs_absent = files == [filename]
        if behavior_ok and not leaked and input_preserved and outputs_absent:
            passed.append(case_id)
            preserved += 1
        else:
            failures.append(f"{case_id}:entropy_precision_failure")
    return passed, failures, preserved


def _ids_digest(case_ids: list[str]) -> str:
    return hashlib.sha256("\n".join(case_ids).encode("utf-8")).hexdigest().upper()


def all_case_ids() -> dict[str, list[str]]:
    generator = [case.case_id for case in generator_negative_cases()]
    parity = [case.case_id for case in parity_negative_cases()]
    scanner = scanner_case_ids()
    entropy_precision = entropy_precision_case_ids()
    portable = [case.case_id for case in portable_property_cases()]
    return {
        "generator": generator,
        "parity": parity,
        "scanner": scanner,
        "scanner_entropy_precision": entropy_precision,
        "portable_properties": portable,
    }


def _platform_evidence() -> dict[str, str]:
    return {
        "windows": "live" if os.name == "nt" else "modeled_not_live_verified",
        "linux": "modeled_not_live_verified",
        "macos": "modeled_not_live_verified",
    }


def _declared_limits() -> dict[str, Any]:
    fuzz_corpus = [_sha_fuzz_path(index) for index in range(1, SHA_FUZZ_CASES + 1)]
    return {
        "linux_case_sensitivity": "modeled_not_live_verified",
        "macos_normalization_and_firmlink": "modeled_not_live_verified",
        "posix_permissions": "not_exercised",
        "finite_fuzz_scope": {
            "cases": SHA_FUZZ_CASES,
            "corpus_sha256": _value_digest(fuzz_corpus),
            "derivation": "SHA-256",
            "invariant": "no_crash_and_repeatable_outcome",
            "max_path_codepoints": MAX_FUZZ_PATH_CODEPOINTS,
        },
    }


def run_matrix(root: Path) -> dict[str, Any]:
    root = root.resolve()
    if not root.is_dir() or root.name != CANONICAL_BASENAME:
        raise ContractError("root must be the canonical skill directory")
    required = [
        root / "SKILL.md",
        root / "scripts" / "secret_scan.py",
        root / "scripts" / "generate_host_adapters.py",
        root / "scripts" / "adapter_parity_check.py",
    ]
    if not all(path.is_file() for path in required):
        raise ContractError("root is missing required public entrypoints")

    ids = all_case_ids()
    ordered_ids = (
        ids["generator"]
        + ids["parity"]
        + ids["scanner"]
        + ids["scanner_entropy_precision"]
        + ids["portable_properties"]
    )
    if len(ordered_ids) != TOTAL_CASES or len(set(ordered_ids)) != TOTAL_CASES:
        raise ContractError("case registry denominator or uniqueness failure")
    if len(ordered_ids) > MAX_CASES:
        raise ContractError("case cap exceeded")

    source_records_before = collect_records(root)
    _, source_hash_before = fingerprint(source_records_before)
    deadline = time.monotonic() + MAX_TOTAL_SECONDS
    failures: list[str] = []
    negative_passed: list[str] = []
    typed_preserved = 0
    for case in generator_negative_cases() + parity_negative_cases():
        if time.monotonic() >= deadline:
            failures.append(f"{case.case_id}:time_cap")
            continue
        rejected, preserved, reason = _run_negative(case)
        if rejected and preserved and reason is None:
            negative_passed.append(case.case_id)
            typed_preserved += 1
        else:
            suffix = reason or ("accepted" if not rejected else "input_mutated")
            failures.append(f"{case.case_id}:{suffix}")

    property_passed: list[str] = []
    property_preserved = 0
    for case in portable_property_cases():
        if time.monotonic() >= deadline:
            failures.append(f"{case.case_id}:time_cap")
            continue
        correct, preserved = _run_property(case)
        if correct and preserved:
            property_passed.append(case.case_id)
            property_preserved += 1
        else:
            failures.append(f"{case.case_id}:property_failure")

    with tempfile.TemporaryDirectory(prefix="masa-security-matrix-") as temp_name:
        temp_root = Path(temp_name)
        scanner_passed, scanner_failures, scanner_preserved = _run_scanner_matrix(
            root,
            temp_root,
            deadline,
        )
        entropy_passed, entropy_failures, entropy_preserved = _run_entropy_matrix(
            root,
            temp_root,
            deadline,
        )
    failures.extend(scanner_failures)
    failures.extend(entropy_failures)

    source_records_after = collect_records(root)
    _, source_hash_after = fingerprint(source_records_after)
    source_unchanged = (
        source_records_before == source_records_after
        and source_hash_before == source_hash_after
    )
    if not source_unchanged:
        failures.append("source:readback_drift")

    group_digests = {name: _ids_digest(values) for name, values in ids.items()}
    payload = {
        "case_ids": ids,
        "declared_limits": _declared_limits(),
        "denominators": {
            "generator_negative": f"{sum(case_id in negative_passed for case_id in ids['generator'])}/{GENERATOR_CASES}",
            "parity_negative": f"{sum(case_id in negative_passed for case_id in ids['parity'])}/{PARITY_CASES}",
            "negative_total": f"{len(negative_passed)}/{NEGATIVE_CASES}",
            "scanner_compatibility": f"{len(scanner_passed)}/{SCANNER_CASES}",
            "scanner_entropy_precision": f"{len(entropy_passed)}/{ENTROPY_PRECISION_CASES}",
            "portable_properties": f"{len(property_passed)}/{PORTABLE_PROPERTY_CASES}",
            "total": f"{len(negative_passed) + len(scanner_passed) + len(entropy_passed) + len(property_passed)}/{TOTAL_CASES}",
        },
        "digests": {
            **group_digests,
            "negative_ordered": _ids_digest(ids["generator"] + ids["parity"]),
            "all_ordered": _ids_digest(ordered_ids),
        },
        "errors": failures,
        "platform_evidence": _platform_evidence(),
        "preservation": {
            "typed_inputs": f"{typed_preserved}/{NEGATIVE_CASES}",
            "portable_inputs": f"{property_preserved}/{PORTABLE_PROPERTY_CASES}",
            "scanner_inputs_and_outputs": f"{scanner_preserved}/{SCANNER_CASES}",
            "entropy_inputs_and_outputs": f"{entropy_preserved}/{ENTROPY_PRECISION_CASES}",
            "source_unchanged": source_unchanged,
        },
        "resources": {
            "case_cap": MAX_CASES,
            "fixture_bytes_cap": MAX_FIXTURE_BYTES,
            "subprocess_timeout_seconds": SUBPROCESS_TIMEOUT_SECONDS,
            "temp_file_cap": MAX_TEMP_FILES,
            "total_timeout_seconds": MAX_TOTAL_SECONDS,
        },
        "seed": SUITE_SEED,
        "source_readback": {
            "files_before": len(source_records_before),
            "files_after": len(source_records_after),
            "sha256_before": source_hash_before,
            "sha256_after": source_hash_after,
        },
        "status": "pass" if not failures else "fail",
        "suite_version": SUITE_VERSION,
    }
    return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="Canonical skill root")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def _emit(payload: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    print(f"status: {payload['status']}")
    print(f"suite_version: {payload['suite_version']}")
    print(f"seed: {payload['seed']}")
    print(f"denominators: {json.dumps(payload['denominators'], sort_keys=True)}")
    print(f"digests: {json.dumps(payload['digests'], sort_keys=True)}")
    print(f"errors: {json.dumps(payload['errors'])}")


def main() -> int:
    args = parse_args()
    try:
        payload = run_matrix(args.root)
    except (OSError, ContractError, ValueError) as exc:
        payload = {
            "status": "error",
            "suite_version": SUITE_VERSION,
            "seed": SUITE_SEED,
            "error": type(exc).__name__,
        }
        _emit(payload, args.json)
        return 2
    _emit(payload, args.json)
    return 0 if payload["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
