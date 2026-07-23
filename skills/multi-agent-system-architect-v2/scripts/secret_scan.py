#!/usr/bin/env python3
"""Scan governed text files for obvious credential material."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from _common import ContractError, emit


PATTERNS = {
    "openai_key": re.compile(r"sk-(?!ant-)[A-Za-z0-9_-]{20,}"),
    "anthropic_key": re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
    "google_key": re.compile(r"AIza[0-9A-Za-z_-]{30,}"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
    "github_fine_grained_token": re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    "gitlab_token": re.compile(r"glpat-[A-Za-z0-9_-]{20,}"),
    "stripe_secret_key": re.compile(
        r"(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}"
    ),
    "slack_token": re.compile(
        r"(?:xox[baprs]-[0-9A-Za-z-]{20,}|xapp-[0-9A-Za-z-]{20,})"
    ),
    "aws_access_key": re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "jwt": re.compile(
        r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"
    ),
    "database_url": re.compile(
        r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis)://"
        r"[^/\s:@]+:[^@\s/]{8,}@[^\s/]+"
    ),
    "azure_storage_connection": re.compile(
        r"(?i)\bDefaultEndpointsProtocol=https?;[^\r\n]*"
        r"\bAccountKey=[A-Za-z0-9+/=]{16,}"
    ),
    "bearer_token": re.compile(
        r"(?i)\bAuthorization\s*[:=]\s*['\"]?Bearer\s+"
        r"[A-Za-z0-9._~+/=-]{16,}"
    ),
    "generic_secret": re.compile(
        r"(?x)(?<![A-Za-z0-9])(?i:("
        r"api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|"
        r"aws[_-]?secret[_-]?access[_-]?key|secret|password|passwd|pwd|token|credential"
        r"))\s*[:=]\s*(?:['\"][^'\"\r\n]{8,}['\"]|"
        r"(?=[A-Za-z0-9_./+=:@-]{16,})(?=[A-Za-z0-9_./+=:@-]*[0-9A-Z+/=@:-])"
        r"[A-Za-z0-9_./+=:@-]{16,})"
    ),
}
TEXT_SUFFIXES = {
    ".bash",
    ".bat",
    ".cfg",
    ".cmd",
    ".conf",
    ".env",
    ".ini",
    ".json",
    ".key",
    ".md",
    ".pem",
    ".properties",
    ".ps1",
    ".py",
    ".sh",
    ".toml",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
    ".zsh",
}
EXTENSIONLESS_TEXT_NAMES = {
    ".envrc",
    ".git-credentials",
    ".netrc",
    ".npmrc",
    ".pgpass",
    ".pypirc",
    "brewfile",
    "config",
    "containerfile",
    "credentials",
    "dockerfile",
    "gemfile",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "jenkinsfile",
    "makefile",
    "procfile",
    "rakefile",
    "secrets",
    "vagrantfile",
}
SELF = Path("scripts/secret_scan.py")
POLICY_VERSION = "2.1.0"
MAX_FILES = 10_000
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MIN_SEMANTIC_LENGTH = 20
MIN_LOWER_LENGTH = 24
MIN_BARE_LENGTH = 24
MIN_HEX_LENGTH = 32
MIN_SEMANTIC_ENTROPY = 3.7
MIN_LOWER_ENTROPY = 3.5
MIN_BASE64_ENTROPY = 4.0
MIN_HEX_ENTROPY = 3.25
EXCLUDED_PARTS = frozenset({".git", ".pytest_cache", "__pycache__"})
HIGH_RISK_NAMES = frozenset(
    {
        ".envrc",
        ".git-credentials",
        ".netrc",
        ".npmrc",
        ".pgpass",
        ".pypirc",
        "credentials",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
        "secrets",
    }
)
HIGH_RISK_SUFFIXES = frozenset({".key", ".pem"})
ENTROPY_DETECTORS = (
    "entropy_bare_base64",
    "entropy_bare_hex",
    "entropy_native_netrc",
    "entropy_native_npmrc",
    "entropy_native_pgpass",
    "entropy_semantic_assignment",
)
LAYERS = (
    "carrier_selection",
    "bounded_utf8",
    "regex_signatures",
    "context_gated_entropy",
    "redacted_reporting",
)
SEMANTIC_TERMINALS = frozenset(
    {"credential", "passwd", "password", "pwd", "secret", "token"}
)
KEY_QUALIFIERS = frozenset(
    {
        "access",
        "api",
        "client",
        "encryption",
        "jwt",
        "private",
        "secret",
        "signing",
    }
)
NON_SECRET_SUFFIXES = frozenset(
    {
        "checksum",
        "count",
        "digest",
        "example",
        "hash",
        "hint",
        "id",
        "name",
        "placeholder",
        "sha",
        "sha1",
        "sha256",
        "sha512",
        "uuid",
    }
)
PLACEHOLDER_MARKERS = (
    "${",
    "{{",
    "<secret",
    "changeme",
    "change_me",
    "dummy",
    "example",
    "fake",
    "not-a-real",
    "notareal",
    "placeholder",
    "redacted",
    "replace_me",
    "sample",
    "xxxxx",
    "your-",
    "your_",
)
COMMON_DIGEST_HEX_LENGTHS = frozenset({32, 40, 64, 96, 128})
UUID_RE = re.compile(
    r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
HEX_RE = re.compile(r"(?i)^[0-9a-f]+$")
BASE64_RE = re.compile(r"^[A-Za-z0-9+/_-]+={0,2}$")
ASSIGNMENT_RE = re.compile(
    r"^[ \t]*(?:[\"'](?P<quoted_name>[A-Za-z_][A-Za-z0-9_.-]{0,79})[\"']|"
    r"(?P<bare_name>[A-Za-z_][A-Za-z0-9_.-]{0,79}))[ \t]*[:=][ \t]*"
    r"(?:\"(?P<double_value>[^\"\r\n]+)\"|'(?P<single_value>[^'\r\n]+)'|"
    r"(?P<bare_value>[A-Za-z0-9_./+=:@-]+))[ \t]*(?:[,;][ \t]*)?(?:#.*)?$"
)
JSON_ASSIGNMENT_RE = re.compile(
    r"(?:\"(?P<double_name>[A-Za-z_][A-Za-z0-9_.-]{0,79})\"|"
    r"'(?P<single_name>[A-Za-z_][A-Za-z0-9_.-]{0,79})')[ \t]*:[ \t]*"
    r"(?:\"(?P<double_value>[^\"\r\n]+)\"|'(?P<single_value>[^'\r\n]+)')"
)
NPMRC_RE = re.compile(
    r"(?i)^[ \t]*[^=\r\n]*(?P<name>_authToken|_auth|password)[ \t]*="
    r"[ \t]*(?P<value>[^\s#;]+)[ \t]*(?:[;#].*)?$"
)
NETRC_RE = re.compile(r"(?i)\b(?:password|account)[ \t]+(?P<value>[^\s#]+)")


def metadata_token(value: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        stat.S_IFMT(value.st_mode),
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_nlink),
        int(value.st_size),
        int(value.st_mtime_ns),
        int(value.st_ctime_ns),
        int(getattr(value, "st_file_attributes", 0)),
    )


def path_handle_token(value: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    """Comparable subset because Windows path/handle ctime semantics differ."""

    token = metadata_token(value)
    return (*token[:6], token[7])


def is_reparse(value: os.stat_result) -> bool:
    attributes = int(getattr(value, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(value.st_mode) or bool(attributes & reparse_flag)


def validate_plain_directory(path: Path, *, label: str) -> os.stat_result:
    value = os.lstat(path)
    if not stat.S_ISDIR(value.st_mode) or is_reparse(value):
        raise ContractError(f"{label} must be a plain directory")
    return value


def validate_plain_file(value: os.stat_result, *, label: str) -> None:
    if not stat.S_ISREG(value.st_mode) or is_reparse(value):
        raise ContractError(f"{label} must be a plain file")
    if int(value.st_nlink) != 1:
        raise ContractError(f"{label} must not be hardlinked")


def physical_inventory(root: Path):
    root_before = validate_plain_directory(root, label="scan root")

    def walk_error(error: OSError) -> None:
        raise error

    for current, directories, files in os.walk(
        root, topdown=True, followlinks=False, onerror=walk_error
    ):
        current_path = Path(current)
        validate_plain_directory(current_path, label="inventory directory")
        retained: list[str] = []
        for name in sorted(directories):
            candidate = current_path / name
            validate_plain_directory(candidate, label="inventory directory")
            if name not in EXCLUDED_PARTS:
                retained.append(name)
        directories[:] = retained
        for name in sorted(files):
            candidate = current_path / name
            relative = candidate.relative_to(root)
            value = os.lstat(candidate)
            validate_plain_file(value, label=f"inventory file {relative.as_posix()}")
            yield candidate, relative, value
    if metadata_token(validate_plain_directory(root, label="scan root")) != metadata_token(
        root_before
    ):
        raise ContractError("scan root changed during inventory")


def stable_read_utf8(
    path: Path, *, relative: Path, expected: os.stat_result
) -> tuple[str, int]:
    path_before = os.lstat(path)
    validate_plain_file(path_before, label=f"scan file {relative.as_posix()}")
    if metadata_token(path_before) != metadata_token(expected):
        raise ContractError(f"file changed before scan: {relative.as_posix()}")
    with path.open("rb") as stream:
        handle_before = os.fstat(stream.fileno())
        validate_plain_file(handle_before, label=f"scan file {relative.as_posix()}")
        if path_handle_token(handle_before) != path_handle_token(path_before):
            raise ContractError(f"path/handle mismatch: {relative.as_posix()}")
        data = stream.read()
        handle_after = os.fstat(stream.fileno())
    path_after = os.lstat(path)
    if metadata_token(handle_before) != metadata_token(handle_after):
        raise ContractError(f"file changed during scan: {relative.as_posix()}")
    if metadata_token(path_before) != metadata_token(path_after):
        raise ContractError(f"file changed during scan: {relative.as_posix()}")
    if path_handle_token(handle_after) != path_handle_token(path_after):
        raise ContractError(f"file changed during scan: {relative.as_posix()}")
    if len(data) != int(path_after.st_size):
        raise ContractError(f"file size drift during scan: {relative.as_posix()}")
    if data.startswith(b"\xef\xbb\xbf"):
        raise ContractError(f"UTF-8 BOM is not allowed: {relative.as_posix()}")
    if b"\r" in data:
        raise ContractError(f"Line endings must be LF: {relative.as_posix()}")
    if b"\x00" in data:
        raise ContractError(f"NUL byte is not allowed: {relative.as_posix()}")
    try:
        return data.decode("utf-8"), len(data)
    except UnicodeDecodeError as exc:
        raise ContractError(
            f"Invalid UTF-8 in {relative.as_posix()}: {exc}"
        ) from exc


def is_scannable_text(path: Path) -> bool:
    name = path.name.casefold()
    return (
        path.suffix.casefold() in TEXT_SUFFIXES
        or name in EXTENSIONLESS_TEXT_NAMES
        or name == ".env"
        or name.startswith(".env.")
    )


def is_high_risk_carrier(path: Path) -> bool:
    name = path.name.casefold()
    return (
        name in HIGH_RISK_NAMES
        or path.suffix.casefold() in HIGH_RISK_SUFFIXES
        or name == ".env"
        or name.startswith(".env.")
    )


def shannon_entropy(value: str) -> float:
    length = len(value)
    if not length:
        return 0.0
    return -sum(
        (count / length) * math.log2(count / length)
        for count in {character: value.count(character) for character in set(value)}.values()
    )


def is_placeholder(value: str) -> bool:
    folded = value.casefold()
    return any(marker in folded for marker in PLACEHOLDER_MARKERS)


def is_semantic_secret_name(name: str) -> bool:
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    tokens = [
        token
        for token in re.split(r"[^A-Za-z0-9]+", separated.casefold())
        if token
    ]
    if not tokens or tokens[-1] in NON_SECRET_SUFFIXES:
        return False
    terminal = tokens[-1]
    if terminal in SEMANTIC_TERMINALS:
        return True
    return terminal == "key" and any(token in KEY_QUALIFIERS for token in tokens[:-1])


def is_high_entropy(value: str, *, mode: str) -> bool:
    candidate = value.strip().strip("\"'")
    if (
        len(candidate) < 16
        or len(candidate) > 4096
        or any(character.isspace() for character in candidate)
        or UUID_RE.fullmatch(candidate)
        or is_placeholder(candidate)
    ):
        return False
    unique = len(set(candidate))
    entropy = shannon_entropy(candidate)
    if mode == "hex":
        return (
            len(candidate) >= MIN_HEX_LENGTH
            and len(candidate) not in COMMON_DIGEST_HEX_LENGTHS
            and HEX_RE.fullmatch(candidate) is not None
            and unique >= 10
            and entropy >= MIN_HEX_ENTROPY
        )
    if mode == "base64":
        return (
            len(candidate) >= MIN_BARE_LENGTH
            and BASE64_RE.fullmatch(candidate) is not None
            and HEX_RE.fullmatch(candidate) is None
            and unique >= 16
            and entropy >= MIN_BASE64_ENTROPY
        )
    if HEX_RE.fullmatch(candidate):
        return (
            len(candidate) >= MIN_LOWER_LENGTH
            and unique >= 10
            and entropy >= MIN_HEX_ENTROPY
        )
    if candidate.isalpha() and candidate.islower():
        return (
            len(candidate) >= MIN_LOWER_LENGTH
            and unique >= 12
            and entropy >= MIN_LOWER_ENTROPY
        )
    classes = sum(
        any(check(character) for character in candidate)
        for check in (str.islower, str.isupper, str.isdigit)
    ) + int(any(not character.isalnum() for character in candidate))
    return (
        len(candidate) >= MIN_SEMANTIC_LENGTH
        and unique >= 12
        and classes >= 2
        and entropy >= MIN_SEMANTIC_ENTROPY
    )


def iter_entropy_findings(text: str, relative: Path):
    high_risk = is_high_risk_carrier(relative)
    name = relative.name.casefold()
    for line_number, line in enumerate(text.splitlines(), start=1):
        assignment = ASSIGNMENT_RE.fullmatch(line)
        if assignment:
            key = assignment.group("quoted_name") or assignment.group("bare_name")
            value = (
                assignment.group("double_value")
                or assignment.group("single_value")
                or assignment.group("bare_value")
            )
            if is_semantic_secret_name(key) and is_high_entropy(value, mode="semantic"):
                yield "entropy_semantic_assignment", line_number, value

        for pair in JSON_ASSIGNMENT_RE.finditer(line):
            key = pair.group("double_name") or pair.group("single_name")
            value = pair.group("double_value") or pair.group("single_value")
            if is_semantic_secret_name(key) and is_high_entropy(value, mode="semantic"):
                yield "entropy_semantic_assignment", line_number, value

        if name == ".npmrc":
            native = NPMRC_RE.fullmatch(line)
            if native and is_high_entropy(native.group("value"), mode="semantic"):
                yield "entropy_native_npmrc", line_number, native.group("value")

        if name == ".netrc":
            for native in NETRC_RE.finditer(line):
                if is_high_entropy(native.group("value"), mode="semantic"):
                    yield "entropy_native_netrc", line_number, native.group("value")

        if name == ".pgpass" and line and not line.lstrip().startswith("#"):
            fields = line.split(":")
            if len(fields) >= 5 and is_high_entropy(fields[-1], mode="semantic"):
                yield "entropy_native_pgpass", line_number, fields[-1]

        if not high_risk:
            continue
        bare = line.strip().strip("\"'")
        if is_high_entropy(bare, mode="hex"):
            yield "entropy_bare_hex", line_number, bare
        elif is_high_entropy(bare, mode="base64"):
            yield "entropy_bare_base64", line_number, bare


def entropy_config_sha256() -> str:
    config = {
        "common_digest_hex_lengths": sorted(COMMON_DIGEST_HEX_LENGTHS),
        "detectors": list(ENTROPY_DETECTORS),
        "high_risk_names": sorted(HIGH_RISK_NAMES),
        "high_risk_suffixes": sorted(HIGH_RISK_SUFFIXES),
        "limits": {
            "max_file_bytes": MAX_FILE_BYTES,
            "max_files": MAX_FILES,
            "max_total_bytes": MAX_TOTAL_BYTES,
        },
        "policy_version": POLICY_VERSION,
        "thresholds": {
            "base64_entropy": MIN_BASE64_ENTROPY,
            "bare_length": MIN_BARE_LENGTH,
            "hex_entropy": MIN_HEX_ENTROPY,
            "hex_length": MIN_HEX_LENGTH,
            "lower_entropy": MIN_LOWER_ENTROPY,
            "lower_length": MIN_LOWER_LENGTH,
            "semantic_entropy": MIN_SEMANTIC_ENTROPY,
            "semantic_length": MIN_SEMANTIC_LENGTH,
        },
    }
    canonical = json.dumps(config, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest().upper()


def metadata_payload(
    *,
    eligible: int,
    scanned: int,
    skipped: int,
    eligible_bytes: int,
    scanned_bytes: int,
    entropy_enabled: bool,
) -> dict:
    return {
        "policy_version": POLICY_VERSION,
        "config_sha256": entropy_config_sha256(),
        "detectors": {
            "context_entropy": list(ENTROPY_DETECTORS),
            "entropy_enabled": entropy_enabled,
            "regex": list(PATTERNS),
        },
        "layers": list(LAYERS),
        "limits": {
            "max_file_bytes": MAX_FILE_BYTES,
            "max_files": MAX_FILES,
            "max_total_bytes": MAX_TOTAL_BYTES,
        },
        "eligible_files": eligible,
        "scanned_files": scanned,
        "skipped_files": skipped,
        "eligible_bytes": eligible_bytes,
        "scanned_bytes": scanned_bytes,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path, help="Explicit tree root")
    parser.add_argument(
        "--entropy",
        action="store_true",
        help="Enable redacted context-gated entropy detectors",
    )
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(os.path.abspath(os.fspath(args.root)))
    if not root.is_dir():
        payload = metadata_payload(
            eligible=0,
            scanned=0,
            skipped=0,
            eligible_bytes=0,
            scanned_bytes=0,
            entropy_enabled=args.entropy,
        )
        payload.update(
            {
                "status": "error",
                "error": f"not a directory: {root}",
                "patterns": len(PATTERNS),
            }
        )
        emit(payload, args.json)
        return 2
    finding_keys: set[tuple[str, int, str]] = set()
    entropy_finding_keys: set[tuple[str, int, str, str, int, float]] = set()
    eligible_entries: list[tuple[Path, Path, os.stat_result]] = []
    eligible = 0
    scanned = 0
    skipped = 0
    eligible_bytes = 0
    scanned_bytes = 0
    try:
        for path, relative, file_metadata in physical_inventory(root):
            if relative == SELF or not is_scannable_text(path):
                skipped += 1
                continue
            size = int(file_metadata.st_size)
            eligible_entries.append((path, relative, file_metadata))
            eligible += 1
            eligible_bytes += size

        if eligible > MAX_FILES:
            raise ContractError(
                f"eligible file count exceeds policy limit ({eligible} > {MAX_FILES})"
            )
        oversized = next(
            (
                (relative, size)
                for _, relative, file_metadata in eligible_entries
                for size in (int(file_metadata.st_size),)
                if size > MAX_FILE_BYTES
            ),
            None,
        )
        if oversized is not None:
            relative, size = oversized
            raise ContractError(
                f"file exceeds policy byte limit: {relative.as_posix()} "
                f"({size} > {MAX_FILE_BYTES})"
            )
        if eligible_bytes > MAX_TOTAL_BYTES:
            raise ContractError(
                "eligible byte count exceeds policy limit "
                f"({eligible_bytes} > {MAX_TOTAL_BYTES})"
            )

        for path, relative, expected_metadata in eligible_entries:
            text, actual_size = stable_read_utf8(
                path, relative=relative, expected=expected_metadata
            )
            if actual_size > MAX_FILE_BYTES:
                raise ContractError(
                    f"file exceeds policy byte limit: {relative.as_posix()} "
                    f"({actual_size} > {MAX_FILE_BYTES})"
                )
            if scanned_bytes + actual_size > MAX_TOTAL_BYTES:
                raise ContractError("scanned byte count exceeds policy limit")
            scanned += 1
            scanned_bytes += actual_size
            for name, pattern in PATTERNS.items():
                for match in pattern.finditer(text):
                    finding_keys.add(
                        (
                            relative.as_posix(),
                            text.count("\n", 0, match.start()) + 1,
                            name,
                        )
                    )
            if args.entropy:
                for kind, line_number, token in iter_entropy_findings(text, relative):
                    entropy_finding_keys.add(
                        (
                            relative.as_posix(),
                            line_number,
                            kind,
                            hashlib.sha256(token.encode("utf-8")).hexdigest().upper(),
                            len(token),
                            round(shannon_entropy(token), 6),
                        )
                    )
    except (OSError, ContractError) as exc:
        payload = metadata_payload(
            eligible=eligible,
            scanned=scanned,
            skipped=skipped,
            eligible_bytes=eligible_bytes,
            scanned_bytes=scanned_bytes,
            entropy_enabled=args.entropy,
        )
        payload.update(
            {
                "status": "error",
                "error": str(exc),
                "patterns": len(PATTERNS),
            }
        )
        emit(payload, args.json)
        return 2
    pattern_rank = {name: index for index, name in enumerate(PATTERNS)}
    findings = [
        {"path": path, "line": line, "pattern": pattern}
        for path, line, pattern in sorted(
            finding_keys,
            key=lambda item: (item[0], item[1], pattern_rank[item[2]]),
        )
    ]
    entropy_findings = [
        {
            "kind": kind,
            "path": path,
            "line": line,
            "token_sha256": token_sha256,
            "length": length,
            "entropy": entropy,
        }
        for path, line, kind, token_sha256, length, entropy in sorted(
            entropy_finding_keys
        )
    ]
    payload = {
        "status": "pass" if not findings and not entropy_findings else "fail",
        "findings": findings,
        "patterns": len(PATTERNS),
    }
    if args.entropy:
        payload["entropy_findings"] = entropy_findings
    payload.update(
        metadata_payload(
            eligible=eligible,
            scanned=scanned,
            skipped=skipped,
            eligible_bytes=eligible_bytes,
            scanned_bytes=scanned_bytes,
            entropy_enabled=args.entropy,
        )
    )
    emit(payload, args.json)
    return 0 if not findings and not entropy_findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
