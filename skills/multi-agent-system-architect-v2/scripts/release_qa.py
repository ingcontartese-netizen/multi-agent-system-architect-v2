#!/usr/bin/env python3
"""Official deterministic 2.1 release-QA command line."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence


sys.dont_write_bytecode = True

from _release_guard import (  # noqa: E402
    RUNNER_VERSION,
    SCHEMA_VERSION,
    ReleaseQaError,
    RunnerError,
    lease_status_command,
    list_command,
    run_command,
    status_for_exit,
)


class JsonArgumentParser(argparse.ArgumentParser):
    """Raise a typed error so malformed invocations still return JSON."""

    def error(self, message: str) -> None:
        reason = "invalid-arguments"
        if "required" in message:
            reason = "missing-required-argument"
        elif "invalid choice" in message:
            reason = "invalid-command"
        raise RunnerError(
            "CLI_INVALID",
            step="cli",
            detail={"reason": reason},
        )


def _positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("positive integer required") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("positive integer required")
    return parsed


def _nonnegative_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("nonnegative integer required") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("nonnegative integer required")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = JsonArgumentParser(
        prog="release_qa.py",
        description="Run deterministic, cold-copy release QA without installation.",
    )
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        parser_class=JsonArgumentParser,
    )

    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("source", type=Path)
    list_parser.add_argument("--json", action="store_true", required=True)

    status_parser = subparsers.add_parser("lease-status")
    status_parser.add_argument("source", type=Path)
    status_parser.add_argument("--json", action="store_true", required=True)

    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("source", type=Path)
    run_parser.add_argument("work_root", type=Path)
    run_parser.add_argument(
        "--timeout-seconds",
        type=_positive_integer,
        required=True,
    )
    run_parser.add_argument(
        "--lease-seconds",
        type=_positive_integer,
        required=True,
    )
    run_parser.add_argument(
        "--expect-files",
        type=_nonnegative_integer,
        required=True,
        help="Expected file count from list.source_snapshot",
    )
    run_parser.add_argument(
        "--expect-tree",
        required=True,
        help=(
            "Expected release-physical-tree-v1 SHA-256 from "
            "list.source_snapshot.tree_sha256"
        ),
    )
    run_parser.add_argument("--seal-out", type=Path)
    run_parser.add_argument("--json", action="store_true", required=True)
    return parser


def configure_utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="strict")


def emit(payload: dict, exit_code: int) -> int:
    value = dict(payload)
    value.setdefault("schema_version", SCHEMA_VERSION)
    value.setdefault("runner_version", RUNNER_VERSION)
    value.setdefault("status", status_for_exit(exit_code))
    sys.stdout.write(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    )
    return exit_code


def dispatch(arguments: argparse.Namespace) -> tuple[dict, int]:
    if arguments.command == "list":
        return list_command(arguments.source)
    if arguments.command == "lease-status":
        return lease_status_command(arguments.source)
    if arguments.command == "run":
        return run_command(
            arguments.source,
            arguments.work_root,
            timeout_seconds=arguments.timeout_seconds,
            lease_seconds=arguments.lease_seconds,
            expect_files=arguments.expect_files,
            expect_tree=arguments.expect_tree,
            seal_out=arguments.seal_out,
        )
    raise RunnerError("CLI_INVALID", step="cli")


def main(argv: Sequence[str] | None = None) -> int:
    configure_utf8_stdio()
    try:
        arguments = build_parser().parse_args(argv)
        payload, exit_code = dispatch(arguments)
    except ReleaseQaError as exc:
        exit_code = exc.exit_code
        payload = {
            "schema_version": SCHEMA_VERSION,
            "runner_version": RUNNER_VERSION,
            "command": "unknown",
            "status": status_for_exit(exit_code),
            "errors": [exc.payload()],
        }
    except KeyboardInterrupt:
        exit_code = 2
        payload = {
            "schema_version": SCHEMA_VERSION,
            "runner_version": RUNNER_VERSION,
            "command": "unknown",
            "status": "error",
            "errors": [{"code": "INTERRUPTED", "step": "cli"}],
        }
    return emit(payload, exit_code)


if __name__ == "__main__":
    raise SystemExit(main())
