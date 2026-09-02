"""Command-line interface for the ``sanitize`` tool.

Reads from a file or stdin, writes sanitized text to stdout (or ``--output``),
and optionally prints a count report to stderr. Sensitive input is never logged.
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .config import Config, ConfigError, find_config, load_config
from .engine import sanitize_text
from .profiles import DEFAULT_PROFILE, PROFILES
from .report import format_json_report, format_text_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sanitize",
        description=(
            "Sanitize support notes, logs, and configs before pasting into AI "
            "tools. Reads a file or stdin; writes sanitized text to stdout."
        ),
        epilog=(
            "This tool reduces risk but does not guarantee that text is safe to "
            "share externally. Always review the output before pasting it into "
            "third-party tools."
        ),
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="Input file. If omitted, read from stdin.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Write sanitized text to this file instead of stdout.",
    )
    parser.add_argument(
        "--profile",
        choices=sorted(PROFILES),
        default=DEFAULT_PROFILE,
        help=f"Redaction profile (default: {DEFAULT_PROFILE}).",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Print a count summary to stderr after sanitizing.",
    )
    parser.add_argument(
        "--json-report",
        action="store_true",
        help="Print a machine-readable JSON summary to stderr.",
    )
    parser.add_argument(
        "--customer",
        action="append",
        default=[],
        metavar="NAME",
        help="Customer/org name to redact as <ORG_n>. Repeatable.",
    )
    parser.add_argument(
        "--allow",
        action="append",
        default=[],
        metavar="TERM",
        help="Extra term to never treat as a hostname. Repeatable.",
    )
    parser.add_argument(
        "--config",
        metavar="FILE",
        help="Path to a .sanitizer.yml config. Overrides auto-discovery.",
    )
    parser.add_argument(
        "--no-config",
        action="store_true",
        help="Skip auto-discovery of a .sanitizer.yml config file.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help=(
            "Include original values in the report. Off by default for safety; "
            "only use locally."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def _read_input(path: str | None) -> str:
    if path:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError as exc:
            raise SystemExit(f"sanitize: cannot read {path!r}: {exc.strerror}")
    if sys.stdin.isatty():
        raise SystemExit(
            "sanitize: no input file given and stdin is a terminal. "
            "Pass a file or pipe text in."
        )
    return sys.stdin.read()


def _write_output(text: str, path: str | None) -> None:
    if path:
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        except OSError as exc:
            raise SystemExit(f"sanitize: cannot write {path!r}: {exc.strerror}")
    else:
        sys.stdout.write(text)


def _resolve_config(args: argparse.Namespace) -> Config:
    """Load config from --config, else auto-discover near the input/cwd."""
    if args.config:
        path = args.config
    elif args.no_config:
        return Config()
    else:
        found = find_config(args.input)
        if found is None:
            return Config()
        path = found
    try:
        return load_config(path)
    except ConfigError as exc:
        raise SystemExit(f"sanitize: {exc}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    config = _resolve_config(args)
    raw = _read_input(args.input)
    result = sanitize_text(
        raw,
        profile=args.profile,
        customer_names=[*config.customer_names, *args.customer],
        allowlist=set(config.allowlist) | set(args.allow),
        extra_detectors=config.extra_detectors,
    )

    _write_output(result.text, args.output)

    if args.json_report:
        print(format_json_report(result, debug=args.debug), file=sys.stderr)
    if args.report:
        print(format_text_report(result, debug=args.debug), file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
