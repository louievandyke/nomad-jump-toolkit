"""Report formatting.

Reports show *counts only* by default. Original sensitive values are never
included unless the caller explicitly opts in via the debug flag.
"""

from __future__ import annotations

import json

from .engine import SanitizeResult


def format_text_report(result: SanitizeResult, *, debug: bool = False) -> str:
    """Human-readable count summary (intended for stderr)."""
    lines = ["Sanitization report", "-------------------", f"profile: {result.profile}"]
    counts = result.counts
    if not counts:
        lines.append("(nothing redacted)")
    else:
        width = max(len(k) for k in counts)
        for kind in sorted(counts):
            lines.append(f"{kind.ljust(width)} : {counts[kind]}")
    lines.append(f"{'TOTAL'.ljust(max((len(k) for k in counts), default=5))} : "
                 f"{sum(counts.values())}")

    if debug:
        lines.append("")
        lines.append("debug (original -> placeholder):")
        for f in result.findings:
            lines.append(f"  {f.original!r} -> {f.replacement}")
    return "\n".join(lines)


def format_json_report(result: SanitizeResult, *, debug: bool = False) -> str:
    """Machine-readable summary."""
    payload: dict = {
        "profile": result.profile,
        "summary": result.counts,
        "total": sum(result.counts.values()),
    }
    if debug:
        payload["findings"] = [
            {"kind": f.kind, "replacement": f.replacement, "original": f.original}
            for f in result.findings
        ]
    return json.dumps(payload, indent=2)
