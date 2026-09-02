"""Stable, deterministic placeholder replacement.

The same original value always maps to the same placeholder within a single
run, so relationships in the text (a host that appears twice, an IP referenced
in several log lines) stay legible after sanitization.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class Finding:
    """One redacted value. ``original`` is only retained for debug output and
    is never emitted unless the caller explicitly asks for it."""

    kind: str
    replacement: str
    original: str = field(repr=False, default="")


class StableReplacer:
    """Assigns deterministic placeholders and tracks counts per kind."""

    def __init__(self) -> None:
        # (kind, value) -> placeholder, so identical values reuse a placeholder.
        self._value_to_replacement: dict[tuple[str, str], str] = {}
        self._counters: defaultdict[str, int] = defaultdict(int)
        self.findings: list[Finding] = []

    def replace(self, kind: str, label: str, value: str) -> str:
        """Return the stable placeholder for ``value``.

        Args:
            kind: Report key (counts are grouped by this).
            label: Placeholder label; output is ``<{label}_{n}>``.
            value: The original sensitive substring.
        """
        key = (kind, value)
        existing = self._value_to_replacement.get(key)
        if existing is not None:
            return existing

        self._counters[kind] += 1
        replacement = f"<{label}_{self._counters[kind]}>"
        self._value_to_replacement[key] = replacement
        self.findings.append(
            Finding(kind=kind, replacement=replacement, original=value)
        )
        return replacement

    def counts(self) -> dict[str, int]:
        """Number of distinct values redacted, grouped by kind."""
        return dict(self._counters)
