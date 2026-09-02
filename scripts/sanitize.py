"""Sanitize support notes, logs, and configs before pasting into AI tools.

Thin wrapper around the ``sanitizer`` package vendored at the project root.
Usage mirrors the standalone ``sanitize`` CLI exactly.

Examples
--------
Sanitize a file and print to stdout:

    python3 scripts/sanitize.py analysis/results.md

Sanitize stdin (pipe from another toolkit script):

    python3 scripts/inventory_bundle_v2.py bundles/<bundle> \
        | python3 scripts/sanitize.py --profile case-summary

Write sanitized output to a file and print a redaction report:

    python3 scripts/sanitize.py analysis/results.md \
        --output analysis/results_sanitized.md \
        --report

Redact a specific customer/org name on top of the default patterns:

    python3 scripts/sanitize.py analysis/results.md \
        --customer acme-corp \
        --report

Profiles
--------
  infra-safe   (default) Redacts secrets, IPs, hostnames, URLs, and customer
               names while preserving ports, protocols, and error text.
  case-summary Optimised for pasting into an AI assistant. Keeps product names,
               versions, and the technical narrative readable.
  strict       Aggressive. Also redacts UUIDs and phone numbers.
"""

from __future__ import annotations

import sys
import os

# Make the vendored sanitizer package importable when this script is run from
# any working directory, as long as the jumptoolkit project root is intact.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from sanitizer.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
