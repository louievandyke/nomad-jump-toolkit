#!/usr/bin/env python3
"""
_bundlelib.py

Shared, read-only helpers for the Nomad Jump Toolkit scripts.

This module is not a standalone tool (leading underscore is deliberate).
It exists to remove duplication that had already caused real drift across
the seven validated scripts: four non-identical copies of bundle-root
detection, a timestamp parser that silently covered fewer formats in one
script than the others, and a Markdown-escape helper that could blank out
a legitimate `0` value in two scripts. See AGENTS.md's "Known Duplication
/ Drift" section for the reconciliation history.

Every function here is pure/read-only and Python-stdlib-only, matching the
toolkit's non-negotiable rules in AGENTS.md. This module must be kept next
to the scripts that import it (`import _bundlelib` relies on Python adding
the executed script's own directory to sys.path).
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional


# ---------------------------------------------------------------------------
# Bundle layout
# ---------------------------------------------------------------------------

REQUIRED_BUNDLE_DIRS = ("cluster", "interval", "server", "client")


def find_bundle_root(root: Path) -> Optional[Path]:
    """
    Accept either:
      ./nomad-debug-2026-...
    or a parent containing exactly one nomad-debug-* directory.

    Reconciled from four near-identical copies. The consolidated version
    keeps the try/except OSError guard that three of the four originals had
    (one copy, formerly in correlate_timeline_v2.py, would raise an
    unhandled exception and dump a Python traceback instead of the tool's
    normal bounded error output).
    """
    if all((root / name).is_dir() for name in REQUIRED_BUNDLE_DIRS):
        return root

    candidates = []
    try:
        for child in root.iterdir():
            if child.is_dir() and all(
                (child / name).is_dir() for name in REQUIRED_BUNDLE_DIRS
            ):
                candidates.append(child)
    except OSError:
        return None

    return candidates[0] if len(candidates) == 1 else None


# ---------------------------------------------------------------------------
# Small generic helpers
# ---------------------------------------------------------------------------

def first_value(d: dict, keys: Iterable[str]) -> Any:
    for key in keys:
        if key in d:
            return d[key]
    return None


def short_id(value: str) -> str:
    return value[:8] if value else ""


def md_escape(value: Any) -> str:
    """
    Render a value for a Markdown table cell.

    Only `None` becomes an empty cell. Two of the seven scripts previously
    used `str(value or "")`, which also blanks out legitimate falsy values
    such as `0` or `False` -- e.g. a retry count or exit code of 0 would
    silently vanish from a report instead of being shown. That contradicts
    AGENTS.md's "do not erase contradictory or partial evidence" rule, so
    the reconciled version only special-cases actual absence.
    """
    if value is None:
        return ""
    return str(value).replace("|", r"\|").replace("\n", " ")


def human_size(num_bytes: int) -> str:
    value = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024.0 or unit == "TB":
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{num_bytes} B"


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------
#
# Ordered from most specific to least specific. Kept as one canonical list:
# inventory_bundle_v2.py previously used a narrower 3-pattern list that
# missed monitor.log-style offsets like "-0700" (no colon) and the
# "YYYY-MM-DD HH:MM:SS +0000 UTC" form, so its Timestamp Coverage report
# under-detected timestamps compared to every other script.

TIMESTAMP_PATTERNS = [
    # 2026-08-14T17:18:10Z
    re.compile(r"\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\b"),
    # 2026-08-14T17:18:10-07:00
    re.compile(r"\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{2}:\d{2})\b"),
    # Nomad monitor.log: 2026-08-14T10:18:17.883-0700
    re.compile(r"\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{4})\b"),
    # 2026-08-14 17:18:10 +0000 UTC
    re.compile(r"\b(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?) ([+-]\d{4}) UTC\b"),
    # Naive timestamp occurring inside source data. Interpreted as UTC only
    # for scanning/extraction; user-supplied --start/--end still require an
    # explicit timezone or --assume-tz (see parse_user_dt).
    re.compile(r"\b(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\b"),
]


def iso(dt: Optional[datetime]) -> str:
    if dt is None:
        return ""
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_offset_no_colon(raw: str) -> str:
    """Convert a trailing -0700/+0000 to -07:00/+00:00 for fromisoformat()."""
    m = re.search(r"([+-])(\d{2})(\d{2})$", raw)
    if not m:
        return raw
    return raw[: m.start()] + f"{m.group(1)}{m.group(2)}:{m.group(3)}"


def parse_ts(raw: str, default_tz: timezone = timezone.utc) -> Optional[datetime]:
    """
    Parse a single timestamp string into a UTC-aware datetime.

    Handles: "YYYY-MM-DD HH:MM:SS +HHMM UTC", trailing "Z", offsets with or
    without a colon, and naive timestamps (assumed to be `default_tz`).
    This is the most capable of the four near-duplicate parsers this was
    reconciled from; see TIMESTAMP_PATTERNS docstring above.
    """
    raw = raw.strip()

    m = re.fullmatch(
        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?) ([+-]\d{4}) UTC",
        raw,
    )
    if m:
        base, offset = m.groups()
        offset_colon = offset[:3] + ":" + offset[3:]
        try:
            return datetime.fromisoformat(base + offset_colon).astimezone(timezone.utc)
        except ValueError:
            return None

    try:
        if raw.endswith("Z"):
            return datetime.fromisoformat(raw[:-1] + "+00:00").astimezone(timezone.utc)

        normalized = normalize_offset_no_colon(raw)
        dt = datetime.fromisoformat(normalized)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=default_tz)

        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def timestamps_in_text(text: str) -> list[datetime]:
    """
    Extract timestamps from a line without double-counting overlapping forms.

    Example: "2026-08-14T10:17:40.950820-0700" must produce only
    17:17:40.950820Z, not also a spurious naive 10:17:40.950820Z reading of
    the same substring. Two of the five original copies of this function
    (used in extract_window_v2.py) did not mask overlapping regex spans, so
    an offset-qualified monitor.log timestamp could also be matched by the
    trailing naive-timestamp pattern and yielded as if it were a second,
    unrelated, UTC-already event a few hours off from the real one -- which
    could pull a monitor.log line into (or out of) an extracted window
    based on the wrong reading.
    """
    spans: list[tuple[int, int]] = []
    results: list[datetime] = []
    seen = set()

    for pattern in TIMESTAMP_PATTERNS:
        for match in pattern.finditer(text):
            start, end = match.span()

            if any(not (end <= s or start >= e) for s, e in spans):
                continue

            if len(match.groups()) == 2:
                raw = f"{match.group(1)} {match.group(2)} UTC"
            else:
                raw = match.group(1)

            dt = parse_ts(raw)
            if dt is None:
                continue

            spans.append((start, end))

            key = dt.isoformat()
            if key not in seen:
                seen.add(key)
                results.append(dt)

    return results


def unixish_to_dt(value: Any) -> Optional[datetime]:
    """
    Interpret a Nomad-style timestamp field: a Unix epoch number at
    seconds/ms/us/ns scale, or an ISO-ish string.

    String handling routes through parse_ts() first so offset-without-colon
    and " UTC"-suffixed forms are recognized; two of the three original
    copies (in alloc_lineage_v2.py and eval_trace.py) instead tried
    int(value) first and fell back to a bare fromisoformat() with only
    "Z"-suffix handling, silently failing on those forms.
    """
    if value is None:
        return None

    if isinstance(value, str):
        parsed = parse_ts(value)
        if parsed:
            return parsed
        try:
            value = int(value)
        except ValueError:
            return None

    if not isinstance(value, (int, float)):
        return None

    num = float(value)

    try:
        if num > 1e17:
            return datetime.fromtimestamp(num / 1e9, tz=timezone.utc)
        if num > 1e14:
            return datetime.fromtimestamp(num / 1e6, tz=timezone.utc)
        if num > 1e11:
            return datetime.fromtimestamp(num / 1e3, tz=timezone.utc)
        if num > 1e9:
            return datetime.fromtimestamp(num, tz=timezone.utc)
    except (ValueError, OSError, OverflowError):
        return None

    return None


def parse_user_dt(
    value: Optional[str],
    assume_tz: Optional[Any],
) -> Optional[datetime]:
    """
    Parse a user-supplied --start/--end CLI value. Returns None only if
    `value` is None (an omitted, optional bound); a present-but-invalid
    string raises ValueError with a message the caller can print.
    Naive values require `assume_tz` (a zoneinfo.ZoneInfo) or raise.
    """
    if value is None:
        return None

    raw = value.strip()

    try:
        dt = (
            datetime.fromisoformat(raw[:-1] + "+00:00")
            if raw.endswith("Z")
            else datetime.fromisoformat(raw)
        )
    except ValueError as exc:
        raise ValueError(
            f"invalid datetime '{value}'. Use ISO 8601, e.g. "
            "2026-08-14T17:18:30Z or 2026-08-14T10:18:30-07:00"
        ) from exc

    if dt.tzinfo is None:
        if assume_tz is None:
            raise ValueError(
                f"datetime '{value}' has no timezone. Supply an offset/Z or use --assume-tz."
            )
        dt = dt.replace(tzinfo=assume_tz)

    return dt.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# Eventstream iteration
# ---------------------------------------------------------------------------

def iter_eventstream_records(path: Path) -> Iterable[tuple[int, dict]]:
    """
    Yield (line_number, record) from cluster/eventstream.json.

    Tolerates a JSON array, a single JSON object, or JSON-lines. Reconciled
    from two designs: alloc_lineage_v2.py/eval_trace.py tried a whole-file
    json.loads() first and fell back to line-by-line, which correctly
    handles a single bare JSON object; alloc_lifecycle_v2.py and
    correlate_timeline_v2.py instead peeked at the first non-empty line to
    decide array-vs-lines, which is cheaper on a huge file but silently
    yields nothing for a bundle whose eventstream.json is one ordinary JSON
    object rather than an array or JSON-lines -- a shape AGENTS.md's
    parsing rules explicitly require tolerating. This keeps the
    whole-file-first approach for correctness; line number 1 is used for a
    single top-level object or array element index otherwise.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    if not text.strip():
        return

    try:
        value = json.loads(text)

        if isinstance(value, list):
            for idx, item in enumerate(value, 1):
                if isinstance(item, dict):
                    yield idx, item
            return

        if isinstance(value, dict):
            yield 1, value
            return

    except json.JSONDecodeError:
        pass

    for line_no, line in enumerate(text.splitlines(), 1):
        line = line.strip()

        if not line:
            continue

        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        if isinstance(item, dict):
            yield line_no, item


# ---------------------------------------------------------------------------
# Interval snapshot parsing (allocations.json / evaluations.json / etc.)
# ---------------------------------------------------------------------------

def parse_json_documents(path: Path) -> tuple[list[Any], str]:
    """
    Parse a snapshot file into a list of top-level JSON values, tolerating a
    single ordinary JSON document (object or array) or JSON-lines/multiple
    JSON documents. Returns (values, parse_mode) where parse_mode is one of:
    empty | json | json-lines | unparseable.

    Unlike read_records()/expand_json_value() below, this does not flatten
    wrapper objects or filter to dict-only records: it hands back the raw
    parsed value(s) as-is. Use this when a caller needs to recurse into
    arbitrary nested structure itself (e.g. a caller doing its own deep
    search for an ID at any depth) rather than a normalized flat list of
    top-level records.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], "unparseable"

    if not text.strip():
        return [], "empty"

    try:
        value = json.loads(text)
        return [value], "json"
    except json.JSONDecodeError:
        pass

    values = []
    parsed_any = False

    for line in text.splitlines():
        line = line.strip()

        if not line:
            continue

        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue

        parsed_any = True
        values.append(value)

    if parsed_any:
        return values, "json-lines"

    return [], "unparseable"


def expand_json_value(
    value: Any,
    wrapper_keys: Iterable[str],
    id_keys: Optional[Iterable[str]] = None,
) -> list[dict]:
    """
    Normalize one parsed JSON value into a list of record dicts.

    `wrapper_keys` are tried in order for a `{"Allocations": [...]}`-style
    wrapper object. If none match and the value is a bare dict:
      - id_keys is None: always treat it as a single record (permissive;
        matches correlate_timeline_v2.py's original behavior, useful when
        the caller filters by substring match rather than by identity).
      - id_keys is a tuple: only treat it as a single record if one of
        those keys is present (matches alloc_lineage_v2.py/eval_trace.py's
        original stricter behavior).
    """
    if isinstance(value, list):
        return [x for x in value if isinstance(x, dict)]

    if isinstance(value, dict):
        for key in wrapper_keys:
            if isinstance(value.get(key), list):
                return [x for x in value[key] if isinstance(x, dict)]

        if id_keys is None or first_value(value, id_keys):
            return [value]

    return []


def read_records(
    path: Path,
    wrapper_keys: Iterable[str],
    id_keys: Optional[Iterable[str]] = None,
) -> tuple[list[dict], str]:
    """
    Read one interval snapshot file (allocations.json, evaluations.json,
    nodes.json, ...) tolerating ordinary JSON, a wrapper object, or
    JSON-lines/multiple JSON documents.

    Returns (records, parse_mode) where parse_mode is one of:
      empty | json | json-lines | unparseable

    correlate_timeline_v2.py previously read these files with a single
    json.loads() and no JSON-lines fallback, so a bundle whose
    allocations.json/evaluations.json used the JSON-lines shape (a real,
    documented case in AGENTS.md's "Known Bundle/Test Characteristics")
    would have that interval's records silently skipped -- caught by a
    bare `except json.JSONDecodeError: continue` with no count or warning,
    which is exactly what AGENTS.md's parsing rules say not to do.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], "unparseable"

    if not text.strip():
        return [], "empty"

    try:
        value = json.loads(text)
        return expand_json_value(value, wrapper_keys, id_keys), "json"
    except json.JSONDecodeError:
        pass

    records = []
    parsed_any = False

    for line in text.splitlines():
        line = line.strip()

        if not line:
            continue

        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue

        parsed_any = True
        records.extend(expand_json_value(value, wrapper_keys, id_keys))

    if parsed_any:
        return records, "json-lines"

    return [], "unparseable"


def merge_record(existing: dict, incoming: dict, source_file: str, interval_id: str) -> dict:
    """
    Merge a newly-observed record summary into any prior observation of the
    same ID, tracking first/last-seen interval and source provenance.

    Later non-empty fields win (most recent capture wins). `interval_id`
    may be "" for eventstream-derived observations that aren't tied to a
    regular interval capture; in that case first/last_seen_interval are
    left alone rather than being overwritten with an empty string.
    """
    if not existing:
        out = dict(incoming)
        out["first_seen_interval"] = interval_id
        out["last_seen_interval"] = interval_id
        out["sources"] = [source_file]
        return out

    out = dict(existing)

    for key, value in incoming.items():
        if value not in (None, "", [], {}):
            out[key] = value

    if interval_id:
        if not out.get("first_seen_interval"):
            out["first_seen_interval"] = interval_id
        out["last_seen_interval"] = interval_id

    sources = list(out.get("sources", []))
    if source_file not in sources:
        sources.append(source_file)
    out["sources"] = sources

    return out


# ---------------------------------------------------------------------------
# Generic relationship-graph traversal
# ---------------------------------------------------------------------------
#
# Operates on plain node-id strings, so it is shared as-is between
# alloc_lineage_v2.py (allocation lineage) and eval_trace.py (evaluation
# chains). Edge construction (add_edge/build_relationships) stays local to
# each script because it is genuinely domain-specific: it reads different
# dataclass fields (Relationship.from_alloc/to_alloc vs
# EvalRelationship.from_eval/to_eval) and different authoritative Nomad
# fields (PreviousAllocation/RescheduleTracker vs PreviousEval/BlockedEval).

def discover_connected(
    seed: str,
    successors: dict[str, set[str]],
    predecessors: dict[str, set[str]],
    max_depth: int,
) -> tuple[set[str], dict[str, int]]:
    discovered = {seed}
    depth_map = {seed: 0}
    queue = [(seed, 0)]

    while queue:
        current, depth = queue.pop(0)

        if depth >= max_depth:
            continue

        neighbors = set(successors.get(current, set()))
        neighbors.update(predecessors.get(current, set()))

        for neighbor in sorted(neighbors):
            if neighbor in discovered:
                continue

            discovered.add(neighbor)
            depth_map[neighbor] = depth + 1
            queue.append((neighbor, depth + 1))

    return discovered, depth_map


def detect_cycles(nodes: set[str], successors: dict[str, set[str]]) -> list[list[str]]:
    cycles = []
    visiting = set()
    visited = set()
    stack = []

    def dfs(node: str):
        if node in visiting:
            if node in stack:
                idx = stack.index(node)
                cycles.append(stack[idx:] + [node])
            return

        if node in visited:
            return

        visiting.add(node)
        stack.append(node)

        for nxt in successors.get(node, set()):
            if nxt in nodes:
                dfs(nxt)

        stack.pop()
        visiting.remove(node)
        visited.add(node)

    for node in sorted(nodes):
        dfs(node)

    return cycles


def canonical_paths(
    nodes: set[str],
    successors: dict[str, set[str]],
    predecessors: dict[str, set[str]],
    max_paths: int = 50,
) -> list[list[str]]:
    roots = [
        node for node in nodes
        if not (predecessors.get(node, set()) & nodes)
    ]

    if not roots:
        roots = sorted(nodes)

    paths = []

    def walk(node: str, path: list[str], seen: set[str]):
        if len(paths) >= max_paths:
            return

        next_nodes = sorted(successors.get(node, set()) & nodes)

        if not next_nodes:
            paths.append(path + [node])
            return

        for nxt in next_nodes:
            if nxt in seen:
                paths.append(path + [node, nxt])
                continue

            walk(nxt, path + [node], seen | {nxt})

    for root in sorted(roots):
        walk(root, [], {root})

        if len(paths) >= max_paths:
            break

    return paths
