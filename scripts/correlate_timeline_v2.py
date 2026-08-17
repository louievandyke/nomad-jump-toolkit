#!/usr/bin/env python3
"""
correlate_timeline_v2.py

Build one bounded, chronological incident timeline from an unpacked Nomad
`operator debug` bundle.

Version 2 improvements:
- Suppresses known `nomad operator debug` self-observation HTTP traffic by
  default (pprof/host collection requests). Use --include-debug-traffic to keep it.
- Collapses identical server/client monitor-log records into one correlated event.
- Adds relevance tiers: high / medium / telemetry.
- Collapses unchanged repeated interval snapshots in the Markdown view while
  retaining the full raw timeline in CSV.
- Keeps OR filter semantics for broad forensic correlation.
- Preserves source attribution and bounded output.

Sources:
- cluster/eventstream.json
- server/*/monitor.log
- client/*/monitor.log
- interval/*/allocations.json
- interval/*/evaluations.json
- interval/*/nodes.json

Examples:
  python3 correlate_timeline_v2.py ./nomad-debug-test \
    --alloc ee943c77-0149-b085-fad0-de0f30f23c2c

  python3 correlate_timeline_v2.py ./nomad-debug-test \
    --alloc ee943c77-0149-b085-fad0-de0f30f23c2c \
    --node 027c010c-e769-eb1b-2ebe-a4b819fcbbd4 \
    --eval ced8afab-16e4-87ce-2f01-e297b45ba3c3 \
    --overwrite
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


DEFAULT_MAX_LOG_MATCHES = 500
DEFAULT_LINE_WIDTH = 700

TIMESTAMP_PATTERNS = [
    re.compile(r"\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\b"),
    re.compile(r"\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{2}:\d{2})\b"),
    re.compile(r"\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{4})\b"),
    re.compile(r"\b(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?) ([+-]\d{4}) UTC\b"),
    re.compile(r"\b(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\b"),
]

DEBUG_TRAFFIC_PATTERNS = (
    "/v1/agent/pprof/",
    "/v1/agent/host",
    "s.rpcHandlerForNode()",
)

HIGH_SIGNAL_EVENT_TOKENS = (
    "PlanResult",
    "EvaluationUpdated",
    "JobRegistered",
    "AllocationUpdated",
    "NodeDrain",
    "drain",
    "migrate",
    "resched",
    "restart",
    "health",
    "failed",
    "lost",
    "blocked",
)

MEDIUM_SIGNAL_EVENT_TOKENS = (
    "allocation observed",
    "evaluation observed",
    "node observed",
    "template render",
    "scheduler",
)

@dataclass
class TimelineEvent:
    timestamp_utc: str
    sort_ts: float
    source_type: str
    source_file: str
    source_line: Optional[int]
    object_type: str
    object_id: str
    event: str
    details: str
    relevance: str
    source_group: str = ""


def iso(dt: Optional[datetime]) -> str:
    if dt is None:
        return ""
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_offset(raw: str) -> str:
    m = re.search(r"([+-])(\d{2})(\d{2})$", raw)
    if not m:
        return raw
    return raw[:m.start()] + f"{m.group(1)}{m.group(2)}:{m.group(3)}"


def parse_ts(raw: str) -> Optional[datetime]:
    raw = raw.strip()

    m = re.fullmatch(
        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?) ([+-]\d{4}) UTC",
        raw,
    )
    if m:
        base, off = m.groups()
        off = off[:3] + ":" + off[3:]
        try:
            return datetime.fromisoformat(base + off).astimezone(timezone.utc)
        except ValueError:
            return None

    try:
        if raw.endswith("Z"):
            return datetime.fromisoformat(raw[:-1] + "+00:00").astimezone(timezone.utc)

        dt = datetime.fromisoformat(normalize_offset(raw))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def timestamps_in_text(text: str) -> list[datetime]:
    spans, out, seen = [], [], set()

    for pattern in TIMESTAMP_PATTERNS:
        for match in pattern.finditer(text):
            start, end = match.span()
            if any(not (end <= s or start >= e) for s, e in spans):
                continue

            raw = (
                f"{match.group(1)} {match.group(2)} UTC"
                if len(match.groups()) == 2
                else match.group(1)
            )
            dt = parse_ts(raw)
            if dt is None:
                continue

            spans.append((start, end))
            key = dt.isoformat()
            if key not in seen:
                seen.add(key)
                out.append(dt)

    return out


def unixish_to_dt(value: Any) -> Optional[datetime]:
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


def parse_user_dt(value: Optional[str], assume_tz: Optional[ZoneInfo]) -> Optional[datetime]:
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
        raise ValueError(f"invalid ISO-8601 datetime: {value}") from exc

    if dt.tzinfo is None:
        if assume_tz is None:
            raise ValueError(
                f"datetime '{value}' has no timezone; use Z/offset or --assume-tz"
            )
        dt = dt.replace(tzinfo=assume_tz)

    return dt.astimezone(timezone.utc)


def find_bundle_root(root: Path) -> Optional[Path]:
    required = ("cluster", "interval", "server", "client")

    if all((root / d).is_dir() for d in required):
        return root

    candidates = []

    for child in root.iterdir():
        if child.is_dir() and all((child / d).is_dir() for d in required):
            candidates.append(child)

    return candidates[0] if len(candidates) == 1 else None


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        return json.load(fh)


def within_window(
    dt: Optional[datetime],
    start: Optional[datetime],
    end: Optional[datetime],
) -> bool:
    if dt is None:
        return start is None and end is None
    if start is not None and dt < start:
        return False
    if end is not None and dt > end:
        return False
    return True


def json_text(obj: Any) -> str:
    try:
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError):
        return str(obj)


def matches_filters(obj: Any, needles: list[str]) -> bool:
    if not needles:
        return True

    text = json_text(obj)
    return any(n in text for n in needles)


def first_value(d: dict, keys: Iterable[str]) -> Any:
    for key in keys:
        if key in d:
            return d[key]
    return None


def compact(value: Any, limit: int = 400) -> str:
    text = json_text(value)
    return text if len(text) <= limit else text[:limit] + " …[truncated]"


def interval_capture_timestamp(interval_dir: Path) -> Optional[datetime]:
    metrics = interval_dir / "metrics.json"

    if metrics.is_file():
        try:
            data = load_json(metrics)
            raw = data.get("Timestamp") if isinstance(data, dict) else None

            if isinstance(raw, str):
                dt = parse_ts(raw)
                if dt:
                    return dt
        except (OSError, json.JSONDecodeError):
            pass

    return None


def records_from_snapshot(data: Any, wrappers: tuple[str, ...]) -> list[dict]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]

    if isinstance(data, dict):
        for key in wrappers:
            if isinstance(data.get(key), list):
                return [x for x in data[key] if isinstance(x, dict)]

        return [data]

    return []


def summarize_alloc(obj: dict) -> tuple[str, str]:
    obj_id = str(first_value(obj, ("ID", "AllocID", "AllocationID")) or "")

    fields = (
        ("JobID", "job"),
        ("TaskGroup", "group"),
        ("NodeID", "node"),
        ("EvalID", "eval"),
        ("DeploymentID", "deployment"),
        ("DesiredStatus", "desired"),
        ("ClientStatus", "client"),
        ("PreviousAllocation", "previous"),
        ("NextAllocation", "next"),
    )

    parts = [
        f"{label}={obj[key]}"
        for key, label in fields
        if obj.get(key) not in (None, "", [], {})
    ]

    return obj_id, "; ".join(parts)


def summarize_eval(obj: dict) -> tuple[str, str]:
    obj_id = str(first_value(obj, ("ID", "EvalID")) or "")

    fields = (
        ("JobID", "job"),
        ("Namespace", "namespace"),
        ("NodeID", "node"),
        ("TriggeredBy", "triggered_by"),
        ("Status", "status"),
        ("StatusDescription", "status_description"),
        ("PreviousEval", "previous_eval"),
        ("NextEval", "next_eval"),
        ("BlockedEval", "blocked_eval"),
    )

    parts = [
        f"{label}={obj[key]}"
        for key, label in fields
        if obj.get(key) not in (None, "", [], {})
    ]

    return obj_id, "; ".join(parts)


def summarize_node(obj: dict) -> tuple[str, str]:
    obj_id = str(first_value(obj, ("ID", "NodeID")) or "")

    fields = (
        ("Name", "name"),
        ("Status", "status"),
        ("StatusDescription", "status_description"),
        ("SchedulingEligibility", "eligibility"),
        ("NodePool", "pool"),
        ("NodeClass", "class"),
    )

    parts = [
        f"{label}={obj[key]}"
        for key, label in fields
        if obj.get(key) not in (None, "", [], {})
    ]

    if obj.get("Drain") not in (None, "", [], {}):
        parts.append(f"drain={compact(obj['Drain'], 180)}")

    return obj_id, "; ".join(parts)


def relevance_for(event_name: str, details: str, source_type: str) -> str:
    haystack = f"{event_name} {details}".lower()

    if any(token.lower() in haystack for token in HIGH_SIGNAL_EVENT_TOKENS):
        return "high"

    if any(token.lower() in haystack for token in MEDIUM_SIGNAL_EVENT_TOKENS):
        return "medium"

    if source_type.endswith("_monitor_log"):
        return "telemetry"

    return "medium"


def collect_snapshot_events(
    bundle_root: Path,
    root: Path,
    start: Optional[datetime],
    end: Optional[datetime],
    needles: list[str],
) -> list[TimelineEvent]:
    events = []

    interval_dirs = sorted(
        p for p in (bundle_root / "interval").iterdir()
        if p.is_dir() and p.name.isdigit()
    )

    print(f"Inspecting {len(interval_dirs)} interval capture(s)...")

    specs = [
        ("allocations.json", "allocation", ("Allocations", "Items"), summarize_alloc),
        ("evaluations.json", "evaluation", ("Evaluations", "Items"), summarize_eval),
        ("nodes.json", "node", ("Nodes", "Items"), summarize_node),
    ]

    for idir in interval_dirs:
        capture_dt = interval_capture_timestamp(idir)

        if not within_window(capture_dt, start, end):
            continue

        for filename, object_type, wrappers, summarizer in specs:
            path = idir / filename

            if not path.is_file():
                continue

            try:
                data = load_json(path)
            except (OSError, json.JSONDecodeError):
                continue

            for record in records_from_snapshot(data, wrappers):
                if not matches_filters(record, needles):
                    continue

                object_id, details = summarizer(record)
                event_name = f"{object_type} observed in interval {idir.name}"

                events.append(
                    TimelineEvent(
                        timestamp_utc=iso(capture_dt),
                        sort_ts=capture_dt.timestamp() if capture_dt else float("inf"),
                        source_type="interval_snapshot",
                        source_file=str(path.relative_to(root)),
                        source_line=None,
                        object_type=object_type,
                        object_id=object_id,
                        event=event_name,
                        details=details,
                        relevance=relevance_for(event_name, details, "interval_snapshot"),
                    )
                )

    return events


def iter_eventstream(path: Path):
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        first = next((line.lstrip() for line in fh if line.strip()), None)

    if not first:
        return

    if first.startswith("["):
        data = load_json(path)

        if isinstance(data, list):
            for idx, item in enumerate(data, 1):
                if isinstance(item, dict):
                    yield idx, item

        return

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh, 1):
            if not line.strip():
                continue

            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            if isinstance(item, dict):
                yield line_no, item


def eventstream_timestamp(record: dict) -> Optional[datetime]:
    for key in ("Timestamp", "Time", "EventTime"):
        value = record.get(key)

        if isinstance(value, str):
            dt = parse_ts(value)
            if dt:
                return dt

        elif isinstance(value, (int, float)):
            dt = unixish_to_dt(value)
            if dt:
                return dt

    payload = record.get("Payload")

    if isinstance(payload, dict):
        for name in ("Allocation", "Evaluation", "Node"):
            obj = payload.get(name)

            if isinstance(obj, dict):
                for key in ("ModifyTime", "CreateTime"):
                    dt = unixish_to_dt(obj.get(key))
                    if dt:
                        return dt

    return None


def collect_eventstream_events(
    bundle_root: Path,
    root: Path,
    start: Optional[datetime],
    end: Optional[datetime],
    needles: list[str],
) -> list[TimelineEvent]:
    path = bundle_root / "cluster" / "eventstream.json"

    if not path.is_file():
        return []

    print("Parsing cluster/eventstream.json structurally...")
    events = []

    try:
        for line_no, record in iter_eventstream(path):
            if not matches_filters(record, needles):
                continue

            dt = eventstream_timestamp(record)

            if not within_window(dt, start, end):
                continue

            topic = str(record.get("Topic") or "Unknown")
            event_type = str(record.get("Type") or "Unknown")
            obj_id = str(record.get("Key") or "")
            details = []

            if record.get("Index") is not None:
                details.append(f"index={record['Index']}")

            payload = record.get("Payload")

            if isinstance(payload, dict):
                for name, summarizer in (
                    ("Allocation", summarize_alloc),
                    ("Evaluation", summarize_eval),
                    ("Node", summarize_node),
                ):
                    obj = payload.get(name)

                    if isinstance(obj, dict):
                        _, summary = summarizer(obj)

                        if summary:
                            details.append(summary)

                        break

            if record.get("FilterKeys"):
                details.append(f"filter_keys={compact(record['FilterKeys'], 220)}")

            event_name = f"{topic} / {event_type}"
            detail_text = "; ".join(details)

            events.append(
                TimelineEvent(
                    timestamp_utc=iso(dt),
                    sort_ts=dt.timestamp() if dt else float("inf"),
                    source_type="event_stream",
                    source_file=str(path.relative_to(root)),
                    source_line=line_no,
                    object_type=topic.lower(),
                    object_id=obj_id,
                    event=event_name,
                    details=detail_text,
                    relevance=relevance_for(event_name, detail_text, "event_stream"),
                )
            )

    except OSError:
        pass

    print(f"Structured event-stream match(es): {len(events)}")

    return events


def excerpt(line: str, needles: list[str], width: int) -> str:
    clean = line.rstrip("\r\n")
    positions = [clean.find(n) for n in needles if n and clean.find(n) >= 0]

    if not positions:
        return clean if len(clean) <= width else clean[:width] + " …[truncated]"

    pos = min(positions)
    half = width // 2
    start = max(0, pos - half)
    end = min(len(clean), start + width)

    if end - start < width:
        start = max(0, end - width)

    return (
        ("… " if start else "")
        + clean[start:end]
        + (" …[truncated]" if end < len(clean) else "")
    )


def classify_log(line: str) -> str:
    lower = line.lower()

    rules = [
        ("task not restarting", ("not restarting",)),
        ("task restart signaled", ("restart signaled",)),
        ("task restarting", ("restarting",)),
        ("disk migration", ("migrate_disk", "snapshot from previous alloc")),
        ("health check", ("healthcheck", "health check", "check_restart")),
        ("task killing", ("task killing", " killing",)),
        ("task terminated", ("task terminated", "terminated")),
        ("task started", ("task started", " started")),
        ("node drain", ("drain", "draining")),
        ("reschedule", ("reschedul",)),
        ("migration", ("migrat",)),
        ("template render", ("template-render", "rendering")),
        ("scheduler", ("scheduler", "plan", "evaluation")),
    ]

    for name, tokens in rules:
        if any(token in lower for token in tokens):
            return name

    return "matching log record"


def is_debug_collection_traffic(line: str) -> bool:
    return any(token in line for token in DEBUG_TRAFFIC_PATTERNS)


def normalize_log_for_dedupe(line: str) -> str:
    """
    Remove the leading timestamp so identical client/server monitor lines can
    collapse even if timestamps are identical-but-formatted once per source.
    """
    text = line.rstrip("\r\n")
    return re.sub(
        r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{4}\s+",
        "",
        text,
    )


def collect_monitor_events(
    bundle_root: Path,
    root: Path,
    start: Optional[datetime],
    end: Optional[datetime],
    needles: list[str],
    max_matches: int,
    line_width: int,
    include_debug_traffic: bool,
) -> tuple[list[TimelineEvent], int, int]:
    paths = []

    for side in ("server", "client"):
        paths += list((bundle_root / side).glob("*/monitor.log"))

    paths = sorted(p for p in paths if p.is_file())

    print(f"Scanning {len(paths)} monitor.log file(s)...")

    raw_matches = []
    suppressed = 0

    for path in paths:
        side = "server" if "/server/" in str(path).replace("\\", "/") else "client"

        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line_no, line in enumerate(fh, 1):
                if needles and not any(n in line for n in needles):
                    continue

                timestamps = timestamps_in_text(line)
                dt = timestamps[0] if timestamps else None

                if not within_window(dt, start, end):
                    continue

                if not include_debug_traffic and is_debug_collection_traffic(line):
                    suppressed += 1
                    continue

                raw_matches.append(
                    {
                        "timestamp": dt,
                        "side": side,
                        "path": path,
                        "line_no": line_no,
                        "line": line.rstrip("\r\n"),
                        "dedupe": normalize_log_for_dedupe(line),
                    }
                )

    total_matches = len(raw_matches)

    grouped = defaultdict(list)

    for item in raw_matches:
        # Exact timestamp + normalized message gives a safe duplicate key.
        ts_key = iso(item["timestamp"])
        grouped[(ts_key, item["dedupe"])].append(item)

    events = []

    for (_, _), items in grouped.items():
        first = items[0]
        sides = sorted({item["side"] for item in items})
        source_group = ",".join(sides)

        if len(items) == 1:
            source_type = f"{first['side']}_monitor_log"
            source_file = str(first["path"].relative_to(root))
            source_line = first["line_no"]
        else:
            source_type = "correlated_monitor_log"
            source_file = " + ".join(
                sorted({str(item["path"].relative_to(root)) for item in items})
            )
            source_line = None

        event_name = classify_log(first["line"])
        detail_text = excerpt(first["line"], needles, line_width)

        events.append(
            TimelineEvent(
                timestamp_utc=iso(first["timestamp"]),
                sort_ts=first["timestamp"].timestamp() if first["timestamp"] else float("inf"),
                source_type=source_type,
                source_file=source_file,
                source_line=source_line,
                object_type="log",
                object_id="",
                event=event_name,
                details=detail_text,
                relevance=relevance_for(event_name, detail_text, source_type),
                source_group=source_group,
            )
        )

    events.sort(key=lambda e: (e.sort_ts, e.source_type, e.source_file))

    if len(events) > max_matches:
        events = events[:max_matches]

    print(f"Monitor-log match(es) after suppression : {total_matches}")
    print(f"Debug collection line(s) suppressed     : {suppressed}")
    print(f"Correlated monitor event(s) retained    : {len(events)}")

    return events, total_matches, suppressed


def snapshot_signature(event: TimelineEvent) -> tuple[str, str, str]:
    """
    Used only for the human Markdown view. Full CSV keeps all snapshots.
    """
    return (
        event.object_type,
        event.object_id,
        re.sub(r"interval \d{4}", "interval NNNN", event.details),
    )


def collapse_snapshot_view(events: list[TimelineEvent]) -> list[TimelineEvent]:
    """
    Collapse consecutive unchanged interval observations for the Markdown view.

    Example:
      node ready/eligible in intervals 0000..0009
    becomes one row describing the span.
    """
    out = []
    i = 0

    while i < len(events):
        current = events[i]

        if current.source_type != "interval_snapshot":
            out.append(current)
            i += 1
            continue

        sig = snapshot_signature(current)
        run = [current]
        j = i + 1

        while j < len(events):
            nxt = events[j]

            if nxt.source_type != "interval_snapshot":
                break

            if snapshot_signature(nxt) != sig:
                break

            run.append(nxt)
            j += 1

        if len(run) == 1:
            out.append(current)
        else:
            first = run[0]
            last = run[-1]
            details = (
                f"{first.details}; unchanged across {len(run)} captured interval observations "
                f"from {first.timestamp_utc} through {last.timestamp_utc}"
            )

            out.append(
                TimelineEvent(
                    timestamp_utc=first.timestamp_utc,
                    sort_ts=first.sort_ts,
                    source_type="interval_snapshot",
                    source_file=f"{first.source_file} … {last.source_file}",
                    source_line=None,
                    object_type=first.object_type,
                    object_id=first.object_id,
                    event=f"{first.object_type} state unchanged across {len(run)} intervals",
                    details=details,
                    relevance=first.relevance,
                    source_group="",
                )
            )

        i = j

    return out


def md_escape(value: Any) -> str:
    return str(value or "").replace("|", r"\|").replace("\n", " ")


def write_outputs(
    run_dir: Path,
    raw_events: list[TimelineEvent],
    root: Path,
    start: Optional[datetime],
    end: Optional[datetime],
    args: argparse.Namespace,
    monitor_total: int,
    suppressed_debug: int,
):
    csv_path = run_dir / "timeline.csv"
    md_path = run_dir / "timeline.md"
    json_path = run_dir / "summary.json"

    csv_fields = [
        "timestamp_utc",
        "source_type",
        "source_file",
        "source_line",
        "object_type",
        "object_id",
        "event",
        "details",
        "relevance",
        "source_group",
    ]

    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=csv_fields)
        writer.writeheader()

        for event in raw_events:
            row = asdict(event)
            row.pop("sort_ts")
            writer.writerow(row)

    markdown_events = collapse_snapshot_view(raw_events)

    relevance_order = {"high": 0, "medium": 1, "telemetry": 2}

    counts = Counter(e.source_type for e in raw_events)
    relevance_counts = Counter(e.relevance for e in raw_events)

    with md_path.open("w", encoding="utf-8") as fh:
        fh.write("# Correlated Nomad Timeline\n\n")
        fh.write(f"- Search root: `{root}`\n")
        fh.write(f"- Start UTC: `{iso(start)}`\n")
        fh.write(f"- End UTC: `{iso(end)}`\n")
        fh.write(f"- Allocation filters: `{', '.join(args.alloc)}`\n")
        fh.write(f"- Node filters: `{', '.join(args.node)}`\n")
        fh.write(f"- Evaluation filters: `{', '.join(args.eval)}`\n")
        fh.write(f"- Job filters: `{', '.join(args.job)}`\n")
        fh.write(f"- Text filters: `{', '.join(args.text)}`\n")
        fh.write(f"- Raw timeline events: **{len(raw_events)}**\n")
        fh.write(f"- Human-view events after snapshot collapsing: **{len(markdown_events)}**\n")
        fh.write(f"- Monitor-log matches after suppression: **{monitor_total}**\n")
        fh.write(f"- Debug collection lines suppressed: **{suppressed_debug}**\n\n")

        fh.write("## Relevance Counts\n\n")
        fh.write("| Relevance | Events |\n|---|---:|\n")

        for level in ("high", "medium", "telemetry"):
            fh.write(f"| {level} | {relevance_counts.get(level, 0)} |\n")

        fh.write("\n## Source Counts\n\n")
        fh.write("| Source Type | Events |\n|---|---:|\n")

        for source_type, count in counts.most_common():
            fh.write(f"| {md_escape(source_type)} | {count} |\n")

        fh.write("\n## Investigation Timeline\n\n")
        fh.write("| Timestamp (UTC) | Relevance | Source | Object | Event | Details |\n")
        fh.write("|---|---|---|---|---|---|\n")

        for event in markdown_events:
            source = event.source_file

            if event.source_line is not None:
                source += f":{event.source_line}"

            obj = event.object_type

            if event.object_id:
                obj += f": {event.object_id}"

            fh.write(
                f"| {md_escape(event.timestamp_utc)} | "
                f"{md_escape(event.relevance)} | "
                f"`{md_escape(source)}` | "
                f"{md_escape(obj)} | "
                f"{md_escape(event.event)} | "
                f"{md_escape(event.details)} |\n"
            )

        fh.write("\n## Notes\n\n")
        fh.write(
            "- This timeline correlates observations from supplied artifacts; "
            "it does not infer root cause.\n"
        )
        fh.write(
            "- Multiple filters are OR-matched to avoid hiding handoff/correlation events.\n"
        )
        fh.write(
            "- Known operator-debug self-observation HTTP traffic is suppressed by default. "
            "Use `--include-debug-traffic` to retain it.\n"
        )
        fh.write(
            "- `timeline.csv` preserves the full raw correlated timeline; the Markdown view "
            "collapses consecutive unchanged interval snapshots for readability.\n"
        )

    summary = {
        "search_root": str(root),
        "window": {
            "start_utc": iso(start),
            "end_utc": iso(end),
        },
        "filters": {
            "alloc": args.alloc,
            "node": args.node,
            "eval": args.eval,
            "job": args.job,
            "text": args.text,
        },
        "raw_timeline_event_count": len(raw_events),
        "human_view_event_count": len(markdown_events),
        "monitor_log_match_count_after_suppression": monitor_total,
        "debug_collection_lines_suppressed": suppressed_debug,
        "source_counts": dict(counts),
        "relevance_counts": dict(relevance_counts),
    }

    with json_path.open("w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
        fh.write("\n")

    return md_path, csv_path, json_path


def safe_slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)[:40]


def make_run_slug(args, start, end) -> str:
    parts = []

    if start or end:
        s = start.strftime("%Y%m%dT%H%M%SZ") if start else "begin"
        e = end.strftime("%Y%m%dT%H%M%SZ") if end else "end"
        parts.append(f"{s}_{e}")

    for label, values in (
        ("alloc", args.alloc),
        ("node", args.node),
        ("eval", args.eval),
        ("job", args.job),
        ("text", args.text),
    ):
        if values:
            parts.append(f"{label}-{safe_slug(values[0])}")

    return "__".join(parts) or "all-events"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Correlate Nomad debug-bundle observations into one timeline."
    )

    parser.add_argument("bundle", type=Path)

    parser.add_argument("--alloc", action="append", default=[])
    parser.add_argument("--node", action="append", default=[])
    parser.add_argument("--eval", action="append", default=[])
    parser.add_argument("--job", action="append", default=[])
    parser.add_argument("--text", action="append", default=[])

    parser.add_argument("--start")
    parser.add_argument("--end")
    parser.add_argument("--assume-tz")

    parser.add_argument(
        "--max-log-matches",
        type=int,
        default=DEFAULT_MAX_LOG_MATCHES,
    )

    parser.add_argument(
        "--line-width",
        type=int,
        default=DEFAULT_LINE_WIDTH,
    )

    parser.add_argument(
        "--include-debug-traffic",
        action="store_true",
        help="Retain operator-debug collection HTTP traffic such as pprof requests.",
    )

    parser.add_argument("--output", type=Path)
    parser.add_argument("--overwrite", action="store_true")

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.bundle.expanduser().resolve()

    if not root.is_dir():
        print(f"ERROR: bundle directory does not exist: {root}", file=sys.stderr)
        return 2

    if args.max_log_matches <= 0 or args.line_width <= 0:
        print("ERROR: limits must be greater than zero.", file=sys.stderr)
        return 2

    assume_tz = None

    if args.assume_tz:
        try:
            assume_tz = ZoneInfo(args.assume_tz)
        except ZoneInfoNotFoundError:
            print(f"ERROR: unknown timezone: {args.assume_tz}", file=sys.stderr)
            return 2

    try:
        start = parse_user_dt(args.start, assume_tz)
        end = parse_user_dt(args.end, assume_tz)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if start and end and end < start:
        print("ERROR: --end must be >= --start.", file=sys.stderr)
        return 2

    bundle_root = find_bundle_root(root)

    if not bundle_root:
        print("ERROR: standard Nomad operator debug layout not detected.", file=sys.stderr)
        return 2

    base_output = (
        args.output.expanduser().resolve()
        if args.output
        else (root.parent / "analysis_correlate_timeline").resolve()
    )

    run_dir = base_output / make_run_slug(args, start, end)

    if run_dir.exists():
        if not args.overwrite:
            print(
                f"ERROR: derived timeline already exists: {run_dir}\n"
                "Use --overwrite to replace it.",
                file=sys.stderr,
            )
            return 2

        shutil.rmtree(run_dir)

    run_dir.mkdir(parents=True, exist_ok=True)

    needles = list(
        dict.fromkeys(
            args.alloc + args.node + args.eval + args.job + args.text
        )
    )

    print(f"Search root      : {root}")
    print(f"Bundle root      : {bundle_root}")
    print(f"Start (UTC)      : {iso(start)}")
    print(f"End (UTC)        : {iso(end)}")
    print(f"Filters          : {len(needles)}")
    print(f"Output directory : {run_dir}")
    print()

    events = []

    events.extend(
        collect_eventstream_events(
            bundle_root,
            root,
            start,
            end,
            needles,
        )
    )

    events.extend(
        collect_snapshot_events(
            bundle_root,
            root,
            start,
            end,
            needles,
        )
    )

    log_events, monitor_total, suppressed_debug = collect_monitor_events(
        bundle_root,
        root,
        start,
        end,
        needles,
        args.max_log_matches,
        args.line_width,
        args.include_debug_traffic,
    )

    events.extend(log_events)

    events.sort(
        key=lambda e: (
            e.sort_ts,
            e.source_type,
            e.source_file,
            e.source_line if e.source_line is not None else -1,
        )
    )

    md_path, csv_path, json_path = write_outputs(
        run_dir,
        events,
        root,
        start,
        end,
        args,
        monitor_total,
        suppressed_debug,
    )

    print()
    print("Done.")
    print(f"  Raw timeline events      : {len(events)}")
    print(f"  Monitor matches retained : {monitor_total}")
    print(f"  Debug traffic suppressed : {suppressed_debug}")

    for source_type, count in Counter(e.source_type for e in events).most_common():
        print(f"    {source_type:<24} {count}")

    print()
    print(f"Timeline Markdown : {md_path}")
    print(f"Timeline CSV      : {csv_path}")
    print(f"Summary JSON      : {json_path}")
    print()
    print("Tip: inspect timeline.md first; timeline.csv keeps the full raw correlated view.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
