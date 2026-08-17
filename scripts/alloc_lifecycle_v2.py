#!/usr/bin/env python3
"""
alloc_lifecycle_v2.py

Reconstruct a bounded, chronological lifecycle for one Nomad allocation from an
unpacked `nomad operator debug` bundle or related customer artifact directory.

Version 2 fixes and improvements:
- Parses cluster/eventstream.json structurally instead of using substring
  classification.
- Uses the interval capture timestamp for snapshot observations, while preserving
  allocation ModifyTime/CreateTime in details.
- Prevents overlapping timestamp regexes from producing bogus duplicate times
  (for example treating 2026-08-14T10:17:40-0700 as both local-with-offset and UTC).
- Excludes goroutine-debug*.txt from generic lifecycle scans.
- Augments missing summary metadata from structured event-stream allocation
  payloads when available.
- Keeps output bounded, source-attributed, and observation-only.

Examples:
    python3 alloc_lifecycle_v2.py ./nomad-debug-test \
      --alloc ee943c77-0149-b085-fad0-de0f30f23c2c

Output:
    analysis_alloc_lifecycle/<alloc-id>/
      timeline.csv
      timeline.md
      snapshots.json
      eventstream.json
      summary.json
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import sys
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Optional

import _bundlelib as bl


DEFAULT_SAMPLES = 100
DEFAULT_LINE_WIDTH = 700
DEFAULT_PROGRESS_EVERY = 100

TEXT_EXTENSIONS = {
    ".log", ".txt", ".jsonl", ".ndjson", ".csv", ".tsv",
    ".out", ".err",
}

ALLOC_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)

PROFILE_TEXT_RE = re.compile(
    r"^(?:goroutine-debug1|goroutine-debug2)_\d{4}\.txt$"
)

@dataclass
class TimelineEvent:
    timestamp_utc: str
    sort_ts: float
    source_type: str
    source_file: str
    source_line: Optional[int]
    event: str
    details: str


def find_alloc_objects(obj: Any, alloc_id: str) -> list[dict]:
    found = []

    def walk(value: Any):
        if isinstance(value, dict):
            ids = []

            for key in ("ID", "Id", "id", "AllocID", "AllocationID"):
                v = value.get(key)
                if isinstance(v, str):
                    ids.append(v)

            if alloc_id in ids:
                found.append(value)

            for child in value.values():
                walk(child)

        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(obj)
    return found


def compact(value: Any, max_len: int = 300) -> str:
    if value is None:
        return ""

    if isinstance(value, (dict, list)):
        text = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    else:
        text = str(value)

    if len(text) > max_len:
        return text[:max_len] + " …[truncated]"

    return text


def snapshot_capture_timestamp(interval_dir: Path) -> Optional[datetime]:
    metrics = interval_dir / "metrics.json"

    if metrics.is_file():
        try:
            data = bl.load_json(metrics)
            if isinstance(data, dict):
                raw = data.get("Timestamp")
                if isinstance(raw, str):
                    parsed = bl.parse_ts(raw)
                    if parsed:
                        return parsed
        except (OSError, json.JSONDecodeError):
            pass

    for name in ("allocations.json", "evaluations.json", "nodes.json"):
        path = interval_dir / name
        if not path.is_file():
            continue

        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                text = fh.read(65536)

            timestamps = bl.timestamps_in_text(text)
            if timestamps:
                return min(timestamps)

        except OSError:
            continue

    return None


def snapshot_summary(alloc: dict, interval_id: str, source_file: str, capture_dt: Optional[datetime]) -> dict:
    create_dt = bl.unixish_to_dt(bl.first_value(alloc, ("CreateTime", "CreateTimestamp", "CreatedAt")))
    modify_dt = bl.unixish_to_dt(bl.first_value(alloc, ("ModifyTime", "ModifyTimestamp", "UpdatedAt")))

    job = alloc.get("Job")

    job_id = bl.first_value(alloc, ("JobID",))
    namespace = bl.first_value(alloc, ("Namespace",))
    task_group = bl.first_value(alloc, ("TaskGroup", "TaskGroupName"))
    node_id = bl.first_value(alloc, ("NodeID",))
    node_name = bl.first_value(alloc, ("NodeName",))
    client_status = bl.first_value(alloc, ("ClientStatus",))
    desired_status = bl.first_value(alloc, ("DesiredStatus",))
    previous_alloc = bl.first_value(alloc, ("PreviousAllocation", "PreviousAllocID"))
    next_alloc = bl.first_value(alloc, ("NextAllocation", "NextAllocID"))
    eval_id = bl.first_value(alloc, ("EvalID",))
    deployment_id = bl.first_value(alloc, ("DeploymentID",))

    if isinstance(job, dict):
        job_id = job_id or bl.first_value(job, ("ID", "Name"))
        namespace = namespace or bl.first_value(job, ("Namespace",))

    return {
        "interval_id": interval_id,
        "source_file": source_file,
        "capture_timestamp_utc": bl.iso(capture_dt),
        "id": bl.first_value(alloc, ("ID", "Id", "id", "AllocID", "AllocationID")),
        "job_id": job_id,
        "namespace": namespace,
        "task_group": task_group,
        "node_id": node_id,
        "node_name": node_name,
        "eval_id": eval_id,
        "deployment_id": deployment_id,
        "desired_status": desired_status,
        "client_status": client_status,
        "previous_allocation": previous_alloc,
        "next_allocation": next_alloc,
        "create_time_utc": bl.iso(create_dt),
        "modify_time_utc": bl.iso(modify_dt),
        "desired_description": bl.first_value(alloc, ("DesiredDescription",)),
        "client_description": bl.first_value(alloc, ("ClientDescription",)),
        "reschedule_tracker": alloc.get("RescheduleTracker"),
        "desired_transition": alloc.get("DesiredTransition"),
        "task_states": alloc.get("TaskStates"),
    }


def collect_snapshots(bundle_root: Path, root: Path, alloc_id: str) -> list[dict]:
    snapshots = []
    interval_root = bundle_root / "interval"

    if not interval_root.is_dir():
        return snapshots

    interval_dirs = sorted(
        p for p in interval_root.iterdir()
        if p.is_dir() and p.name.isdigit()
    )

    print(f"Inspecting {len(interval_dirs)} interval allocation snapshot(s)...")

    for interval_dir in interval_dirs:
        path = interval_dir / "allocations.json"

        if not path.is_file():
            continue

        try:
            data = bl.load_json(path)
        except (OSError, json.JSONDecodeError):
            continue

        matches = find_alloc_objects(data, alloc_id)
        if not matches:
            continue

        capture_dt = snapshot_capture_timestamp(interval_dir)

        for alloc in matches:
            snapshots.append(
                snapshot_summary(
                    alloc=alloc,
                    interval_id=interval_dir.name,
                    source_file=str(path.relative_to(root)),
                    capture_dt=capture_dt,
                )
            )

    snapshots.sort(key=lambda x: int(x["interval_id"]))
    print(f"Allocation present in {len(snapshots)} interval snapshot(s).")

    return snapshots


def build_snapshot_events(snapshots: list[dict]) -> list[TimelineEvent]:
    """
    Snapshot observations are timestamped by capture time, not allocation
    ModifyTime. Modify/Create times are preserved in details.
    """
    events = []
    previous = None

    for snapshot in snapshots:
        capture_dt = bl.parse_ts(snapshot.get("capture_timestamp_utc", ""))

        if capture_dt is None:
            sort_ts = float("inf")
        else:
            sort_ts = capture_dt.timestamp()

        if previous is None:
            details = (
                f"interval={snapshot['interval_id']} "
                f"job={snapshot.get('job_id') or ''} "
                f"group={snapshot.get('task_group') or ''} "
                f"node={snapshot.get('node_id') or ''} "
                f"desired={snapshot.get('desired_status') or ''} "
                f"client={snapshot.get('client_status') or ''} "
                f"create_time={snapshot.get('create_time_utc') or ''} "
                f"modify_time={snapshot.get('modify_time_utc') or ''}"
            ).strip()

            events.append(
                TimelineEvent(
                    timestamp_utc=bl.iso(capture_dt),
                    sort_ts=sort_ts,
                    source_type="allocation_snapshot",
                    source_file=snapshot["source_file"],
                    source_line=None,
                    event="allocation observed in interval snapshot",
                    details=details,
                )
            )

        else:
            changed = []

            fields = [
                ("node_id", "node"),
                ("desired_status", "desired_status"),
                ("client_status", "client_status"),
                ("previous_allocation", "previous_allocation"),
                ("next_allocation", "next_allocation"),
                ("eval_id", "eval_id"),
                ("deployment_id", "deployment_id"),
            ]

            for key, label in fields:
                old = previous.get(key)
                new = snapshot.get(key)

                if old != new:
                    changed.append(f"{label}: {old!r} -> {new!r}")

            if previous.get("task_states") != snapshot.get("task_states"):
                changed.append("task_states changed")

            if previous.get("desired_transition") != snapshot.get("desired_transition"):
                changed.append("desired_transition changed")

            if previous.get("reschedule_tracker") != snapshot.get("reschedule_tracker"):
                changed.append("reschedule_tracker changed")

            if changed:
                details = "; ".join(changed)
                details += (
                    f"; allocation_modify_time={snapshot.get('modify_time_utc') or ''}"
                )

                events.append(
                    TimelineEvent(
                        timestamp_utc=bl.iso(capture_dt),
                        sort_ts=sort_ts,
                        source_type="allocation_snapshot",
                        source_file=snapshot["source_file"],
                        source_line=None,
                        event=f"snapshot change at interval {snapshot['interval_id']}",
                        details=details,
                    )
                )

        previous = snapshot

    return events


def event_contains_alloc(record: dict, alloc_id: str) -> bool:
    if record.get("Key") == alloc_id:
        return True

    try:
        text = json.dumps(record, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError):
        return False

    return alloc_id in text


def event_timestamp(record: dict) -> Optional[datetime]:
    """
    Prefer explicit event timestamps, then inspect structured payload fields.
    """
    for key in ("Timestamp", "Time", "EventTime"):
        value = record.get(key)
        if isinstance(value, str):
            dt = bl.parse_ts(value)
            if dt:
                return dt
        elif isinstance(value, (int, float)):
            dt = bl.unixish_to_dt(value)
            if dt:
                return dt

    payload = record.get("Payload")

    if isinstance(payload, dict):
        # Allocation payloads commonly expose CreateTime/ModifyTime.
        alloc = payload.get("Allocation")

        if isinstance(alloc, dict):
            for key in ("ModifyTime", "CreateTime"):
                dt = bl.unixish_to_dt(alloc.get(key))
                if dt:
                    return dt

        # Some event stream records may carry task-event timestamps.
        for key in ("Timestamp", "Time"):
            value = payload.get(key)
            if isinstance(value, str):
                dt = bl.parse_ts(value)
                if dt:
                    return dt

    return None


def summarize_allocation_payload(alloc: dict) -> str:
    parts = []

    for key, label in (
        ("ClientStatus", "client"),
        ("DesiredStatus", "desired"),
        ("NodeID", "node"),
        ("EvalID", "eval"),
        ("DeploymentID", "deployment"),
        ("PreviousAllocation", "previous"),
        ("NextAllocation", "next"),
    ):
        value = alloc.get(key)
        if value not in (None, "", []):
            parts.append(f"{label}={value}")

    client_desc = alloc.get("ClientDescription")
    desired_desc = alloc.get("DesiredDescription")

    if client_desc:
        parts.append(f"client_description={client_desc}")

    if desired_desc:
        parts.append(f"desired_description={desired_desc}")

    task_states = alloc.get("TaskStates")
    if isinstance(task_states, dict):
        state_parts = []

        for task_name, state in task_states.items():
            if not isinstance(state, dict):
                continue

            state_parts.append(
                f"{task_name}:{state.get('State') or ''}"
            )

        if state_parts:
            parts.append("tasks=" + ",".join(state_parts))

    return "; ".join(parts)


def parse_eventstream(
    bundle_root: Path,
    root: Path,
    alloc_id: str,
) -> tuple[list[TimelineEvent], list[dict]]:
    path = bundle_root / "cluster" / "eventstream.json"

    if not path.is_file():
        return [], []

    events = []
    raw_matches = []

    print("Parsing cluster/eventstream.json structurally...")

    for line_no, record in bl.iter_eventstream_records(path):
        if not event_contains_alloc(record, alloc_id):
            continue

        raw_matches.append(record)

        topic = str(record.get("Topic") or "Unknown")
        event_type = str(record.get("Type") or "Unknown")
        dt = event_timestamp(record)

        details_parts = []

        index = record.get("Index")
        if index is not None:
            details_parts.append(f"index={index}")

        payload = record.get("Payload")
        if isinstance(payload, dict):
            alloc = payload.get("Allocation")

            if isinstance(alloc, dict):
                alloc_summary = summarize_allocation_payload(alloc)
                if alloc_summary:
                    details_parts.append(alloc_summary)

        filter_keys = record.get("FilterKeys")
        if filter_keys:
            details_parts.append(f"filter_keys={compact(filter_keys, 220)}")

        events.append(
            TimelineEvent(
                timestamp_utc=bl.iso(dt),
                sort_ts=dt.timestamp() if dt else float("inf"),
                source_type="event_stream",
                source_file=str(path.relative_to(root)),
                source_line=line_no,
                event=f"{topic} / {event_type}",
                details="; ".join(details_parts),
            )
        )

    print(f"Structured event-stream match(es): {len(events)}")

    return events, raw_matches


def augment_summary_from_eventstream(summary: dict, records: list[dict]) -> dict:
    """
    Fill only missing values. Never overwrite snapshot-derived metadata.
    """
    for record in records:
        payload = record.get("Payload")
        if not isinstance(payload, dict):
            continue

        alloc = payload.get("Allocation")
        if not isinstance(alloc, dict):
            continue

        mapping = {
            "job_id": alloc.get("JobID"),
            "namespace": alloc.get("Namespace"),
            "task_group": alloc.get("TaskGroup"),
            "node_id": alloc.get("NodeID"),
            "node_name": alloc.get("NodeName"),
            "eval_id": alloc.get("EvalID"),
            "deployment_id": alloc.get("DeploymentID"),
            "previous_allocation": alloc.get("PreviousAllocation"),
            "next_allocation": alloc.get("NextAllocation"),
        }

        for key, value in mapping.items():
            if summary.get(key) in (None, "") and value not in (None, ""):
                summary[key] = value

        if summary.get("create_time_utc") in (None, ""):
            dt = bl.unixish_to_dt(alloc.get("CreateTime"))
            if dt:
                summary["create_time_utc"] = bl.iso(dt)

    return summary


def excerpt_around(line: str, needle: str, width: int) -> str:
    clean = line.rstrip("\r\n")
    pos = clean.find(needle)

    if pos < 0:
        return compact(clean, width)

    if len(clean) <= width:
        return clean

    half = max(1, (width - len(needle)) // 2)
    start = max(0, pos - half)
    end = min(len(clean), pos + len(needle) + half)

    if end - start < width:
        remaining = width - (end - start)

        if start == 0:
            end = min(len(clean), end + remaining)
        elif end == len(clean):
            start = max(0, start - remaining)

    prefix = "… " if start > 0 else ""
    suffix = " …[truncated]" if end < len(clean) else ""

    return prefix + clean[start:end] + suffix


def classify_monitor_line(line: str) -> str:
    lower = line.lower()

    # Order matters: specific before general.
    rules = [
        ("task not restarting", ("not restarting",)),
        ("task restart signaled", ("restart signaled",)),
        ("task restarting", ("restarting",)),
        ("disk migration", ("migrate_disk", "migrating data", "snapshot from previous alloc")),
        ("health check", ("healthcheck", "health check", "check_restart")),
        ("task killing", ("task killing", " killing",)),
        ("task terminated", ("task terminated", "terminated")),
        ("task started", ("task started", " started")),
        ("node drain", ("drain", "draining")),
        ("allocation reschedule", ("reschedul",)),
        ("allocation migration", ("migrat",)),
        ("template render", ("template-render", "rendering")),
        ("allocation log record", ("alloc",)),
    ]

    for event_name, needles in rules:
        if any(needle in lower for needle in needles):
            return event_name

    return "matching log record"


def iter_line_sources(root: Path, eventstream_path: Optional[Path]) -> Iterable[Path]:
    for dirpath, _, filenames in os.walk(root):
        current = Path(dirpath)

        for filename in filenames:
            path = current / filename

            if not path.is_file() or path.is_symlink():
                continue

            if eventstream_path and path.resolve() == eventstream_path.resolve():
                continue

            if PROFILE_TEXT_RE.match(path.name):
                continue

            lower = path.name.lower()

            if lower == "monitor.log":
                yield path
                continue

            if path.suffix.lower() in TEXT_EXTENSIONS:
                yield path


def scan_line_sources(
    root: Path,
    alloc_id: str,
    sample_limit: int,
    line_width: int,
    eventstream_path: Optional[Path],
) -> list[TimelineEvent]:
    events = []
    matched = 0
    files = sorted(set(iter_line_sources(root, eventstream_path)))

    print(f"Scanning {len(files):,} line-oriented source file(s)...")

    for index, path in enumerate(files, start=1):
        if index == 1 or index % DEFAULT_PROGRESS_EVERY == 0 or index == len(files):
            print(f"  [{index:,}/{len(files):,}] {path.relative_to(root)}")

        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for line_no, line in enumerate(fh, start=1):
                    if alloc_id not in line:
                        continue

                    matched += 1

                    if len(events) >= sample_limit:
                        continue

                    timestamps = bl.timestamps_in_text(line)
                    dt = timestamps[0] if timestamps else None

                    source_type = (
                        "monitor_log"
                        if path.name.lower() == "monitor.log"
                        else "text_source"
                    )

                    events.append(
                        TimelineEvent(
                            timestamp_utc=bl.iso(dt),
                            sort_ts=dt.timestamp() if dt else float("inf"),
                            source_type=source_type,
                            source_file=str(path.relative_to(root)),
                            source_line=line_no,
                            event=classify_monitor_line(line),
                            details=excerpt_around(line, alloc_id, line_width),
                        )
                    )

        except (OSError, UnicodeError):
            continue

    if matched > sample_limit:
        print(
            f"  Note: {matched:,} matching line(s) found; "
            f"timeline retained first {sample_limit:,} bounded record(s)."
        )
    else:
        print(f"  Matching line(s) retained: {matched:,}")

    return events


def write_timeline_csv(events: list[TimelineEvent], path: Path) -> None:
    fields = [
        "timestamp_utc",
        "source_type",
        "source_file",
        "source_line",
        "event",
        "details",
    ]

    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()

        for event in events:
            row = asdict(event)
            row.pop("sort_ts")
            writer.writerow(row)


def write_markdown(
    path: Path,
    alloc_id: str,
    summary: dict,
    snapshots: list[dict],
    events: list[TimelineEvent],
) -> None:
    with path.open("w", encoding="utf-8") as fh:
        fh.write(f"# Allocation Lifecycle: `{alloc_id}`\n\n")

        fh.write("## Allocation Summary\n\n")
        fh.write(f"- Job: `{bl.md_escape(summary.get('job_id', ''))}`\n")
        fh.write(f"- Namespace: `{bl.md_escape(summary.get('namespace', ''))}`\n")
        fh.write(f"- Task group: `{bl.md_escape(summary.get('task_group', ''))}`\n")
        fh.write(f"- Node ID: `{bl.md_escape(summary.get('node_id', ''))}`\n")
        fh.write(f"- Node name: `{bl.md_escape(summary.get('node_name', ''))}`\n")
        fh.write(f"- Eval ID: `{bl.md_escape(summary.get('eval_id', ''))}`\n")
        fh.write(f"- Deployment ID: `{bl.md_escape(summary.get('deployment_id', ''))}`\n")
        fh.write(f"- Previous allocation: `{bl.md_escape(summary.get('previous_allocation', ''))}`\n")
        fh.write(f"- Next allocation: `{bl.md_escape(summary.get('next_allocation', ''))}`\n")
        fh.write(f"- Create time: `{bl.md_escape(summary.get('create_time_utc', ''))}`\n")
        fh.write(f"- Interval snapshots containing allocation: **{len(snapshots)}**\n")
        fh.write(f"- Timeline events retained: **{len(events)}**\n\n")

        fh.write("## Interval Snapshot History\n\n")

        if snapshots:
            fh.write(
                "| Interval | Capture Time | Modify Time | Desired | Client | "
                "Node | Previous Allocation | Next Allocation |\n"
            )
            fh.write("|---|---|---|---|---|---|---|---|\n")

            for snap in snapshots:
                fh.write(
                    f"| `{snap['interval_id']}` | "
                    f"{bl.md_escape(snap.get('capture_timestamp_utc', ''))} | "
                    f"{bl.md_escape(snap.get('modify_time_utc', ''))} | "
                    f"{bl.md_escape(snap.get('desired_status', ''))} | "
                    f"{bl.md_escape(snap.get('client_status', ''))} | "
                    f"`{bl.md_escape(snap.get('node_id', ''))}` | "
                    f"`{bl.md_escape(snap.get('previous_allocation', ''))}` | "
                    f"`{bl.md_escape(snap.get('next_allocation', ''))}` |\n"
                )
        else:
            fh.write("Allocation was not found in interval `allocations.json` snapshots.\n")

        fh.write("\n## Chronological Timeline\n\n")

        if events:
            fh.write("| Timestamp (UTC) | Source | Event | Details |\n")
            fh.write("|---|---|---|---|\n")

            for event in events:
                source = event.source_file

                if event.source_line is not None:
                    source += f":{event.source_line}"

                fh.write(
                    f"| {bl.md_escape(event.timestamp_utc)} | "
                    f"`{bl.md_escape(source)}` | "
                    f"{bl.md_escape(event.event)} | "
                    f"{bl.md_escape(event.details)} |\n"
                )
        else:
            fh.write("No timeline events were found for this allocation.\n")

        fh.write("\n## Notes\n\n")
        fh.write(
            "- This report records observations from the supplied artifacts; "
            "it does not infer root cause.\n"
        )
        fh.write(
            "- Interval snapshot rows are timestamped by capture time. Allocation "
            "CreateTime/ModifyTime are state metadata and are shown separately.\n"
        )
        fh.write(
            "- Event stream records use their structured Topic/Type rather than "
            "substring-based event classification.\n"
        )
        fh.write(
            "- Exit code 137, if present in logs, is not by itself proof of an OOM kill; "
            "the surrounding lifecycle context must be considered.\n"
        )


def build_summary(
    alloc_id: str,
    snapshots: list[dict],
    eventstream_records: list[dict],
    timeline_count: int,
) -> dict:
    first = snapshots[0] if snapshots else {}

    summary = {
        "allocation_id": alloc_id,
        "job_id": first.get("job_id"),
        "namespace": first.get("namespace"),
        "task_group": first.get("task_group"),
        "node_id": first.get("node_id"),
        "node_name": first.get("node_name"),
        "eval_id": first.get("eval_id"),
        "deployment_id": first.get("deployment_id"),
        "previous_allocation": first.get("previous_allocation"),
        "next_allocation": first.get("next_allocation"),
        "create_time_utc": first.get("create_time_utc"),
        "snapshot_count": len(snapshots),
        "timeline_event_count": timeline_count,
    }

    return augment_summary_from_eventstream(summary, eventstream_records)


def write_summary_json(path: Path, summary: dict) -> None:
    with path.open("w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
        fh.write("\n")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Reconstruct a bounded lifecycle for one Nomad allocation."
    )

    parser.add_argument(
        "bundle",
        type=Path,
        help="Path to an unpacked Nomad debug bundle or parent artifact directory.",
    )

    parser.add_argument(
        "--alloc",
        required=True,
        help="Full Nomad allocation UUID.",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Base output directory. Default: <bundle-parent>/analysis_alloc_lifecycle",
    )

    parser.add_argument(
        "--samples",
        type=int,
        default=DEFAULT_SAMPLES,
        help=f"Maximum matching non-eventstream line records retained. Default: {DEFAULT_SAMPLES}.",
    )

    parser.add_argument(
        "--line-width",
        type=int,
        default=DEFAULT_LINE_WIDTH,
        help=f"Maximum characters retained around each line match. Default: {DEFAULT_LINE_WIDTH}.",
    )

    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace an existing derived report for this allocation.",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    root = args.bundle.expanduser().resolve()

    if not root.exists():
        print(f"ERROR: bundle path does not exist: {root}", file=sys.stderr)
        return 2

    if not root.is_dir():
        print(f"ERROR: bundle path is not a directory: {root}", file=sys.stderr)
        return 2

    if args.samples <= 0 or args.line_width <= 0:
        print("ERROR: --samples and --line-width must be greater than zero.", file=sys.stderr)
        return 2

    if not ALLOC_UUID_RE.fullmatch(args.alloc):
        print(
            "ERROR: --alloc must be a full allocation UUID "
            "(xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).",
            file=sys.stderr,
        )
        return 2

    alloc_id = args.alloc

    base_output = (
        args.output.expanduser().resolve()
        if args.output
        else (root.parent / "analysis_alloc_lifecycle").resolve()
    )

    run_dir = base_output / alloc_id

    if run_dir.exists():
        if not args.overwrite:
            print(
                f"ERROR: derived allocation report already exists: {run_dir}\n"
                "Use --overwrite to replace it.",
                file=sys.stderr,
            )
            return 2

        shutil.rmtree(run_dir)

    run_dir.mkdir(parents=True, exist_ok=True)

    bundle_root = bl.find_bundle_root(root)

    print(f"Search root      : {root}")
    print(f"Allocation       : {alloc_id}")
    print(f"Bundle detected  : {'yes' if bundle_root else 'no'}")
    print(f"Output directory : {run_dir}")
    print("Source artifacts are opened read-only.")
    print()

    snapshots = []

    if bundle_root:
        snapshots = collect_snapshots(
            bundle_root=bundle_root,
            root=root,
            alloc_id=alloc_id,
        )
    else:
        print("Standard Nomad debug layout not detected; skipping interval snapshot analysis.")

    snapshot_events = build_snapshot_events(snapshots)

    eventstream_events = []
    eventstream_records = []
    eventstream_path = None

    if bundle_root:
        eventstream_path = bundle_root / "cluster" / "eventstream.json"

        eventstream_events, eventstream_records = parse_eventstream(
            bundle_root=bundle_root,
            root=root,
            alloc_id=alloc_id,
        )

    line_events = scan_line_sources(
        root=root,
        alloc_id=alloc_id,
        sample_limit=args.samples,
        line_width=args.line_width,
        eventstream_path=eventstream_path if eventstream_path and eventstream_path.is_file() else None,
    )

    events = snapshot_events + eventstream_events + line_events

    events.sort(
        key=lambda e: (
            e.sort_ts,
            e.source_type,
            e.source_file,
            e.source_line if e.source_line is not None else -1,
        )
    )

    summary = build_summary(
        alloc_id=alloc_id,
        snapshots=snapshots,
        eventstream_records=eventstream_records,
        timeline_count=len(events),
    )

    timeline_csv = run_dir / "timeline.csv"
    timeline_md = run_dir / "timeline.md"
    snapshots_json = run_dir / "snapshots.json"
    eventstream_json = run_dir / "eventstream.json"
    summary_json = run_dir / "summary.json"

    write_timeline_csv(events, timeline_csv)
    write_markdown(
        timeline_md,
        alloc_id,
        summary,
        snapshots,
        events,
    )

    with snapshots_json.open("w", encoding="utf-8") as fh:
        json.dump(snapshots, fh, indent=2)
        fh.write("\n")

    with eventstream_json.open("w", encoding="utf-8") as fh:
        json.dump(eventstream_records, fh, indent=2)
        fh.write("\n")

    write_summary_json(summary_json, summary)

    print()
    print("Done.")
    print(f"  Interval snapshots   : {len(snapshots)}")
    print(f"  Event-stream records : {len(eventstream_records)}")
    print(f"  Timeline events      : {len(events)}")
    print(f"  Job                  : {summary.get('job_id') or ''}")
    print(f"  Task group           : {summary.get('task_group') or ''}")
    print(f"  Node                 : {summary.get('node_id') or ''}")
    print(f"  Deployment           : {summary.get('deployment_id') or ''}")
    print(f"  Previous alloc       : {summary.get('previous_allocation') or ''}")
    print(f"  Next alloc           : {summary.get('next_allocation') or ''}")
    print()
    print(f"Timeline Markdown : {timeline_md}")
    print(f"Timeline CSV      : {timeline_csv}")
    print(f"Snapshots JSON    : {snapshots_json}")
    print(f"Eventstream JSON  : {eventstream_json}")
    print(f"Summary JSON      : {summary_json}")
    print()
    print("Tip: inspect timeline.md first; event stream records are now structurally classified.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
