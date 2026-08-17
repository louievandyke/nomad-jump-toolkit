#!/usr/bin/env python3
"""
extract_window.py

Create a reduced, read-only forensic view of a Nomad operator debug bundle
for a specific incident time window.

Version 2 improvements:
- Supports Nomad monitor.log timestamps like:
    2026-08-14T10:18:17.883-0700
- Excludes goroutine-debug*.txt and other profile artifacts from generic log scans.
- Uses deterministic per-window output directories.
- Refuses to overwrite an existing run unless --overwrite is supplied.
- Clears only the selected derived run directory when --overwrite is used.
- Preserves source-relative paths and hashes source/derived files.
- Keeps stdout bounded.

Safety / forensic goals:
- Never modify source artifacts.
- Python standard library only.
- Bounded terminal output.
- No implicit timezone guessing for user-supplied naive timestamps.
- Derived output is isolated from customer data.

Examples:
    python3 extract_window.py ./nomad-debug-test \
      --start 2026-08-14T17:18:30Z \
      --end   2026-08-14T17:20:30Z

    python3 extract_window.py ./nomad-debug-test \
      --start 2026-08-14T10:18:30 \
      --end   2026-08-14T10:20:30 \
      --assume-tz America/Los_Angeles

    python3 extract_window.py ./bundle \
      --start 2026-07-31T04:20:00Z \
      --end   2026-07-31T05:30:00Z \
      --include-static \
      --include-profiles
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import sys
from collections import Counter
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

DEFAULT_SCAN_MB = 8
DEFAULT_PROGRESS_EVERY = 100

TEXT_EXTENSIONS = {
    ".log", ".txt", ".json", ".jsonl", ".ndjson", ".csv", ".tsv",
    ".hcl", ".nomad", ".md", ".yaml", ".yml", ".conf", ".cfg",
    ".out", ".err",
}

PROFILE_RE = re.compile(
    r"^(?:goroutine|goroutine-debug1|goroutine-debug2|heap|profile|threadcreate|trace)_(\d{4})\.(?:prof|txt)$"
)

# Explicitly exclude line-oriented profile dumps from generic incident-log scans.
PROFILE_TEXT_RE = re.compile(
    r"^(?:goroutine-debug1|goroutine-debug2)_\d{4}\.txt$"
)

TIMESTAMP_PATTERNS = [
    # 2026-08-14T17:18:10Z
    re.compile(r"\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\b"),

    # 2026-08-14T17:18:10-07:00
    re.compile(r"\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{2}:\d{2})\b"),

    # Nomad monitor.log:
    # 2026-08-14T10:18:17.883-0700
    re.compile(r"\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{4})\b"),

    # 2026-08-14 17:18:10 +0000 UTC
    re.compile(r"\b(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?) ([+-]\d{4}) UTC\b"),

    # Naive timestamp occurring inside source data. We interpret source-naive
    # timestamps as UTC only for extraction compatibility; user-supplied
    # --start/--end still require an explicit timezone or --assume-tz.
    re.compile(r"\b(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\b"),
]


@dataclass
class ManifestRow:
    action: str
    relative_path: str
    source_size_bytes: int
    output_size_bytes: int
    source_sha256: str
    output_sha256: str
    matched_lines: int
    detected_first_timestamp: str
    detected_last_timestamp: str
    note: str


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


def parse_user_datetime(value: str, assume_tz: Optional[ZoneInfo]) -> datetime:
    raw = value.strip()

    try:
        if raw.endswith("Z"):
            dt = datetime.fromisoformat(raw[:-1] + "+00:00")
        else:
            dt = datetime.fromisoformat(raw)
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


def normalize_offset_no_colon(raw: str) -> str:
    """
    Convert trailing -0700/+0000 to -07:00/+00:00 for datetime.fromisoformat().
    """
    m = re.search(r"([+-])(\d{2})(\d{2})$", raw)
    if not m:
        return raw
    return raw[:m.start()] + f"{m.group(1)}{m.group(2)}:{m.group(3)}"


def parse_timestamp_text(raw: str, default_tz: timezone = timezone.utc) -> Optional[datetime]:
    raw = raw.strip()

    # "2026-08-14 17:18:10 +0000 UTC"
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


def timestamps_in_text(text: str) -> Iterable[datetime]:
    seen = set()

    for pattern in TIMESTAMP_PATTERNS:
        for match in pattern.finditer(text):
            if len(match.groups()) == 2:
                raw = f"{match.group(1)} {match.group(2)} UTC"
            else:
                raw = match.group(1)

            dt = parse_timestamp_text(raw)
            if dt is None:
                continue

            key = dt.isoformat()
            if key in seen:
                continue

            seen.add(key)
            yield dt


def timestamp_bounds_in_file(
    path: Path,
    max_scan_bytes: int,
) -> tuple[Optional[datetime], Optional[datetime]]:
    first = None
    last = None
    read_bytes = 0

    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                read_bytes += len(line.encode("utf-8", errors="replace"))

                for dt in timestamps_in_text(line):
                    if first is None or dt < first:
                        first = dt
                    if last is None or dt > last:
                        last = dt

                if read_bytes >= max_scan_bytes:
                    break

    except (OSError, UnicodeError):
        return None, None

    return first, last


def first_timestamp_from_file(path: Path, max_scan_bytes: int) -> Optional[datetime]:
    first, _ = timestamp_bounds_in_file(path, max_scan_bytes)
    return first


def find_bundle_root(root: Path) -> Optional[Path]:
    if (
        (root / "cluster").is_dir()
        and (root / "interval").is_dir()
        and (root / "server").is_dir()
        and (root / "client").is_dir()
    ):
        return root

    candidates = []

    try:
        for child in root.iterdir():
            if not child.is_dir():
                continue

            if (
                (child / "cluster").is_dir()
                and (child / "interval").is_dir()
                and (child / "server").is_dir()
                and (child / "client").is_dir()
            ):
                candidates.append(child)

    except OSError:
        return None

    return candidates[0] if len(candidates) == 1 else None


def interval_timestamp(
    interval_dir: Path,
    max_scan_bytes: int,
) -> tuple[Optional[datetime], str]:
    candidates = [
        "metrics.json",
        "allocations.json",
        "evaluations.json",
        "deployments.json",
        "jobs.json",
        "nodes.json",
        "operator-scheduler.json",
    ]

    for name in candidates:
        path = interval_dir / name
        if not path.is_file():
            continue

        dt = first_timestamp_from_file(path, max_scan_bytes)
        if dt is not None:
            return dt, name

    try:
        for path in sorted(interval_dir.iterdir()):
            if not path.is_file() or path.suffix.lower() not in TEXT_EXTENSIONS:
                continue

            dt = first_timestamp_from_file(path, max_scan_bytes)
            if dt is not None:
                return dt, path.name

    except OSError:
        pass

    return None, ""


def iso(dt: Optional[datetime]) -> str:
    if dt is None:
        return ""
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def window_slug(start: datetime, end: datetime) -> str:
    return (
        start.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "_"
        + end.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    )


def copy_file_with_manifest(
    source: Path,
    destination: Path,
    relative_path: str,
    action: str,
    note: str,
) -> ManifestRow:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)

    return ManifestRow(
        action=action,
        relative_path=relative_path,
        source_size_bytes=source.stat().st_size,
        output_size_bytes=destination.stat().st_size,
        source_sha256=sha256_file(source),
        output_sha256=sha256_file(destination),
        matched_lines=0,
        detected_first_timestamp="",
        detected_last_timestamp="",
        note=note,
    )


def extract_timestamped_lines(
    source: Path,
    destination: Path,
    relative_path: str,
    start: datetime,
    end: datetime,
) -> Optional[ManifestRow]:
    destination.parent.mkdir(parents=True, exist_ok=True)

    matched_lines = 0
    first_seen = None
    last_seen = None

    try:
        with source.open("r", encoding="utf-8", errors="replace") as src, \
             destination.open("w", encoding="utf-8") as dst:

            for line in src:
                timestamps = list(timestamps_in_text(line))
                if not timestamps:
                    continue

                in_window = [dt for dt in timestamps if start <= dt <= end]
                if not in_window:
                    continue

                dst.write(line)
                matched_lines += 1

                line_first = min(in_window)
                line_last = max(in_window)

                if first_seen is None or line_first < first_seen:
                    first_seen = line_first

                if last_seen is None or line_last > last_seen:
                    last_seen = line_last

    except (OSError, UnicodeError):
        try:
            destination.unlink(missing_ok=True)
        except OSError:
            pass
        return None

    if matched_lines == 0:
        try:
            destination.unlink(missing_ok=True)
        except OSError:
            pass
        return None

    return ManifestRow(
        action="filtered_lines",
        relative_path=relative_path,
        source_size_bytes=source.stat().st_size,
        output_size_bytes=destination.stat().st_size,
        source_sha256=sha256_file(source),
        output_sha256=sha256_file(destination),
        matched_lines=matched_lines,
        detected_first_timestamp=iso(first_seen),
        detected_last_timestamp=iso(last_seen),
        note="complete source lines with timestamps inside requested window",
    )


def write_manifest_csv(rows: list[ManifestRow], path: Path) -> None:
    fields = [
        "action",
        "relative_path",
        "source_size_bytes",
        "output_size_bytes",
        "source_sha256",
        "output_sha256",
        "matched_lines",
        "detected_first_timestamp",
        "detected_last_timestamp",
        "note",
    ]

    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))


def md_escape(value: object) -> str:
    return str(value).replace("|", r"\|").replace("\n", " ")


def write_summary_md(
    path: Path,
    root: Path,
    bundle_root: Optional[Path],
    start: datetime,
    end: datetime,
    selected_intervals: list[tuple[str, datetime, str]],
    unparsed_intervals: list[str],
    rows: list[ManifestRow],
) -> None:
    action_counts = Counter(row.action for row in rows)
    source_bytes = sum(row.source_size_bytes for row in rows)
    output_bytes = sum(row.output_size_bytes for row in rows)

    with path.open("w", encoding="utf-8") as fh:
        fh.write("# Extracted Incident Window\n\n")
        fh.write(f"- Search root: `{root}`\n")
        fh.write(f"- Nomad bundle root: `{bundle_root or 'not detected'}`\n")
        fh.write(f"- Requested start (UTC): **{iso(start)}**\n")
        fh.write(f"- Requested end (UTC): **{iso(end)}**\n")
        fh.write(f"- Selected interval captures: **{len(selected_intervals)}**\n")
        fh.write(f"- Unparsed interval captures: **{len(unparsed_intervals)}**\n")
        fh.write(f"- Manifest rows: **{len(rows)}**\n")
        fh.write(f"- Source bytes represented: **{human_size(source_bytes)}**\n")
        fh.write(f"- Derived output size: **{human_size(output_bytes)}**\n\n")

        fh.write("## Selected Nomad Intervals\n\n")

        if selected_intervals:
            fh.write("| Interval | Capture Timestamp (UTC) | Timestamp Source |\n")
            fh.write("|---|---|---|\n")

            for interval_id, dt, source_name in selected_intervals:
                fh.write(
                    f"| `{interval_id}` | {iso(dt)} | `{md_escape(source_name)}` |\n"
                )
        else:
            fh.write("No regular interval snapshots fell inside the requested window.\n")

        if unparsed_intervals:
            fh.write("\n### Intervals Without Detectable Wall-Clock Timestamp\n\n")
            for interval_id in unparsed_intervals:
                fh.write(f"- `{interval_id}`\n")

        fh.write("\n## Derived File Actions\n\n")
        fh.write("| Action | Files |\n|---|---:|\n")
        for action, count in action_counts.most_common():
            fh.write(f"| {md_escape(action)} | {count:,} |\n")

        fh.write("\n## Extracted Files\n\n")
        fh.write("| Action | Output Size | Matching Lines | Path | Note |\n")
        fh.write("|---|---:|---:|---|---|\n")

        for row in sorted(rows, key=lambda r: (r.action, r.relative_path)):
            fh.write(
                f"| {md_escape(row.action)} | {human_size(row.output_size_bytes)} | "
                f"{row.matched_lines:,} | `{md_escape(row.relative_path)}` | "
                f"{md_escape(row.note)} |\n"
            )


def write_summary_json(
    path: Path,
    root: Path,
    bundle_root: Optional[Path],
    start: datetime,
    end: datetime,
    selected_intervals: list[tuple[str, datetime, str]],
    unparsed_intervals: list[str],
    rows: list[ManifestRow],
) -> None:
    data = {
        "search_root": str(root),
        "bundle_root": str(bundle_root) if bundle_root else None,
        "requested_window": {
            "start_utc": iso(start),
            "end_utc": iso(end),
        },
        "selected_intervals": [
            {
                "interval_id": interval_id,
                "capture_timestamp_utc": iso(dt),
                "timestamp_source": source_name,
            }
            for interval_id, dt, source_name in selected_intervals
        ],
        "unparsed_intervals": unparsed_intervals,
        "actions": dict(Counter(row.action for row in rows)),
        "files": [asdict(row) for row in rows],
    }

    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Extract a reduced incident-time view from a Nomad operator debug "
            "bundle or related artifact directory."
        )
    )

    parser.add_argument(
        "bundle",
        type=Path,
        help="Path to unpacked Nomad debug bundle or parent directory.",
    )

    parser.add_argument(
        "--start",
        required=True,
        help="Incident window start in ISO 8601.",
    )

    parser.add_argument(
        "--end",
        required=True,
        help="Incident window end in ISO 8601.",
    )

    parser.add_argument(
        "--assume-tz",
        default=None,
        help=(
            "IANA timezone for naive --start/--end values, e.g. "
            "America/Chicago or America/Los_Angeles."
        ),
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help=(
            "Base output directory. Default: <bundle-parent>/analysis_extract_window. "
            "A per-window subdirectory is always created."
        ),
    )

    parser.add_argument(
        "--include-static",
        action="store_true",
        help=(
            "Copy one-time cluster metadata and agent-host.json files. "
            "These are not time-filtered."
        ),
    )

    parser.add_argument(
        "--include-profiles",
        action="store_true",
        help=(
            "Copy server/client profile files whose numeric capture index "
            "matches a selected interval ID."
        ),
    )

    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace an existing derived run for the same time window.",
    )

    parser.add_argument(
        "--max-scan-mb",
        type=int,
        default=DEFAULT_SCAN_MB,
        help=(
            f"Maximum bytes inspected while detecting timestamps in each "
            f"snapshot file. Default: {DEFAULT_SCAN_MB} MB."
        ),
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

    if args.max_scan_mb <= 0:
        print("ERROR: --max-scan-mb must be greater than zero.", file=sys.stderr)
        return 2

    assume_tz = None

    if args.assume_tz:
        try:
            assume_tz = ZoneInfo(args.assume_tz)
        except ZoneInfoNotFoundError:
            print(f"ERROR: unknown timezone: {args.assume_tz}", file=sys.stderr)
            return 2

    try:
        start = parse_user_datetime(args.start, assume_tz)
        end = parse_user_datetime(args.end, assume_tz)

    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if end < start:
        print("ERROR: --end must be greater than or equal to --start.", file=sys.stderr)
        return 2

    base_output_dir = (
        args.output.expanduser().resolve()
        if args.output
        else (root.parent / "analysis_extract_window").resolve()
    )

    run_dir = base_output_dir / window_slug(start, end)

    if run_dir.exists():
        if not args.overwrite:
            print(
                f"ERROR: derived run already exists: {run_dir}\n"
                "Use --overwrite to replace this derived run.",
                file=sys.stderr,
            )
            return 2

        shutil.rmtree(run_dir)

    extracted_root = run_dir / "extracted"
    extracted_root.mkdir(parents=True, exist_ok=True)

    bundle_root = find_bundle_root(root)
    max_scan_bytes = args.max_scan_mb * 1024 * 1024

    print(f"Search root      : {root}")
    print(f"Start (UTC)      : {iso(start)}")
    print(f"End (UTC)        : {iso(end)}")
    print(f"Bundle detected  : {'yes' if bundle_root else 'no'}")
    print(f"Output directory : {run_dir}")
    print("Source artifacts are opened read-only.")
    print()

    rows: list[ManifestRow] = []
    selected_intervals: list[tuple[str, datetime, str]] = []
    unparsed_intervals: list[str] = []
    handled: set[Path] = set()

    if bundle_root:
        interval_root = bundle_root / "interval"

        interval_dirs = sorted(
            p for p in interval_root.iterdir()
            if p.is_dir() and p.name.isdigit()
        )

        print(f"Inspecting {len(interval_dirs)} regular interval capture(s)...")

        for interval_dir in interval_dirs:
            dt, timestamp_source = interval_timestamp(interval_dir, max_scan_bytes)

            if dt is None:
                unparsed_intervals.append(interval_dir.name)
                continue

            if not (start <= dt <= end):
                continue

            selected_intervals.append((interval_dir.name, dt, timestamp_source))

            for source in sorted(interval_dir.rglob("*")):
                if not source.is_file() or source.is_symlink():
                    continue

                rel = source.relative_to(root)
                dest = extracted_root / rel

                rows.append(
                    copy_file_with_manifest(
                        source=source,
                        destination=dest,
                        relative_path=str(rel),
                        action="copied_interval_snapshot",
                        note=f"interval {interval_dir.name} capture at {iso(dt)}",
                    )
                )

                handled.add(source.resolve())

        print(
            f"Selected intervals : {len(selected_intervals)}"
            + (
                f" ({selected_intervals[0][0]}-{selected_intervals[-1][0]})"
                if selected_intervals
                else ""
            )
        )

        if unparsed_intervals:
            print(f"Unparsed intervals : {len(unparsed_intervals)}")

        if args.include_static:
            static_sources = []

            cluster_dir = bundle_root / "cluster"

            if cluster_dir.is_dir():
                static_sources.extend(
                    p for p in cluster_dir.rglob("*")
                    if p.is_file() and not p.is_symlink()
                )

            for entity_root_name in ("server", "client"):
                entity_root = bundle_root / entity_root_name

                if not entity_root.is_dir():
                    continue

                for agent_host in entity_root.glob("*/agent-host.json"):
                    if agent_host.is_file():
                        static_sources.append(agent_host)

            index_json = bundle_root / "index.json"

            if index_json.is_file():
                static_sources.append(index_json)

            for source in sorted(set(static_sources)):
                rel = source.relative_to(root)
                dest = extracted_root / rel

                rows.append(
                    copy_file_with_manifest(
                        source=source,
                        destination=dest,
                        relative_path=str(rel),
                        action="copied_static",
                        note="static bundle metadata; not time-filtered",
                    )
                )

                handled.add(source.resolve())

        if args.include_profiles and selected_intervals:
            selected_ids = {
                interval_id
                for interval_id, _, _ in selected_intervals
            }

            for entity_root_name in ("server", "client"):
                entity_root = bundle_root / entity_root_name

                if not entity_root.is_dir():
                    continue

                for source in entity_root.glob("*/*"):
                    if not source.is_file() or source.is_symlink():
                        continue

                    m = PROFILE_RE.match(source.name)

                    if not m or m.group(1) not in selected_ids:
                        continue

                    rel = source.relative_to(root)
                    dest = extracted_root / rel

                    rows.append(
                        copy_file_with_manifest(
                            source=source,
                            destination=dest,
                            relative_path=str(rel),
                            action="copied_profile",
                            note=(
                                f"profile capture index {m.group(1)} matched "
                                "selected regular interval index"
                            ),
                        )
                    )

                    handled.add(source.resolve())

    searchable = []

    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        run_dir_resolved = run_dir.resolve()

        dirnames[:] = [
            d for d in dirnames
            if (current / d).resolve() != run_dir_resolved
        ]

        for filename in filenames:
            source = current / filename

            try:
                if not source.is_file() or source.is_symlink():
                    continue

                if source.resolve() in handled:
                    continue

                if source.suffix.lower() not in TEXT_EXTENSIONS:
                    continue

                if PROFILE_TEXT_RE.match(source.name):
                    continue

                lower_name = source.name.lower()

                # Avoid generically filtering large/minified snapshot JSON.
                # eventstream.json is retained because it can be line-oriented.
                if source.suffix.lower() == ".json" and lower_name != "eventstream.json":
                    continue

                searchable.append(source)

            except OSError:
                continue

    searchable.sort()

    print(f"Scanning {len(searchable):,} line-oriented text file(s) for window matches...")

    for index, source in enumerate(searchable, start=1):
        if (
            index == 1
            or index % DEFAULT_PROGRESS_EVERY == 0
            or index == len(searchable)
        ):
            print(f"  [{index:,}/{len(searchable):,}] {source.relative_to(root)}")

        rel = source.relative_to(root)
        dest = extracted_root / rel

        row = extract_timestamped_lines(
            source=source,
            destination=dest,
            relative_path=str(rel),
            start=start,
            end=end,
        )

        if row is not None:
            rows.append(row)

    rows.sort(key=lambda r: (r.action, r.relative_path))

    manifest_path = run_dir / "manifest.csv"
    summary_md_path = run_dir / "summary.md"
    summary_json_path = run_dir / "summary.json"

    write_manifest_csv(rows, manifest_path)

    write_summary_md(
        path=summary_md_path,
        root=root,
        bundle_root=bundle_root,
        start=start,
        end=end,
        selected_intervals=selected_intervals,
        unparsed_intervals=unparsed_intervals,
        rows=rows,
    )

    write_summary_json(
        path=summary_json_path,
        root=root,
        bundle_root=bundle_root,
        start=start,
        end=end,
        selected_intervals=selected_intervals,
        unparsed_intervals=unparsed_intervals,
        rows=rows,
    )

    action_counts = Counter(row.action for row in rows)

    print()
    print("Done.")
    print(f"  Selected intervals : {len(selected_intervals)}")
    print(f"  Derived files      : {len(rows)}")

    for action, count in action_counts.most_common():
        print(f"    {action:<26} {count}")

    print()
    print(f"Extracted tree : {extracted_root}")
    print(f"Manifest       : {manifest_path}")
    print(f"Markdown       : {summary_md_path}")
    print(f"Summary JSON   : {summary_json_path}")
    print()
    print("Tip: inspect summary.md first; manifest.csv preserves file-level provenance.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
