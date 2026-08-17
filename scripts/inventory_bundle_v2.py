#!/usr/bin/env python3
"""
inventory_bundle.py

Read-only inventory tool for Nomad operator debug bundles and related customer
artifacts.

Version 2 adds native awareness of the standard `nomad operator debug` layout:
- Detects a Nomad operator debug bundle root.
- Summarizes cluster/, interval/, server/, and client/ sections.
- Counts regular interval captures and detects numeric gaps.
- Counts pprof/profiling capture indexes separately for servers and clients.
- Reports repeated artifact names present in interval captures.
- Detects eventstream.json and common cluster snapshot artifacts.
- Preserves the generic file inventory from v1.

Safety goals:
- Never modify source artifacts.
- Never print unbounded file contents.
- Python standard library only.
- Bounded text scanning.
- All generated output goes to a separate analysis directory.

Examples:
    python3 inventory_bundle.py ./nomad-debug-2026-08-14-171817Z
    python3 inventory_bundle.py ./nomad-debug-test
    python3 inventory_bundle.py ./bundle --output ./case-analysis/inventory
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

DEFAULT_MAX_SCAN_MB = 50
DEFAULT_SAMPLE_LINES = 250_000
DEFAULT_TOP_LARGEST = 25

TEXT_EXTENSIONS = {
    ".log", ".txt", ".json", ".jsonl", ".ndjson", ".csv", ".tsv", ".hcl",
    ".nomad", ".md", ".yaml", ".yml", ".conf", ".cfg", ".out", ".err",
}

ARCHIVE_EXTENSIONS = {
    ".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z", ".rar", ".zst",
}

ROLE_PATTERNS = [
    ("nomad_server_log", re.compile(r"(nomad.*server|server.*nomad|servers?\.log|/server/|monitor\.log)", re.I)),
    ("nomad_client_log", re.compile(r"(nomad.*client|client.*nomad|syslog.*nomad|/client/|monitor\.log)", re.I)),
    ("event_stream", re.compile(r"(event[-_ ]?stream|task[-_ ]?events?|node[-_ ]?events?|plan[-_ ]?events?|eval(?:uation)?[-_ ]?events?)", re.I)),
    ("evaluation", re.compile(r"(^|[/_.-])eval(?:uation)?s?([/_.-]|$)", re.I)),
    ("allocation", re.compile(r"(^|[/_.-])alloc(?:ation)?s?([/_.-]|$)", re.I)),
    ("node", re.compile(r"(^|[/_.-])nodes?([/_.-]|$)", re.I)),
    ("job", re.compile(r"(^|[/_.-])jobs?([/_.-]|$)", re.I)),
    ("deployment", re.compile(r"(^|[/_.-])deploy(?:ment)?s?([/_.-]|$)", re.I)),
    ("raft", re.compile(r"raft", re.I)),
    ("metrics", re.compile(r"(metrics?|prometheus|telemetry|pprof|profile|heap|goroutine|trace|threadcreate)", re.I)),
    ("consul", re.compile(r"consul", re.I)),
    ("vault", re.compile(r"vault", re.I)),
    ("aws", re.compile(r"(cloudtrail|autoscal|asg|ec2)", re.I)),
]

TIMESTAMP_PATTERNS = [
    re.compile(r"\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\b"),
    re.compile(r"\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{2}:\d{2})\b"),
    re.compile(r"\b(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\b"),
]

PROFILE_INDEX_RE = re.compile(
    r"^(?:goroutine|goroutine-debug1|goroutine-debug2|heap|profile|threadcreate|trace)_(\d{4})\.(?:prof|txt)$"
)


@dataclass
class FileRecord:
    relative_path: str
    size_bytes: int
    size_human: str
    extension: str
    kind: str
    likely_role: str
    sha256: str
    line_count: Optional[int]
    first_timestamp: Optional[str]
    last_timestamp: Optional[str]
    scan_status: str


@dataclass
class BundleSummary:
    detected: bool
    bundle_root: Optional[str]
    interval_ids: list[str]
    missing_interval_ids: list[str]
    interval_artifacts: list[str]
    interval_artifact_presence: dict[str, int]
    servers: list[str]
    clients: list[str]
    server_profile_ids: dict[str, list[str]]
    client_profile_ids: dict[str, list[str]]
    cluster_artifacts: list[str]
    eventstream_present: bool
    index_json_entries: Optional[int]


def human_size(num_bytes: int) -> str:
    value = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024.0 or unit == "TB":
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{num_bytes} B"


def classify_kind(path: Path) -> str:
    name = path.name.lower()
    if name.endswith(".tar.gz") or name.endswith(".tar.bz2") or name.endswith(".tar.xz"):
        return "archive"
    if path.suffix.lower() in ARCHIVE_EXTENSIONS:
        return "archive"
    if path.suffix.lower() in TEXT_EXTENSIONS:
        return "text"
    if path.suffix == "" and any(token in name for token in ("log", "messages", "syslog", "events")):
        return "text"
    return "binary_or_unknown"


def detect_role(relative_path: str) -> str:
    matches = [role for role, pattern in ROLE_PATTERNS if pattern.search(relative_path)]
    return ",".join(matches) if matches else "unknown"


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def parse_timestamp(text: str) -> Optional[datetime]:
    try:
        if text.endswith("Z"):
            return datetime.fromisoformat(text[:-1] + "+00:00")
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def timestamps_in_line(line: str) -> Iterable[str]:
    for pattern in TIMESTAMP_PATTERNS:
        for match in pattern.finditer(line):
            yield match.group(1)


def scan_text_file(path: Path, max_scan_bytes: int, max_lines: int):
    file_size = path.stat().st_size
    byte_limit = min(file_size, max_scan_bytes)
    bounded = file_size > max_scan_bytes

    bytes_read = 0
    lines_seen = 0
    first_ts_raw = None
    first_ts_dt = None
    last_ts_raw = None
    last_ts_dt = None
    hit_line_limit = False

    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                bytes_read += len(line.encode("utf-8", errors="replace"))
                lines_seen += 1

                for raw_ts in timestamps_in_line(line):
                    dt = parse_timestamp(raw_ts)
                    if dt is None:
                        continue
                    if first_ts_dt is None or dt < first_ts_dt:
                        first_ts_dt = dt
                        first_ts_raw = raw_ts
                    if last_ts_dt is None or dt > last_ts_dt:
                        last_ts_dt = dt
                        last_ts_raw = raw_ts

                if lines_seen >= max_lines:
                    hit_line_limit = True
                    break
                if bytes_read >= byte_limit:
                    break
    except (OSError, UnicodeError) as exc:
        return None, None, None, f"scan_error:{type(exc).__name__}"

    complete = not bounded and not hit_line_limit and bytes_read >= file_size
    if complete:
        return lines_seen, first_ts_raw, last_ts_raw, "full_scan"

    reasons = []
    if bounded:
        reasons.append(f"byte_limit={human_size(max_scan_bytes)}")
    if hit_line_limit:
        reasons.append(f"line_limit={max_lines}")
    return None, first_ts_raw, last_ts_raw, "partial_scan:" + ",".join(reasons or ["bounded"])


def inventory_file(path: Path, root: Path, max_scan_bytes: int, max_lines: int) -> FileRecord:
    rel = str(path.relative_to(root))
    size = path.stat().st_size
    kind = classify_kind(path)
    role = detect_role("/" + rel)

    try:
        digest = sha256_file(path)
    except OSError:
        digest = "ERROR"

    line_count = None
    first_ts = None
    last_ts = None
    scan_status = "not_scanned"

    if kind == "text":
        line_count, first_ts, last_ts, scan_status = scan_text_file(
            path, max_scan_bytes, max_lines
        )

    return FileRecord(
        relative_path=rel,
        size_bytes=size,
        size_human=human_size(size),
        extension=path.suffix.lower() or "(none)",
        kind=kind,
        likely_role=role,
        sha256=digest,
        line_count=line_count,
        first_timestamp=first_ts,
        last_timestamp=last_ts,
        scan_status=scan_status,
    )


def numeric_gaps(ids: list[str]) -> list[str]:
    nums = sorted(int(x) for x in ids if x.isdigit())
    if not nums:
        return []
    width = max(len(x) for x in ids)
    present = set(nums)
    return [f"{n:0{width}d}" for n in range(nums[0], nums[-1] + 1) if n not in present]


def find_bundle_root(root: Path) -> Optional[Path]:
    """
    Accept either:
      ./nomad-debug-2026-...
    or a parent containing exactly one nomad-debug-* directory.
    """
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

    if len(candidates) == 1:
        return candidates[0]
    return None


def collect_profile_ids(entity_dir: Path) -> list[str]:
    ids = set()
    try:
        for path in entity_dir.iterdir():
            if not path.is_file():
                continue
            m = PROFILE_INDEX_RE.match(path.name)
            if m:
                ids.add(m.group(1))
    except OSError:
        pass
    return sorted(ids)


def inspect_nomad_bundle(root: Path) -> BundleSummary:
    bundle_root = find_bundle_root(root)
    if bundle_root is None:
        return BundleSummary(
            detected=False,
            bundle_root=None,
            interval_ids=[],
            missing_interval_ids=[],
            interval_artifacts=[],
            interval_artifact_presence={},
            servers=[],
            clients=[],
            server_profile_ids={},
            client_profile_ids={},
            cluster_artifacts=[],
            eventstream_present=False,
            index_json_entries=None,
        )

    interval_dir = bundle_root / "interval"
    interval_ids = sorted(
        p.name for p in interval_dir.iterdir()
        if p.is_dir() and p.name.isdigit()
    )
    missing_interval_ids = numeric_gaps(interval_ids)

    presence = Counter()
    all_interval_artifacts = set()
    for interval_id in interval_ids:
        idir = interval_dir / interval_id
        try:
            names = {
                p.name for p in idir.iterdir()
                if p.is_file()
            }
        except OSError:
            names = set()
        all_interval_artifacts.update(names)
        presence.update(names)

    server_root = bundle_root / "server"
    client_root = bundle_root / "client"

    servers = sorted(p.name for p in server_root.iterdir() if p.is_dir())
    clients = sorted(p.name for p in client_root.iterdir() if p.is_dir())

    server_profile_ids = {
        name: collect_profile_ids(server_root / name) for name in servers
    }
    client_profile_ids = {
        name: collect_profile_ids(client_root / name) for name in clients
    }

    cluster_dir = bundle_root / "cluster"
    cluster_artifacts = sorted(
        p.name for p in cluster_dir.iterdir() if p.is_file()
    )
    eventstream_present = "eventstream.json" in cluster_artifacts

    index_json_entries = None
    index_path = bundle_root / "index.json"
    if index_path.is_file():
        try:
            with index_path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, list):
                index_json_entries = len(data)
            elif isinstance(data, dict):
                index_json_entries = len(data)
        except (OSError, json.JSONDecodeError):
            pass

    return BundleSummary(
        detected=True,
        bundle_root=str(bundle_root),
        interval_ids=interval_ids,
        missing_interval_ids=missing_interval_ids,
        interval_artifacts=sorted(all_interval_artifacts),
        interval_artifact_presence=dict(sorted(presence.items())),
        servers=servers,
        clients=clients,
        server_profile_ids=server_profile_ids,
        client_profile_ids=client_profile_ids,
        cluster_artifacts=cluster_artifacts,
        eventstream_present=eventstream_present,
        index_json_entries=index_json_entries,
    )


def write_csv(records, output_path: Path):
    fieldnames = [
        "relative_path", "size_bytes", "size_human", "extension", "kind",
        "likely_role", "sha256", "line_count", "first_timestamp",
        "last_timestamp", "scan_status",
    ]
    with output_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for record in records:
            writer.writerow(asdict(record))


def md_escape(value):
    if value is None:
        return ""
    return str(value).replace("|", r"\|").replace("\n", " ")


def summarize_profile_capture(ids: list[str]) -> str:
    if not ids:
        return "none detected"
    gaps = numeric_gaps(ids)
    summary = f"{len(ids)} capture indexes ({ids[0]}–{ids[-1]})"
    if gaps:
        summary += f"; missing: {', '.join(gaps)}"
    else:
        summary += "; no numeric gaps"
    return summary


def write_markdown(
    records,
    output_path: Path,
    root: Path,
    top_largest: int,
    bundle: BundleSummary,
):
    total_bytes = sum(r.size_bytes for r in records)
    kind_counts = Counter(r.kind for r in records)
    role_counts = Counter()

    for r in records:
        for role in r.likely_role.split(","):
            if role and role != "unknown":
                role_counts[role] += 1

    text_files = [r for r in records if r.kind == "text"]
    with_timestamps = [r for r in records if r.first_timestamp or r.last_timestamp]
    largest = sorted(records, key=lambda r: r.size_bytes, reverse=True)[:top_largest]

    with output_path.open("w", encoding="utf-8") as fh:
        fh.write("# Nomad Bundle Inventory\n\n")
        fh.write(f"- Inventory root: `{root}`\n")
        fh.write(f"- Files: **{len(records):,}**\n")
        fh.write(f"- Total size: **{human_size(total_bytes)}**\n")
        fh.write(f"- Text-like files: **{len(text_files):,}**\n")
        fh.write(f"- Files with detected timestamps: **{len(with_timestamps):,}**\n\n")

        if bundle.detected:
            fh.write("## Nomad Operator Debug Summary\n\n")
            fh.write(f"- Bundle detected: **yes**\n")
            fh.write(f"- Bundle root: `{bundle.bundle_root}`\n")
            fh.write(f"- Servers represented: **{len(bundle.servers)}**\n")
            fh.write(f"- Clients represented: **{len(bundle.clients)}**\n")
            fh.write(f"- Regular interval captures: **{len(bundle.interval_ids)}**\n")

            if bundle.interval_ids:
                fh.write(
                    f"- Interval IDs: **{bundle.interval_ids[0]}–{bundle.interval_ids[-1]}**\n"
                )

            if bundle.missing_interval_ids:
                fh.write(
                    f"- Missing interval IDs: **{', '.join(bundle.missing_interval_ids)}**\n"
                )
            else:
                fh.write("- Missing interval IDs: **none detected**\n")

            fh.write(
                f"- Cluster event stream present: **{'yes' if bundle.eventstream_present else 'no'}**\n"
            )

            if bundle.index_json_entries is not None:
                fh.write(f"- `index.json` entries: **{bundle.index_json_entries:,}**\n")

            fh.write("\n### Cluster Artifacts\n\n")
            for name in bundle.cluster_artifacts:
                fh.write(f"- `{name}`\n")

            fh.write("\n### Interval Artifacts\n\n")
            fh.write("| Artifact | Present In | Total Intervals |\n|---|---:|---:|\n")
            total_intervals = len(bundle.interval_ids)
            for name in bundle.interval_artifacts:
                count = bundle.interval_artifact_presence.get(name, 0)
                fh.write(f"| `{md_escape(name)}` | {count} | {total_intervals} |\n")

            fh.write("\n### Server Profiling Captures\n\n")
            if bundle.servers:
                for server in bundle.servers:
                    fh.write(
                        f"- `{server}`: {summarize_profile_capture(bundle.server_profile_ids.get(server, []))}\n"
                    )
            else:
                fh.write("- none detected\n")

            fh.write("\n### Client Profiling Captures\n\n")
            if bundle.clients:
                for client in bundle.clients:
                    fh.write(
                        f"- `{client}`: {summarize_profile_capture(bundle.client_profile_ids.get(client, []))}\n"
                    )
            else:
                fh.write("- none detected\n")

            fh.write("\n")
        else:
            fh.write("## Nomad Operator Debug Summary\n\n")
            fh.write("Standard Nomad operator debug directory layout was **not detected**.\n\n")

        fh.write("## File Kinds\n\n")
        fh.write("| Kind | Count |\n|---|---:|\n")
        for kind, count in kind_counts.most_common():
            fh.write(f"| {md_escape(kind)} | {count:,} |\n")

        fh.write("\n## Likely Roles\n\n")
        fh.write("| Role | Matching Files |\n|---|---:|\n")
        if role_counts:
            for role, count in role_counts.most_common():
                fh.write(f"| {md_escape(role)} | {count:,} |\n")
        else:
            fh.write("| No recognized roles | 0 |\n")

        fh.write("\n## Largest Files\n\n")
        fh.write("| Size | Kind | Role | Path |\n|---:|---|---|---|\n")
        for r in largest:
            fh.write(
                f"| {r.size_human} | {md_escape(r.kind)} | "
                f"{md_escape(r.likely_role)} | `{md_escape(r.relative_path)}` |\n"
            )

        fh.write("\n## Timestamp Coverage\n\n")
        fh.write("| First Timestamp | Last Timestamp | Scan | Path |\n|---|---|---|---|\n")
        for r in sorted(with_timestamps, key=lambda x: x.relative_path):
            fh.write(
                f"| {md_escape(r.first_timestamp)} | {md_escape(r.last_timestamp)} | "
                f"{md_escape(r.scan_status)} | `{md_escape(r.relative_path)}` |\n"
            )

        fh.write("\n## Full Inventory\n\n")
        fh.write("| Size | Kind | Role | Lines | Scan | Path |\n|---:|---|---|---:|---|---|\n")
        for r in sorted(records, key=lambda x: x.relative_path):
            line_value = f"{r.line_count:,}" if r.line_count is not None else ""
            fh.write(
                f"| {r.size_human} | {md_escape(r.kind)} | "
                f"{md_escape(r.likely_role)} | {line_value} | "
                f"{md_escape(r.scan_status)} | `{md_escape(r.relative_path)}` |\n"
            )


def write_bundle_json(bundle: BundleSummary, output_path: Path):
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(asdict(bundle), fh, indent=2)
        fh.write("\n")


def iter_files(root: Path, output_dir: Path):
    output_dir_resolved = output_dir.resolve()
    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        dirnames[:] = [
            d for d in dirnames if (current / d).resolve() != output_dir_resolved
        ]
        for filename in filenames:
            path = current / filename
            try:
                if path.is_file() and not path.is_symlink():
                    yield path
            except OSError:
                continue


def parse_args():
    parser = argparse.ArgumentParser(
        description="Create a bounded, read-only inventory of a Nomad debug bundle."
    )
    parser.add_argument(
        "bundle",
        type=Path,
        help="Path to an unpacked Nomad operator debug bundle or artifact directory.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Analysis output directory. Default: <bundle-parent>/analysis_inventory",
    )
    parser.add_argument(
        "--max-scan-mb",
        type=int,
        default=DEFAULT_MAX_SCAN_MB,
        help=f"Maximum bytes to inspect per text file. Default: {DEFAULT_MAX_SCAN_MB} MB.",
    )
    parser.add_argument(
        "--max-lines",
        type=int,
        default=DEFAULT_SAMPLE_LINES,
        help=f"Maximum lines to inspect per text file. Default: {DEFAULT_SAMPLE_LINES:,}.",
    )
    parser.add_argument(
        "--top-largest",
        type=int,
        default=DEFAULT_TOP_LARGEST,
        help=f"Number of largest files shown in Markdown summary. Default: {DEFAULT_TOP_LARGEST}.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    root = args.bundle.expanduser().resolve()

    if not root.exists():
        print(f"ERROR: bundle path does not exist: {root}", file=sys.stderr)
        return 2
    if not root.is_dir():
        print(f"ERROR: bundle path is not a directory: {root}", file=sys.stderr)
        return 2
    if args.max_scan_mb <= 0 or args.max_lines <= 0 or args.top_largest <= 0:
        print("ERROR: scan limits must be greater than zero.", file=sys.stderr)
        return 2

    output_dir = (
        args.output.expanduser().resolve()
        if args.output
        else (root.parent / "analysis_inventory").resolve()
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    bundle = inspect_nomad_bundle(root)

    if bundle.detected:
        print(f"Nomad operator debug bundle detected: {bundle.bundle_root}")
        print(f"  regular intervals : {len(bundle.interval_ids)}")
        if bundle.interval_ids:
            print(f"  interval range     : {bundle.interval_ids[0]}-{bundle.interval_ids[-1]}")
        print(f"  missing intervals  : {', '.join(bundle.missing_interval_ids) if bundle.missing_interval_ids else 'none'}")
        print(f"  servers            : {len(bundle.servers)}")
        print(f"  clients            : {len(bundle.clients)}")
        print(f"  eventstream.json   : {'yes' if bundle.eventstream_present else 'no'}")
        print()

    files = sorted(iter_files(root, output_dir))
    print(f"Inventorying {len(files):,} files under: {root}")
    print(f"Output directory: {output_dir}")
    print("Source files are opened read-only; no source artifacts are modified.")

    records = []
    max_scan_bytes = args.max_scan_mb * 1024 * 1024

    for index, path in enumerate(files, start=1):
        if index == 1 or index % 100 == 0 or index == len(files):
            print(f"  [{index:,}/{len(files):,}] {path.relative_to(root)}")

        try:
            records.append(
                inventory_file(path, root, max_scan_bytes, args.max_lines)
            )
        except OSError as exc:
            rel = str(path.relative_to(root))
            records.append(
                FileRecord(
                    relative_path=rel,
                    size_bytes=0,
                    size_human="0 B",
                    extension=path.suffix.lower() or "(none)",
                    kind="error",
                    likely_role=detect_role("/" + rel),
                    sha256="ERROR",
                    line_count=None,
                    first_timestamp=None,
                    last_timestamp=None,
                    scan_status=f"inventory_error:{type(exc).__name__}",
                )
            )

    csv_path = output_dir / "inventory.csv"
    md_path = output_dir / "inventory.md"
    bundle_json_path = output_dir / "bundle_summary.json"

    write_csv(records, csv_path)
    write_markdown(records, md_path, root, args.top_largest, bundle)
    write_bundle_json(bundle, bundle_json_path)

    total_size = sum(r.size_bytes for r in records)
    print()
    print("Done.")
    print(f"  Files inventoried : {len(records):,}")
    print(f"  Total source size : {human_size(total_size)}")
    print(f"  CSV               : {csv_path}")
    print(f"  Markdown          : {md_path}")
    print(f"  Bundle summary    : {bundle_json_path}")
    print()
    print("Tip: inspect inventory.md first; later toolkit scripts can consume inventory.csv and bundle_summary.json.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
