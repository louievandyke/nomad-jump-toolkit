#!/usr/bin/env python3
"""
find_identifiers.py

Safely search an unpacked Nomad debug bundle (or related customer artifact
directory) for one or more exact identifiers without dumping unbounded output.

Version 2 improvements:
- Samples are centered around the actual match instead of the start of a line.
- Results are categorized by source type.
- High-value forensic sources are ranked ahead of repetitive telemetry.
- Repetitive interval metrics are summarized separately in Markdown.
- Still counts all occurrences and preserves source line numbers.

Typical uses:
- allocation ID
- node ID
- evaluation ID
- deployment ID
- job ID
- namespace
- hostname
- IP address

Safety / forensic goals:
- Read-only against source artifacts.
- Standard library only.
- Skip obvious binary/profile/archive files.
- Stream files line-by-line instead of loading them into memory.
- Count all matches while retaining only a bounded number of samples.
- Preserve source file and source line number.
- Truncate long sample lines.
- Write detailed results to CSV/Markdown; stdout stays compact.

Examples:
    python3 find_identifiers.py ./nomad-debug-test \
      --id ee943c77-0149-b085-fad0-de0f30f23c2c

    python3 find_identifiers.py ./bundle \
      --id 118bc946-848a-f3e2-13e3-feef08139f43 \
      --id 23bcf08b-079d-5aa6-6ac4-589699be9953

Output:
    analysis_find_identifiers/
      results.csv
      results.md
      summary.json
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, Optional

import _bundlelib as bl

TEXT_EXTENSIONS = {
    ".log", ".txt", ".json", ".jsonl", ".ndjson", ".csv", ".tsv",
    ".hcl", ".nomad", ".md", ".yaml", ".yml", ".conf", ".cfg",
    ".out", ".err",
}

SKIP_EXTENSIONS = {
    ".prof", ".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz",
    ".7z", ".rar", ".zst", ".png", ".jpg", ".jpeg", ".gif",
    ".pdf", ".db", ".sqlite", ".sqlite3",
}

DEFAULT_SAMPLES_PER_FILE = 3
DEFAULT_SAMPLE_WIDTH = 500
DEFAULT_PROGRESS_EVERY = 100


CATEGORY_PRIORITY = {
    "event_stream": 10,
    "allocation_snapshot": 20,
    "evaluation_snapshot": 30,
    "deployment_snapshot": 40,
    "job_snapshot": 50,
    "node_snapshot": 60,
    "scheduler_snapshot": 70,
    "monitor_log": 80,
    "server_log": 90,
    "client_log": 100,
    "metrics": 500,
    "other": 900,
}


@dataclass
class MatchSample:
    identifier: str
    relative_path: str
    category: str
    line_number: int
    occurrences_on_line: int
    sample: str


@dataclass
class FileMatch:
    identifier: str
    relative_path: str
    category: str
    match_count: int
    matching_lines: int
    first_match_line: Optional[int]
    last_match_line: Optional[int]


def is_probably_text(path: Path) -> bool:
    suffix = path.suffix.lower()

    if suffix in SKIP_EXTENSIONS:
        return False

    if suffix in TEXT_EXTENSIONS:
        return True

    name = path.name.lower()
    if suffix == "" and any(
        token in name
        for token in ("log", "messages", "syslog", "events", "output")
    ):
        return True

    return False


def categorize_path(relative_path: str) -> str:
    p = relative_path.replace("\\", "/").lower()
    name = Path(relative_path).name.lower()

    if name == "eventstream.json" or "event-stream" in name or "event_stream" in name:
        return "event_stream"
    if name == "allocations.json":
        return "allocation_snapshot"
    if name == "evaluations.json":
        return "evaluation_snapshot"
    if name == "deployments.json":
        return "deployment_snapshot"
    if name == "jobs.json":
        return "job_snapshot"
    if name == "nodes.json":
        return "node_snapshot"
    if name == "operator-scheduler.json":
        return "scheduler_snapshot"
    if name == "metrics.json" or "/metrics/" in p:
        return "metrics"
    if name == "monitor.log":
        return "monitor_log"
    if "/server/" in p and (name.endswith(".log") or name in {"messages", "syslog"}):
        return "server_log"
    if "/client/" in p and (name.endswith(".log") or name in {"messages", "syslog"}):
        return "client_log"
    return "other"


def iter_searchable_files(root: Path, output_dir: Path) -> Iterable[Path]:
    output_resolved = output_dir.resolve()

    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)

        dirnames[:] = [
            d for d in dirnames
            if (current / d).resolve() != output_resolved
        ]

        for filename in filenames:
            path = current / filename
            try:
                if not path.is_file() or path.is_symlink():
                    continue
                if is_probably_text(path):
                    yield path
            except OSError:
                continue


def sample_around_match(
    line: str,
    needle: str,
    ignore_case: bool,
    width: int,
) -> str:
    """
    Return a bounded excerpt centered around the first occurrence of needle.
    This is much more useful for minified JSON than truncating from column 1.
    """
    clean = line.rstrip("\r\n")
    haystack = clean.lower() if ignore_case else clean
    target = needle.lower() if ignore_case else needle
    pos = haystack.find(target)

    if pos < 0:
        if len(clean) <= width:
            return clean
        return clean[:width] + " …[truncated]"

    if len(clean) <= width:
        return clean

    # Keep the identifier visible and center context around it.
    half = max(1, (width - len(needle)) // 2)
    start = max(0, pos - half)
    end = min(len(clean), pos + len(needle) + half)

    # If we hit an edge, use any remaining budget on the other side.
    current_len = end - start
    if current_len < width:
        remaining = width - current_len
        if start == 0:
            end = min(len(clean), end + remaining)
        elif end == len(clean):
            start = max(0, start - remaining)

    excerpt = clean[start:end]

    prefix = "… " if start > 0 else ""
    suffix = " …[truncated]" if end < len(clean) else ""

    return prefix + excerpt + suffix


def search_file(
    path: Path,
    root: Path,
    identifiers: list[str],
    ignore_case: bool,
    samples_per_file: int,
    sample_width: int,
):
    relative_path = str(path.relative_to(root))
    category = categorize_path(relative_path)

    if ignore_case:
        needles = {identifier: identifier.lower() for identifier in identifiers}
    else:
        needles = {identifier: identifier for identifier in identifiers}

    counts = Counter()
    matching_lines = Counter()
    first_line = {}
    last_line = {}
    samples: dict[str, list[MatchSample]] = defaultdict(list)

    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line_number, line in enumerate(fh, start=1):
                haystack = line.lower() if ignore_case else line

                for original, needle in needles.items():
                    occurrences = haystack.count(needle)
                    if occurrences == 0:
                        continue

                    counts[original] += occurrences
                    matching_lines[original] += 1
                    first_line.setdefault(original, line_number)
                    last_line[original] = line_number

                    if len(samples[original]) < samples_per_file:
                        samples[original].append(
                            MatchSample(
                                identifier=original,
                                relative_path=relative_path,
                                category=category,
                                line_number=line_number,
                                occurrences_on_line=occurrences,
                                sample=sample_around_match(
                                    line=line,
                                    needle=original,
                                    ignore_case=ignore_case,
                                    width=sample_width,
                                ),
                            )
                        )

    except (OSError, UnicodeError) as exc:
        return [], [], f"{relative_path}: {type(exc).__name__}"

    file_matches = []
    flat_samples = []

    for identifier in identifiers:
        if counts[identifier] == 0:
            continue

        file_matches.append(
            FileMatch(
                identifier=identifier,
                relative_path=relative_path,
                category=category,
                match_count=counts[identifier],
                matching_lines=matching_lines[identifier],
                first_match_line=first_line.get(identifier),
                last_match_line=last_line.get(identifier),
            )
        )
        flat_samples.extend(samples[identifier])

    return file_matches, flat_samples, None


def write_results_csv(matches: list[FileMatch], path: Path) -> None:
    fieldnames = [
        "identifier",
        "relative_path",
        "category",
        "match_count",
        "matching_lines",
        "first_match_line",
        "last_match_line",
    ]

    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for item in matches:
            writer.writerow(asdict(item))


def sort_key(row: FileMatch):
    return (
        CATEGORY_PRIORITY.get(row.category, 999),
        -row.match_count,
        row.relative_path,
    )


def write_result_table(fh, rows: list[FileMatch]) -> None:
    fh.write("| Category | Occurrences | Matching Lines | First Line | Last Line | File |\n")
    fh.write("|---|---:|---:|---:|---:|---|\n")
    for row in rows:
        fh.write(
            f"| {bl.md_escape(row.category)} | {row.match_count:,} | "
            f"{row.matching_lines:,} | {row.first_match_line or ''} | "
            f"{row.last_match_line or ''} | "
            f"`{bl.md_escape(row.relative_path)}` |\n"
        )


def write_markdown(
    matches: list[FileMatch],
    samples: list[MatchSample],
    errors: list[str],
    identifiers: list[str],
    root: Path,
    output_path: Path,
) -> None:
    by_identifier: dict[str, list[FileMatch]] = defaultdict(list)
    samples_by_key: dict[tuple[str, str], list[MatchSample]] = defaultdict(list)

    for item in matches:
        by_identifier[item.identifier].append(item)

    for sample in samples:
        samples_by_key[(sample.identifier, sample.relative_path)].append(sample)

    with output_path.open("w", encoding="utf-8") as fh:
        fh.write("# Identifier Search Results\n\n")
        fh.write(f"- Search root: `{root}`\n")
        fh.write(f"- Identifiers searched: **{len(identifiers)}**\n")
        fh.write(f"- Files with matches: **{len(set(m.relative_path for m in matches))}**\n")
        fh.write(f"- Match result rows: **{len(matches)}**\n\n")

        for identifier in identifiers:
            rows = sorted(by_identifier.get(identifier, []), key=sort_key)
            total_matches = sum(row.match_count for row in rows)

            high_value = [row for row in rows if row.category != "metrics"]
            telemetry = [row for row in rows if row.category == "metrics"]

            fh.write(f"## `{bl.md_escape(identifier)}`\n\n")
            fh.write(f"- Total occurrences: **{total_matches:,}**\n")
            fh.write(f"- Matching files: **{len(rows):,}**\n")
            fh.write(f"- High-value/non-metric files: **{len(high_value):,}**\n")
            fh.write(f"- Metric files: **{len(telemetry):,}**\n\n")

            if not rows:
                fh.write("No matches found.\n\n")
                continue

            if high_value:
                fh.write("### High-Value Matches\n\n")
                write_result_table(fh, high_value)
                fh.write("\n")

            if telemetry:
                telemetry_occurrences = sum(row.match_count for row in telemetry)
                telemetry_lines = sum(row.matching_lines for row in telemetry)
                fh.write("### Repeated Telemetry\n\n")
                fh.write(
                    f"`metrics.json` and other telemetry account for "
                    f"**{telemetry_occurrences:,} occurrence(s)** across "
                    f"**{len(telemetry):,} file(s)** and "
                    f"**{telemetry_lines:,} matching line(s)**.\n\n"
                )
                write_result_table(fh, telemetry)
                fh.write("\n")

            fh.write("### Bounded Samples\n\n")

            # Show high-value samples first, metrics last.
            for row in rows:
                key = (identifier, row.relative_path)
                file_samples = samples_by_key.get(key, [])
                if not file_samples:
                    continue

                fh.write(
                    f"**[{bl.md_escape(row.category)}] "
                    f"`{bl.md_escape(row.relative_path)}`**\n\n"
                )

                for sample in file_samples:
                    fh.write(
                        f"- line {sample.line_number}"
                        f" ({sample.occurrences_on_line} occurrence"
                        f"{'' if sample.occurrences_on_line == 1 else 's'} on line): "
                        f"`{bl.md_escape(sample.sample)}`\n"
                    )
                fh.write("\n")

        if errors:
            fh.write("## Read Errors\n\n")
            fh.write(
                f"{len(errors)} file(s) could not be searched completely. "
                "These are listed for transparency.\n\n"
            )
            for error in errors[:100]:
                fh.write(f"- `{bl.md_escape(error)}`\n")
            if len(errors) > 100:
                fh.write(f"- … {len(errors) - 100} additional errors omitted\n")


def write_summary_json(
    matches: list[FileMatch],
    identifiers: list[str],
    searchable_files: int,
    errors: list[str],
    output_path: Path,
) -> None:
    total_by_identifier = Counter()
    files_by_identifier = defaultdict(set)
    category_counts = defaultdict(Counter)

    for item in matches:
        total_by_identifier[item.identifier] += item.match_count
        files_by_identifier[item.identifier].add(item.relative_path)
        category_counts[item.identifier][item.category] += item.match_count

    data = {
        "identifiers": identifiers,
        "searchable_files_scanned": searchable_files,
        "read_errors": len(errors),
        "results": {
            identifier: {
                "occurrences": total_by_identifier[identifier],
                "matching_files": len(files_by_identifier[identifier]),
                "occurrences_by_category": dict(category_counts[identifier]),
            }
            for identifier in identifiers
        },
    }

    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Safely search a Nomad debug bundle for exact IDs/strings with "
            "bounded terminal output."
        )
    )
    parser.add_argument(
        "bundle",
        type=Path,
        help="Path to an unpacked Nomad debug bundle or artifact directory.",
    )
    parser.add_argument(
        "--id",
        dest="identifiers",
        action="append",
        required=True,
        help="Exact identifier/string to search for. Repeat --id for multiple values.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output directory. Default: <bundle-parent>/analysis_find_identifiers",
    )
    parser.add_argument(
        "--ignore-case",
        action="store_true",
        help="Perform case-insensitive searches.",
    )
    parser.add_argument(
        "--samples-per-file",
        type=int,
        default=DEFAULT_SAMPLES_PER_FILE,
        help=f"Maximum sample lines retained per file per identifier. Default: {DEFAULT_SAMPLES_PER_FILE}.",
    )
    parser.add_argument(
        "--sample-width",
        type=int,
        default=DEFAULT_SAMPLE_WIDTH,
        help=f"Maximum characters retained around each match. Default: {DEFAULT_SAMPLE_WIDTH}.",
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
    if args.samples_per_file <= 0 or args.sample_width <= 0:
        print("ERROR: sample limits must be greater than zero.", file=sys.stderr)
        return 2

    identifiers = list(dict.fromkeys(args.identifiers))

    output_dir = (
        args.output.expanduser().resolve()
        if args.output
        else (root.parent / "analysis_find_identifiers").resolve()
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    files = sorted(iter_searchable_files(root, output_dir))

    print(f"Search root          : {root}")
    print(f"Identifiers          : {len(identifiers)}")
    print(f"Searchable text files: {len(files):,}")
    print(f"Output directory     : {output_dir}")
    print("Source artifacts are opened read-only.")
    print()

    all_matches: list[FileMatch] = []
    all_samples: list[MatchSample] = []
    errors: list[str] = []

    for index, path in enumerate(files, start=1):
        if (
            index == 1
            or index % DEFAULT_PROGRESS_EVERY == 0
            or index == len(files)
        ):
            print(f"  [{index:,}/{len(files):,}] {path.relative_to(root)}")

        matches, samples, error = search_file(
            path=path,
            root=root,
            identifiers=identifiers,
            ignore_case=args.ignore_case,
            samples_per_file=args.samples_per_file,
            sample_width=args.sample_width,
        )

        all_matches.extend(matches)
        all_samples.extend(samples)
        if error:
            errors.append(error)

    all_matches.sort(key=lambda x: (x.identifier, *sort_key(x)))
    all_samples.sort(
        key=lambda x: (
            x.identifier,
            CATEGORY_PRIORITY.get(x.category, 999),
            x.relative_path,
            x.line_number,
        )
    )

    csv_path = output_dir / "results.csv"
    md_path = output_dir / "results.md"
    summary_path = output_dir / "summary.json"

    write_results_csv(all_matches, csv_path)
    write_markdown(
        matches=all_matches,
        samples=all_samples,
        errors=errors,
        identifiers=identifiers,
        root=root,
        output_path=md_path,
    )
    write_summary_json(
        matches=all_matches,
        identifiers=identifiers,
        searchable_files=len(files),
        errors=errors,
        output_path=summary_path,
    )

    print()
    print("Results:")
    for identifier in identifiers:
        rows = [m for m in all_matches if m.identifier == identifier]
        occurrence_count = sum(m.match_count for m in rows)
        file_count = len(rows)
        high_value_files = len([m for m in rows if m.category != "metrics"])
        metric_files = len([m for m in rows if m.category == "metrics"])

        print(
            f"  {identifier}: {occurrence_count:,} occurrence(s) "
            f"in {file_count:,} file(s) "
            f"({high_value_files} high-value, {metric_files} metric)"
        )

    if errors:
        print(f"  Read errors: {len(errors):,}")

    print()
    print(f"CSV      : {csv_path}")
    print(f"Markdown : {md_path}")
    print(f"Summary  : {summary_path}")
    print()
    print("Tip: inspect results.md first. High-value sources are ranked ahead of repetitive telemetry.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
