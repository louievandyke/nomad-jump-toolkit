#!/usr/bin/env python3
"""Safely orient an operator in a case artifact directory before bundle analysis.

This tool is intended for ticket directories that may contain dated uploads,
unpacked hcdiag archives, job specifications, server logs, images, and one or
more nested `nomad operator debug` bundles. It does not unpack archives, modify
case data, or choose between multiple bundles.

Examples:
    # Run from the ticket directory after `ticket TS022716548`.
    python3 /path/to/jumptoolkit/scripts/case_intake.py

    # An explicit case directory is also accepted.
    python3 case_intake.py /ecurep/sf/TS022/716/TS022716548 \
      --bundle /path/to/nomad-debug-2026-07-31-191100Z \
      --case-context ~/case-contexts/TS022716548.json
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

import _bundlelib as bl


DEFAULT_MAX_DEPTH = 14
MAX_TERMINAL_CANDIDATES = 12
CASE_ID_RE = re.compile(r"\bTS\d{9}\b", re.IGNORECASE)
KNOWN_SUFFIXES = {".log", ".txt", ".csv", ".tsv", ".png", ".jpg", ".jpeg", ".nomad", ".hcl", ".json", ".tar", ".gz", ".tgz", ".zip"}


@dataclass(frozen=True)
class BundleCandidate:
    path: str
    capture_name: str
    interval_count: int
    server_count: int
    client_count: int
    eventstream_present: bool


@dataclass(frozen=True)
class CaseArtifact:
    path: str
    category: str
    size_bytes: int
    scan_state: str


def path_depth(root: Path, candidate: Path) -> int:
    try:
        return len(candidate.relative_to(root).parts)
    except ValueError:
        return DEFAULT_MAX_DEPTH + 1


def is_bundle_root(path: Path) -> bool:
    return all((path / part).is_dir() for part in bl.REQUIRED_BUNDLE_DIRS)


def discover_bundles(case_root: Path, output_base: Path, max_depth: int) -> tuple[list[BundleCandidate], int]:
    """Walk directories only; never follow symlinks or inspect file contents."""
    candidates: list[BundleCandidate] = []
    inaccessible = 0
    output_resolved = output_base.resolve()

    for dirpath, dirnames, _ in os.walk(case_root, followlinks=False, onerror=lambda _: None):
        current = Path(dirpath)
        depth = path_depth(case_root, current)
        if depth > max_depth:
            dirnames[:] = []
            continue
        pruned = []
        for name in dirnames:
            child = current / name
            try:
                if child.resolve() == output_resolved or child.is_symlink():
                    continue
                pruned.append(name)
            except OSError:
                inaccessible += 1
        dirnames[:] = pruned

        try:
            if not current.name.startswith("nomad-debug-") or not is_bundle_root(current):
                continue
            interval_root = current / "interval"
            interval_count = sum(1 for p in interval_root.iterdir() if p.is_dir() and p.name.isdigit())
            candidates.append(BundleCandidate(
                path=str(current),
                capture_name=current.name,
                interval_count=interval_count,
                server_count=sum(1 for p in (current / "server").iterdir() if p.is_dir()),
                client_count=sum(1 for p in (current / "client").iterdir() if p.is_dir()),
                eventstream_present=(current / "cluster" / "eventstream.json").is_file(),
            ))
            dirnames[:] = []  # Do not rediscover bundle-internal paths.
        except OSError:
            inaccessible += 1

    return sorted(candidates, key=lambda item: item.path), inaccessible


def artifact_category(path: Path) -> str:
    name = path.name.lower()
    if "hcdiag" in name or "nomad-debug" in name:
        return "diagnostic_archive_or_extract"
    if path.suffix.lower() in {".nomad", ".hcl"}:
        return "job_or_configuration"
    if path.suffix.lower() in {".png", ".jpg", ".jpeg"}:
        return "image_or_graph"
    if path.suffix.lower() in {".csv", ".tsv"}:
        return "tabular_export"
    if path.suffix.lower() in {".tar", ".gz", ".tgz", ".zip"}:
        return "archive"
    if "log" in name or path.suffix.lower() in {".log", ".txt"}:
        return "log_or_text"
    return "other"


def collect_case_artifacts(case_root: Path, selected_bundle: Path | None, output_base: Path, max_depth: int) -> tuple[list[CaseArtifact], int]:
    """Index adjacent artifacts, excluding bundle contents already handled by analysis tools."""
    output_resolved = output_base.resolve()
    artifacts: list[CaseArtifact] = []
    inaccessible = 0
    selected_resolved = selected_bundle.resolve() if selected_bundle else None

    for dirpath, dirnames, filenames in os.walk(case_root, followlinks=False, onerror=lambda _: None):
        current = Path(dirpath)
        if path_depth(case_root, current) > max_depth:
            dirnames[:] = []
            continue
        try:
            if selected_resolved and current.resolve() == selected_resolved:
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames if not (current / d).is_symlink() and (current / d).resolve() != output_resolved]
        except OSError:
            inaccessible += 1
            dirnames[:] = []
            continue
        for filename in filenames:
            path = current / filename
            if path.suffix.lower() not in KNOWN_SUFFIXES and "log" not in filename.lower():
                continue
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                artifacts.append(CaseArtifact(str(path.relative_to(case_root)), artifact_category(path), path.stat().st_size, "indexed"))
            except OSError:
                inaccessible += 1

    return sorted(artifacts, key=lambda item: item.path), inaccessible


def case_reference(case_root: Path) -> str:
    match = CASE_ID_RE.search(str(case_root))
    return match.group(0).upper() if match else case_root.name


def is_ecurep_case_path(case_root: Path) -> bool:
    """Return whether this appears to be an ECuRep case directory.

    Both signals are required so an arbitrary headless Linux path is never
    treated as ECuRep: the path must be under the ECuRep tree and contain a
    recognizable TS case reference.
    """
    return "/ecurep/" in case_root.as_posix() and CASE_ID_RE.search(str(case_root)) is not None


def slug(value: str) -> str:
    return (re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip(".-") or "case-intake")[:80]


def write_outputs(run_dir: Path, case_root: Path, case_id: str, ecurep_case_detected: bool, candidates: list[BundleCandidate], selected: BundleCandidate, artifacts: list[CaseArtifact], context_path: Path | None, discovery_errors: int, artifact_errors: int) -> None:
    summary = {
        "case_root": str(case_root),
        "case_reference": case_id,
        "ecurep_case_detected": ecurep_case_detected,
        "case_context_path": str(context_path) if context_path else "",
        "bundle_candidates": [asdict(item) for item in candidates],
        "selected_bundle": asdict(selected),
        "adjacent_artifact_count": len(artifacts),
        "artifact_category_counts": dict(Counter(item.category for item in artifacts)),
        "discovery_inaccessible_paths": discovery_errors,
        "artifact_inaccessible_paths": artifact_errors,
        "forensic_note": "This is a navigation inventory. It does not inspect artifact content or establish technical conclusions.",
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with (run_dir / "artifacts.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(CaseArtifact.__dataclass_fields__))
        writer.writeheader()
        for artifact in artifacts:
            writer.writerow(asdict(artifact))

    bundle_path = selected.path
    # Generated commands must work from the ticket directory, not just from
    # the toolkit checkout. `ticket <CASE-ID>` changes the current directory
    # to ECuRep case data, so relative `scripts/...` paths would fail there.
    script_dir = Path(__file__).resolve().parent
    with (run_dir / "next_steps.md").open("w", encoding="utf-8") as fh:
        fh.write("# Suggested Next Steps\n\n")
        fh.write("These commands analyze only the selected bundle and write derived results outside the case directory. Review the selected path before running them.\n\n")
        fh.write("```bash\n")
        fh.write(f"TOOLKIT_SCRIPTS='{script_dir}'\n")
        fh.write(f"BUNDLE='{bundle_path}'\n")
        fh.write(f"ANALYSIS_DIR='{run_dir}'\n\n")
        fh.write("python3 \"$TOOLKIT_SCRIPTS/inventory_bundle_v2.py\" \"$BUNDLE\" --output \"$ANALYSIS_DIR/inventory\"\n")
        if context_path:
            fh.write(f"python3 \"$TOOLKIT_SCRIPTS/case_review.py\" \"$BUNDLE\" --case-context '{context_path}' --output \"$ANALYSIS_DIR/case_review\"\n")
        else:
            fh.write("# Optional: create a reviewed sidecar from examples/case_context.example.json\n")
            fh.write("# python3 \"$TOOLKIT_SCRIPTS/case_review.py\" \"$BUNDLE\" --case-context /path/to/case_context.json --output \"$ANALYSIS_DIR/case_review\"\n")
        fh.write("```\n\n")
        fh.write("Use exact allocation, evaluation, node, or job IDs from reviewed case material as seeds for lifecycle, lineage, evaluation, or timeline tools. Do not treat this navigation inventory as technical evidence.\n")

    with (run_dir / "report.md").open("w", encoding="utf-8") as fh:
        fh.write("# Case Intake\n\n")
        fh.write(f"- Case root: `{case_root}`\n")
        fh.write(f"- Case reference: `{case_id}`\n")
        fh.write(f"- ECuRep case detected: `{'yes' if ecurep_case_detected else 'no'}`\n")
        fh.write(f"- Selected bundle: `{selected.path}`\n")
        fh.write(f"- Case-context file supplied: `{context_path or ''}`\n")
        fh.write("- Scope: directory navigation only; no artifact content was used for conclusions.\n\n")
        fh.write("## Nomad Debug Bundle Candidates\n\n")
        fh.write("| Selected | Capture | Path | Intervals | Servers | Clients | Eventstream |\n|---|---|---|---:|---:|---:|---|\n")
        for candidate in candidates:
            marker = "yes" if candidate.path == selected.path else ""
            fh.write(f"| {marker} | {candidate.capture_name} | `{candidate.path}` | {candidate.interval_count} | {candidate.server_count} | {candidate.client_count} | {candidate.eventstream_present} |\n")
        fh.write("\n## Adjacent Case Artifacts\n\n")
        fh.write(f"Indexed **{len(artifacts)}** files outside the selected bundle. Full list: `artifacts.csv`.\n\n")
        fh.write("| Category | Count |\n|---|---:|\n")
        for category, count in sorted(Counter(item.category for item in artifacts).items()):
            fh.write(f"| {category} | {count} |\n")
        fh.write("\n## Access Notes\n\n")
        fh.write(f"- Inaccessible paths during bundle discovery: **{discovery_errors}**\n")
        fh.write(f"- Inaccessible paths during adjacent-artifact indexing: **{artifact_errors}**\n")
        fh.write("- Archives were indexed by name only; this tool does not unpack them.\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Discover nested Nomad debug bundles and map adjacent case artifacts without modifying source data.")
    parser.add_argument(
        "case_root",
        nargs="?",
        type=Path,
        default=Path("."),
        help="ticket/case artifact directory (default: current directory)",
    )
    parser.add_argument("--bundle", type=Path, help="select one discovered bundle when several are present")
    parser.add_argument("--case-context", type=Path, help="optional reviewed case-context JSON; path is recorded and used in next steps")
    parser.add_argument("--output", type=Path, help="derived output base (default: ~/analysis_case_intake)")
    parser.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH, help=f"maximum directory depth to scan (default: {DEFAULT_MAX_DEPTH})")
    parser.add_argument("--overwrite", action="store_true", help="replace an existing derived intake directory")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    case_root = args.case_root.expanduser().resolve()
    if not case_root.is_dir():
        print(f"ERROR: case directory does not exist: {case_root}", file=sys.stderr)
        return 2
    if args.max_depth < 1:
        print("ERROR: --max-depth must be at least 1.", file=sys.stderr)
        return 2
    context_path = args.case_context.expanduser().resolve() if args.case_context else None
    if context_path and not context_path.is_file():
        print(f"ERROR: case-context file does not exist: {context_path}", file=sys.stderr)
        return 2
    # The operator normally invokes this from the ticket directory after
    # `ticket <CASE-ID>`; keep derived output out of customer/case data by
    # default. --output remains available for an approved analysis volume.
    output_base = args.output.expanduser().resolve() if args.output else (Path.home() / "analysis_case_intake").resolve()
    case_id = case_reference(case_root)
    ecurep_case_detected = is_ecurep_case_path(case_root)
    run_dir = output_base / slug(case_id)
    if ecurep_case_detected:
        print(f"ECuRep case detected : {case_id}")
    print(f"Case root        : {case_root}")
    print(f"Derived output   : {run_dir}")
    print(f"Search depth     : {args.max_depth}")
    print("Discovering Nomad debug bundle roots without reading source artifacts...")
    candidates, discovery_errors = discover_bundles(case_root, output_base, args.max_depth)
    if not candidates:
        print("ERROR: no standard Nomad operator debug bundle was found within the search depth.", file=sys.stderr)
        return 2
    selected = None
    if args.bundle:
        requested = args.bundle.expanduser().resolve()
        selected = next((item for item in candidates if Path(item.path).resolve() == requested), None)
        if selected is None:
            print("ERROR: --bundle is not one of the discovered standard bundle roots.", file=sys.stderr)
            return 2
    elif len(candidates) == 1:
        selected = candidates[0]
    else:
        print(f"ERROR: found {len(candidates)} viable bundles; select one with --bundle:", file=sys.stderr)
        for candidate in candidates[:MAX_TERMINAL_CANDIDATES]:
            print(f"  {candidate.path}  (intervals={candidate.interval_count}, servers={candidate.server_count}, clients={candidate.client_count})", file=sys.stderr)
        if len(candidates) > MAX_TERMINAL_CANDIDATES:
            print(f"  ... {len(candidates) - MAX_TERMINAL_CANDIDATES} more candidate(s)", file=sys.stderr)
        return 2
    if run_dir.exists():
        if not args.overwrite:
            print(f"ERROR: derived intake already exists: {run_dir}\nUse --overwrite to replace it.", file=sys.stderr)
            return 2
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    print(f"Selected bundle  : {selected.path}")
    print("Indexing adjacent case artifacts by name and metadata only...")
    artifacts, artifact_errors = collect_case_artifacts(case_root, Path(selected.path), output_base, args.max_depth)
    write_outputs(run_dir, case_root, case_id, ecurep_case_detected, candidates, selected, artifacts, context_path, discovery_errors, artifact_errors)
    print("Done.")
    print(f"  Bundle candidates          : {len(candidates)}")
    print(f"  Adjacent artifacts indexed : {len(artifacts)}")
    print(f"  Markdown report            : {run_dir / 'report.md'}")
    print(f"  Suggested next steps       : {run_dir / 'next_steps.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
