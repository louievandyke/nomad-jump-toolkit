#!/usr/bin/env python3
"""
Review a structured, case-reported investigation brief against an unpacked
Nomad operator debug bundle.

The case-context file is an optional workflow input: it supplies leads and
exact identifiers from a ticket or handoff. It is not bundle evidence. This
tool deliberately reports exact identifier observations with provenance and
does not automatically confirm or reject free-text case claims.

Examples:
    python3 case_review.py ./nomad-debug --case-context case_context.json
    python3 case_review.py ./bundle --case-context case_context.json \
      --output ./analysis_case_review --overwrite

Outputs:
    analysis_case_review/<case-reference>/
      report.md
      report.csv
      supporting.json
      summary.json
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import _bundlelib as bl


SCHEMA_VERSION = 1
SEED_TYPES = {
    "allocation_ids": "allocation_id",
    "evaluation_ids": "evaluation_id",
    "job_ids": "job_id",
    "node_ids": "node_id",
    "deployment_ids": "deployment_id",
}

SNAPSHOTS = (
    ("allocations.json", ("Allocations", "Items")),
    ("evaluations.json", ("Evaluations", "Items")),
    ("jobs.json", ("Jobs", "Items")),
    ("nodes.json", ("Nodes", "Items")),
    ("deployments.json", ("Deployments", "Items")),
)


@dataclass(frozen=True)
class Observation:
    seed_type: str
    seed_value: str
    observation_state: str
    evidence_type: str
    source_artifact: str
    interval: str
    source_line: str
    matched_field: str
    matched_object_type: str
    matched_object_id: str


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise ValueError(message)


def load_context(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except OSError as exc:
        fail(f"cannot read case context: {path}: {exc}")
    except json.JSONDecodeError as exc:
        fail(f"case context is not valid JSON: {path}: line {exc.lineno}, column {exc.colno}")

    if not isinstance(value, dict):
        fail("case context must be a JSON object")
    if value.get("schema_version") != SCHEMA_VERSION:
        fail(f"case context schema_version must be {SCHEMA_VERSION}")
    if not isinstance(value.get("classification"), str) or not value["classification"].strip():
        fail("case context requires a non-empty classification")

    seeds = value.get("seeds", {})
    if seeds is None:
        seeds = {}
        value["seeds"] = seeds
    if not isinstance(seeds, dict):
        fail("case context seeds must be an object")

    for plural in SEED_TYPES:
        if plural not in seeds:
            continue
        if not isinstance(seeds[plural], list) or not all(
            isinstance(item, str) and item.strip() for item in seeds[plural]
        ):
            fail(f"case context seeds.{plural} must be an array of non-empty strings")

    claims = value.get("claims_to_test", [])
    if not isinstance(claims, list):
        fail("case context claims_to_test must be an array")
    for index, claim in enumerate(claims, 1):
        if not isinstance(claim, dict):
            fail(f"claims_to_test item {index} must be an object")
        if not isinstance(claim.get("id"), str) or not claim["id"].strip():
            fail(f"claims_to_test item {index} requires a non-empty id")
        if not isinstance(claim.get("claim"), str) or not claim["claim"].strip():
            fail(f"claims_to_test item {index} requires a non-empty claim")

    return value


def seed_map(context: dict[str, Any]) -> dict[str, set[str]]:
    result = {seed_type: set() for seed_type in SEED_TYPES.values()}
    for plural, seed_type in SEED_TYPES.items():
        for value in context.get("seeds", {}).get(plural, []):
            result[seed_type].add(value)
    return result


def first_string(record: dict, keys: tuple[str, ...]) -> str:
    value = bl.first_value(record, keys)
    return str(value) if value is not None else ""


def record_fields(record: dict, artifact_name: str) -> tuple[str, str, dict[str, str]]:
    """Return object metadata and explicit ID-like fields; no inferred links."""
    job = record.get("Job") if isinstance(record.get("Job"), dict) else {}
    fields = {
        "allocation_id": first_string(record, ("ID", "AllocID", "AllocationID")),
        "evaluation_id": first_string(record, ("EvalID", "EvaluationID")),
        "job_id": first_string(record, ("JobID",)),
        "node_id": first_string(record, ("NodeID",)),
        "deployment_id": first_string(record, ("DeploymentID",)),
    }
    if not fields["job_id"]:
        fields["job_id"] = first_string(job, ("ID", "Name"))

    if artifact_name == "evaluations.json":
        fields["evaluation_id"] = first_string(record, ("ID", "EvalID", "EvaluationID"))
    elif artifact_name == "jobs.json":
        fields["job_id"] = first_string(record, ("ID", "Name", "JobID"))
    elif artifact_name == "nodes.json":
        fields["node_id"] = first_string(record, ("ID", "NodeID"))
    elif artifact_name == "deployments.json":
        fields["deployment_id"] = first_string(record, ("ID", "DeploymentID"))

    object_type = artifact_name.removesuffix(".json")
    object_id = next((value for value in fields.values() if value), "")
    return object_type, object_id, {key: value for key, value in fields.items() if value}


def collect_observations(bundle_root: Path, root: Path, seeds: dict[str, set[str]]) -> tuple[list[Observation], dict[str, Any]]:
    observations: list[Observation] = []
    stats: dict[str, Any] = {"intervals": 0, "records_read": Counter(), "parse_modes": Counter(), "eventstream_records": 0}
    interval_root = bundle_root / "interval"
    interval_dirs = sorted(p for p in interval_root.iterdir() if p.is_dir() and p.name.isdigit())
    stats["intervals"] = len(interval_dirs)

    def inspect_record(record: dict, artifact_name: str, evidence_type: str, source: str, interval: str, line: str = "") -> None:
        object_type, object_id, fields = record_fields(record, artifact_name)
        for seed_type, seed_values in seeds.items():
            value = fields.get(seed_type)
            if value and value in seed_values:
                observations.append(Observation(seed_type, value, "observed", evidence_type, source, interval, line, seed_type, object_type, object_id))

    for interval_dir in interval_dirs:
        for artifact_name, wrappers in SNAPSHOTS:
            path = interval_dir / artifact_name
            if not path.is_file():
                continue
            records, mode = bl.read_records(path, wrappers, id_keys=None)
            stats["parse_modes"][f"{artifact_name}:{mode}"] += 1
            stats["records_read"][artifact_name] += len(records)
            for record in records:
                inspect_record(record, artifact_name, "interval_snapshot", str(path.relative_to(root)), interval_dir.name)

    eventstream = bundle_root / "cluster" / "eventstream.json"
    if eventstream.is_file():
        for line_no, event in bl.iter_eventstream_records(eventstream):
            stats["eventstream_records"] += 1
            payload = event.get("Payload")
            if not isinstance(payload, dict):
                continue
            for key, artifact_name in (("Allocation", "allocations.json"), ("Evaluation", "evaluations.json"), ("Job", "jobs.json"), ("Node", "nodes.json"), ("Deployment", "deployments.json")):
                record = payload.get(key)
                if isinstance(record, dict):
                    inspect_record(record, artifact_name, "eventstream_payload", str(eventstream.relative_to(root)), "", str(line_no))

    return observations, stats


def slug(value: str) -> str:
    compact = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip(".-")
    return compact[:80] or "case-review"


def write_outputs(run_dir: Path, root: Path, context_path: Path, context: dict[str, Any], observations: list[Observation], stats: dict[str, Any], seeds: dict[str, set[str]]) -> None:
    observed = {(item.seed_type, item.seed_value) for item in observations}
    all_seeds = sorted((seed_type, value) for seed_type, values in seeds.items() for value in values)
    rows = list(observations)
    for seed_type, value in all_seeds:
        if (seed_type, value) not in observed:
            rows.append(Observation(seed_type, value, "not observed in captured state", "", "", "", "", "", "", ""))
    rows.sort(key=lambda item: (item.seed_type, item.seed_value, item.observation_state, item.source_artifact, item.interval, item.source_line))

    with (run_dir / "report.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(Observation.__dataclass_fields__))
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))

    claim_rows = []
    for claim in context.get("claims_to_test", []):
        claim_rows.append({
            "id": claim["id"],
            "claim": claim["claim"],
            "source": claim.get("source", "case context"),
            "assessment": "not automatically assessed; case-reported claim remains unconfirmed",
            "evidence_needed": claim.get("evidence_needed", []),
        })

    supporting = {
        "case_context_path": str(context_path),
        "case_context": context,
        "seed_observations": [asdict(row) for row in rows],
        "claim_assessments": claim_rows,
        "parsing": {"intervals": stats["intervals"], "records_read": dict(stats["records_read"]), "parse_modes": dict(stats["parse_modes"]), "eventstream_records": stats["eventstream_records"]},
        "forensic_note": "Case context is user-supplied lead material, not bundle-derived evidence. Exact identifier observations do not confirm free-text case claims or relationships.",
    }
    (run_dir / "supporting.json").write_text(json.dumps(supporting, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = {
        "case_reference": context.get("case_reference", ""),
        "classification": context["classification"],
        "seed_count": len(all_seeds),
        "observed_seed_count": len(observed),
        "not_observed_seed_count": len(all_seeds) - len(observed),
        "claim_count": len(claim_rows),
        "claim_confirmation_count": 0,
        "parsing": supporting["parsing"],
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with (run_dir / "report.md").open("w", encoding="utf-8") as fh:
        fh.write("# Case Context Review\n\n")
        fh.write(f"- Bundle search root: `{root}`\n")
        fh.write(f"- Case-context file: `{context_path}`\n")
        fh.write(f"- Case reference: `{context.get('case_reference', '')}`\n")
        fh.write(f"- Classification: **{bl.md_escape(context['classification'])}**\n")
        fh.write("- Evidence boundary: case-reported context is not bundle-derived evidence.\n")
        fh.write(f"- Interval captures inspected: **{stats['intervals']}**\n\n")
        fh.write("## Exact Seed Observations\n\n")
        fh.write("`not observed in captured state` does not establish absence; the referenced object may be outside the capture window or unavailable in the collected artifacts.\n\n")
        fh.write("| Seed type | Seed value | State | Evidence type | Source artifact | Interval | Field | Object |\n|---|---|---|---|---|---|---|---|\n")
        for row in rows:
            source = row.source_artifact + (f":{row.source_line}" if row.source_line else "")
            obj = f"{row.matched_object_type}:{row.matched_object_id}" if row.matched_object_type else ""
            fh.write("| " + " | ".join(bl.md_escape(value) for value in (row.seed_type, row.seed_value, row.observation_state, row.evidence_type, source, row.interval, row.matched_field, obj)) + " |\n")
        fh.write("\n## Case-Reported Claims\n\n")
        fh.write("These claims are retained as leads. This tool does not confirm or reject free-text claims from identifier presence alone.\n\n")
        fh.write("| Claim ID | Case-reported claim | Source | Assessment | Evidence requested |\n|---|---|---|---|---|\n")
        for row in claim_rows:
            needed = "; ".join(str(item) for item in row["evidence_needed"])
            fh.write("| " + " | ".join(bl.md_escape(value) for value in (row["id"], row["claim"], row["source"], row["assessment"], needed)) + " |\n")
        fh.write("\n## Parsing Coverage\n\n")
        fh.write("| Artifact | Records read | Parse modes |\n|---|---:|---|\n")
        for artifact in sorted(stats["records_read"]):
            modes = ", ".join(key.rsplit(":", 1)[1] + f"={count}" for key, count in sorted(stats["parse_modes"].items()) if key.startswith(artifact + ":"))
            fh.write(f"| {artifact} | {stats['records_read'][artifact]} | {modes} |\n")
        fh.write(f"\n- Eventstream records inspected: **{stats['eventstream_records']}**\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Review case-reported exact identifiers against a Nomad debug bundle without treating the case context as evidence.")
    parser.add_argument("bundle", type=Path, help="unpacked bundle root or parent containing one bundle")
    parser.add_argument("--case-context", type=Path, required=True, help="structured JSON investigation brief")
    parser.add_argument("--output", type=Path, help="derived output base directory")
    parser.add_argument("--overwrite", action="store_true", help="replace an existing derived run directory")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.bundle.expanduser().resolve()
    context_path = args.case_context.expanduser().resolve()
    if not root.is_dir():
        print(f"ERROR: bundle directory does not exist: {root}", file=sys.stderr)
        return 2
    try:
        context = load_context(context_path)
    except ValueError:
        return 2
    bundle_root = bl.find_bundle_root(root)
    if bundle_root is None:
        print("ERROR: standard Nomad operator debug layout not detected.", file=sys.stderr)
        return 2
    seeds = seed_map(context)
    if not any(seeds.values()):
        print("ERROR: case context contains no exact identifier seeds.", file=sys.stderr)
        return 2
    base = args.output.expanduser().resolve() if args.output else (root.parent / "analysis_case_review").resolve()
    run_dir = base / slug(str(context.get("case_reference") or context_path.stem))
    if run_dir.exists():
        if not args.overwrite:
            print(f"ERROR: derived case review already exists: {run_dir}\nUse --overwrite to replace it.", file=sys.stderr)
            return 2
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    print(f"Search root      : {root}")
    print(f"Bundle root      : {bundle_root}")
    print(f"Case context     : {context_path}")
    print(f"Output directory : {run_dir}")
    print("Case context is lead material; source bundle artifacts are opened read-only.")
    print()
    print("Inspecting structured interval snapshots and eventstream records...")
    observations, stats = collect_observations(bundle_root, root, seeds)
    write_outputs(run_dir, root, context_path, context, observations, stats, seeds)
    observed_seed_count = len({(item.seed_type, item.seed_value) for item in observations})
    seed_count = sum(len(values) for values in seeds.values())
    print("Done.")
    print(f"  Exact seeds supplied       : {seed_count}")
    print(f"  Exact seeds observed       : {observed_seed_count}")
    print(f"  Claims retained as leads   : {len(context.get('claims_to_test', []))}")
    print(f"  Markdown report            : {run_dir / 'report.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
