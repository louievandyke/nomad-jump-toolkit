#!/usr/bin/env python3
"""
eval_trace.py

Trace Nomad evaluation chains from an evaluation ID or allocation ID using an
unpacked `nomad operator debug` bundle.

Designed for restricted jump boxes:
- Python standard library only
- no network access
- source artifacts opened read-only
- bounded stdout
- derived output written under analysis_eval_trace/

Evidence sources:
- interval/*/evaluations.json
- interval/*/allocations.json
- cluster/eventstream.json

Supported input formats:
- ordinary JSON arrays/objects
- wrapper objects such as {"Evaluations":[...]} / {"Allocations":[...]}
- multiple JSON documents / JSON-lines files
- empty files are reported, not treated as successful parses

Examples:
    python3 eval_trace.py ./nomad-debug-2026-08-14-171817Z \
      --eval ced8afab-16e4-87ce-2f01-e297b45ba3c3

    python3 eval_trace.py ./nomad-debug-2026-08-14-171817Z \
      --alloc ee943c77-0149-b085-fad0-de0f30f23c2c

    python3 eval_trace.py ./nomad-debug-2026-08-14-171817Z \
      --eval ced8afab-16e4-87ce-2f01-e297b45ba3c3 \
      --overwrite

Output:
    analysis_eval_trace/<seed>/
      eval_trace.md
      eval_trace.csv
      evaluations.json
      allocations.json
      relationships.json
      summary.json
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional


UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


@dataclass
class EvalRelationship:
    from_eval: str
    to_eval: str
    relation: str
    evidence_strength: str
    source_file: str
    source_detail: str


def first_value(d: dict, keys: Iterable[str]) -> Any:
    for key in keys:
        if key in d:
            return d[key]
    return None


def iso(dt: Optional[datetime]) -> str:
    if dt is None:
        return ""
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def unixish_to_dt(value: Any) -> Optional[datetime]:
    if value is None:
        return None

    if isinstance(value, str):
        try:
            value = int(value)
        except ValueError:
            try:
                raw = value[:-1] + "+00:00" if value.endswith("Z") else value
                dt = datetime.fromisoformat(raw)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
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


def find_bundle_root(root: Path) -> Optional[Path]:
    required = ("cluster", "interval", "server", "client")

    if all((root / name).is_dir() for name in required):
        return root

    candidates = []

    try:
        for child in root.iterdir():
            if child.is_dir() and all((child / name).is_dir() for name in required):
                candidates.append(child)
    except OSError:
        return None

    return candidates[0] if len(candidates) == 1 else None


def expand_json_value(value: Any, kind: str) -> list[dict]:
    if isinstance(value, list):
        return [x for x in value if isinstance(x, dict)]

    if not isinstance(value, dict):
        return []

    wrappers = {
        "evaluation": ("Evaluations", "Items"),
        "allocation": ("Allocations", "Items"),
    }

    for key in wrappers[kind]:
        if isinstance(value.get(key), list):
            return [x for x in value[key] if isinstance(x, dict)]

    if first_value(value, ("ID", "EvalID", "AllocationID", "AllocID")):
        return [value]

    return []


def read_records(path: Path, kind: str) -> tuple[list[dict], str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], "unparseable"

    if not text.strip():
        return [], "empty"

    try:
        value = json.loads(text)
        return expand_json_value(value, kind), "json"
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
        records.extend(expand_json_value(value, kind))

    if parsed_any:
        return records, "json-lines"

    return [], "unparseable"


def merge_record(existing: dict, incoming: dict, source_file: str, interval_id: str) -> dict:
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


def summarize_eval(record: dict) -> dict:
    create_dt = unixish_to_dt(first_value(record, ("CreateTime", "CreateTimestamp")))
    modify_dt = unixish_to_dt(first_value(record, ("ModifyTime", "ModifyTimestamp")))
    wait_dt = unixish_to_dt(first_value(record, ("WaitUntil",)))

    return {
        "id": str(first_value(record, ("ID", "EvalID")) or ""),
        "namespace": first_value(record, ("Namespace",)),
        "job_id": first_value(record, ("JobID",)),
        "node_id": first_value(record, ("NodeID",)),
        "deployment_id": first_value(record, ("DeploymentID",)),
        "triggered_by": first_value(record, ("TriggeredBy",)),
        "status": first_value(record, ("Status",)),
        "status_description": first_value(record, ("StatusDescription",)),
        "previous_eval": first_value(record, ("PreviousEval",)),
        "next_eval": first_value(record, ("NextEval",)),
        "blocked_eval": first_value(record, ("BlockedEval",)),
        "create_time_utc": iso(create_dt),
        "modify_time_utc": iso(modify_dt),
        "wait_until_utc": iso(wait_dt),
        "priority": first_value(record, ("Priority",)),
        "type": first_value(record, ("Type",)),
        "failed_tg_allocs": record.get("FailedTGAllocs"),
        "queued_allocations": record.get("QueuedAllocations"),
        "class_eligibility": record.get("ClassEligibility"),
        "annotate_plan": record.get("AnnotatePlan"),
    }


def summarize_alloc(record: dict) -> dict:
    create_dt = unixish_to_dt(first_value(record, ("CreateTime", "CreateTimestamp")))
    modify_dt = unixish_to_dt(first_value(record, ("ModifyTime", "ModifyTimestamp")))

    return {
        "id": str(first_value(record, ("ID", "AllocID", "AllocationID")) or ""),
        "eval_id": first_value(record, ("EvalID",)),
        "job_id": first_value(record, ("JobID",)),
        "namespace": first_value(record, ("Namespace",)),
        "task_group": first_value(record, ("TaskGroup", "TaskGroupName")),
        "node_id": first_value(record, ("NodeID",)),
        "node_name": first_value(record, ("NodeName",)),
        "deployment_id": first_value(record, ("DeploymentID",)),
        "desired_status": first_value(record, ("DesiredStatus",)),
        "client_status": first_value(record, ("ClientStatus",)),
        "previous_allocation": first_value(record, ("PreviousAllocation",)),
        "next_allocation": first_value(record, ("NextAllocation",)),
        "create_time_utc": iso(create_dt),
        "modify_time_utc": iso(modify_dt),
    }


def collect_interval_data(bundle_root: Path, root: Path):
    evaluations: dict[str, dict] = {}
    allocations: dict[str, dict] = {}

    stats = {
        "intervals": 0,
        "evaluation_files": 0,
        "evaluation_records": 0,
        "evaluation_json_lines_files": 0,
        "evaluation_empty_files": 0,
        "evaluation_unparseable_files": 0,
        "allocation_files": 0,
        "allocation_records": 0,
        "allocation_json_lines_files": 0,
        "allocation_empty_files": 0,
        "allocation_unparseable_files": 0,
    }

    interval_dirs = sorted(
        p for p in (bundle_root / "interval").iterdir()
        if p.is_dir() and p.name.isdigit()
    )
    stats["intervals"] = len(interval_dirs)

    print(f"Inspecting {len(interval_dirs)} interval capture(s)...")

    for interval_dir in interval_dirs:
        eval_path = interval_dir / "evaluations.json"

        if eval_path.is_file():
            stats["evaluation_files"] += 1
            records, mode = read_records(eval_path, "evaluation")

            if mode == "json-lines":
                stats["evaluation_json_lines_files"] += 1
            elif mode == "empty":
                stats["evaluation_empty_files"] += 1
            elif mode == "unparseable":
                stats["evaluation_unparseable_files"] += 1

            stats["evaluation_records"] += len(records)

            for record in records:
                summary = summarize_eval(record)
                eval_id = summary["id"]

                if not eval_id:
                    continue

                evaluations[eval_id] = merge_record(
                    evaluations.get(eval_id, {}),
                    summary,
                    str(eval_path.relative_to(root)),
                    interval_dir.name,
                )

        alloc_path = interval_dir / "allocations.json"

        if alloc_path.is_file():
            stats["allocation_files"] += 1
            records, mode = read_records(alloc_path, "allocation")

            if mode == "json-lines":
                stats["allocation_json_lines_files"] += 1
            elif mode == "empty":
                stats["allocation_empty_files"] += 1
            elif mode == "unparseable":
                stats["allocation_unparseable_files"] += 1

            stats["allocation_records"] += len(records)

            for record in records:
                summary = summarize_alloc(record)
                alloc_id = summary["id"]

                if not alloc_id:
                    continue

                allocations[alloc_id] = merge_record(
                    allocations.get(alloc_id, {}),
                    summary,
                    str(alloc_path.relative_to(root)),
                    interval_dir.name,
                )

    print(f"Unique evaluations found : {len(evaluations)}")
    print(f"Evaluation records read  : {stats['evaluation_records']}")
    print(f"Unique allocations found : {len(allocations)}")
    print(f"Allocation records read  : {stats['allocation_records']}")

    if stats["evaluation_json_lines_files"]:
        print(f"Evaluation JSON-lines    : {stats['evaluation_json_lines_files']} file(s)")
    if stats["allocation_json_lines_files"]:
        print(f"Allocation JSON-lines    : {stats['allocation_json_lines_files']} file(s)")
    if stats["evaluation_empty_files"]:
        print(f"Empty evaluation files   : {stats['evaluation_empty_files']}")
    if stats["allocation_empty_files"]:
        print(f"Empty allocation files   : {stats['allocation_empty_files']}")
    if stats["evaluation_unparseable_files"]:
        print(f"Bad evaluation files     : {stats['evaluation_unparseable_files']}")
    if stats["allocation_unparseable_files"]:
        print(f"Bad allocation files     : {stats['allocation_unparseable_files']}")

    return evaluations, allocations, stats


def iter_eventstream(path: Path):
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


def collect_eventstream(bundle_root: Path, root: Path, evaluations: dict, allocations: dict):
    path = bundle_root / "cluster" / "eventstream.json"

    counts = {"evaluation": 0, "allocation": 0}

    if not path.is_file():
        return counts

    print("Parsing cluster/eventstream.json...")

    for line_no, record in iter_eventstream(path):
        payload = record.get("Payload")
        if not isinstance(payload, dict):
            continue

        eval_obj = payload.get("Evaluation")

        if isinstance(eval_obj, dict):
            summary = summarize_eval(eval_obj)
            eval_id = summary["id"]

            if eval_id:
                counts["evaluation"] += 1
                source = f"{path.relative_to(root)}:{line_no}"
                evaluations[eval_id] = merge_record(
                    evaluations.get(eval_id, {}),
                    summary,
                    source,
                    "",
                )

        alloc_obj = payload.get("Allocation")

        if isinstance(alloc_obj, dict):
            summary = summarize_alloc(alloc_obj)
            alloc_id = summary["id"]

            if alloc_id:
                counts["allocation"] += 1
                source = f"{path.relative_to(root)}:{line_no}"
                allocations[alloc_id] = merge_record(
                    allocations.get(alloc_id, {}),
                    summary,
                    source,
                    "",
                )

    print(f"Evaluation event records : {counts['evaluation']}")
    print(f"Allocation event records : {counts['allocation']}")

    return counts


def add_edge(
    rels: list[EvalRelationship],
    successors: dict[str, set[str]],
    predecessors: dict[str, set[str]],
    seen: set[tuple[str, str, str]],
    rel: EvalRelationship,
):
    key = (rel.from_eval, rel.to_eval, rel.relation)

    if key in seen:
        return

    seen.add(key)
    rels.append(rel)
    successors[rel.from_eval].add(rel.to_eval)
    predecessors[rel.to_eval].add(rel.from_eval)


def build_relationships(evaluations: dict[str, dict]):
    rels = []
    successors = defaultdict(set)
    predecessors = defaultdict(set)
    seen = set()

    for eval_id, record in evaluations.items():
        source = ", ".join(record.get("sources", [])[:3])

        prev_id = record.get("previous_eval")
        if isinstance(prev_id, str) and prev_id:
            add_edge(
                rels,
                successors,
                predecessors,
                seen,
                EvalRelationship(
                    from_eval=prev_id,
                    to_eval=eval_id,
                    relation="PreviousEval",
                    evidence_strength="authoritative",
                    source_file=source,
                    source_detail=f"{eval_id}.PreviousEval={prev_id}",
                ),
            )

        next_id = record.get("next_eval")
        if isinstance(next_id, str) and next_id:
            add_edge(
                rels,
                successors,
                predecessors,
                seen,
                EvalRelationship(
                    from_eval=eval_id,
                    to_eval=next_id,
                    relation="NextEval",
                    evidence_strength="authoritative",
                    source_file=source,
                    source_detail=f"{eval_id}.NextEval={next_id}",
                ),
            )

        blocked_id = record.get("blocked_eval")
        if isinstance(blocked_id, str) and blocked_id:
            add_edge(
                rels,
                successors,
                predecessors,
                seen,
                EvalRelationship(
                    from_eval=eval_id,
                    to_eval=blocked_id,
                    relation="BlockedEval",
                    evidence_strength="authoritative",
                    source_file=source,
                    source_detail=f"{eval_id}.BlockedEval={blocked_id}",
                ),
            )

    return rels, successors, predecessors


def discover_connected(seed: str, successors, predecessors, max_depth: int):
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


def detect_cycles(nodes: set[str], successors):
    cycles = []
    visiting = set()
    visited = set()
    stack = []

    def dfs(node):
        if node in visiting:
            if node in stack:
                i = stack.index(node)
                cycles.append(stack[i:] + [node])
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


def canonical_paths(nodes, successors, predecessors, max_paths=50):
    roots = [
        node for node in nodes
        if not (predecessors.get(node, set()) & nodes)
    ]

    if not roots:
        roots = sorted(nodes)

    paths = []

    def walk(node, path, seen):
        if len(paths) >= max_paths:
            return

        nxts = sorted(successors.get(node, set()) & nodes)

        if not nxts:
            paths.append(path + [node])
            return

        for nxt in nxts:
            if nxt in seen:
                paths.append(path + [node, nxt])
                continue

            walk(nxt, path + [node], seen | {nxt})

    for root in sorted(roots):
        walk(root, [], {root})
        if len(paths) >= max_paths:
            break

    return paths


def related_allocations(connected_evals: set[str], allocations: dict[str, dict]):
    result = {}

    for alloc_id, alloc in allocations.items():
        if alloc.get("eval_id") in connected_evals:
            result[alloc_id] = alloc

    return result


def short_id(value: str) -> str:
    return value[:8] if value else ""


def md_escape(value: Any) -> str:
    return str(value or "").replace("|", r"\|").replace("\n", " ")


def write_csv(path: Path, connected, evaluations, predecessors, successors, depth_map, allocs_by_eval):
    fields = [
        "evaluation_id",
        "depth_from_seed",
        "create_time_utc",
        "modify_time_utc",
        "namespace",
        "job_id",
        "node_id",
        "deployment_id",
        "triggered_by",
        "status",
        "status_description",
        "previous_eval",
        "next_eval",
        "blocked_eval",
        "related_allocations",
        "first_seen_interval",
        "last_seen_interval",
        "source_count",
    ]

    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()

        rows = []
        for eval_id in connected:
            record = evaluations.get(eval_id, {"id": eval_id})
            rows.append(record)

        rows.sort(key=lambda x: (x.get("create_time_utc") or "", x.get("id") or ""))

        for record in rows:
            eval_id = record.get("id", "")
            writer.writerow({
                "evaluation_id": eval_id,
                "depth_from_seed": depth_map.get(eval_id, ""),
                "create_time_utc": record.get("create_time_utc", ""),
                "modify_time_utc": record.get("modify_time_utc", ""),
                "namespace": record.get("namespace", ""),
                "job_id": record.get("job_id", ""),
                "node_id": record.get("node_id", ""),
                "deployment_id": record.get("deployment_id", ""),
                "triggered_by": record.get("triggered_by", ""),
                "status": record.get("status", ""),
                "status_description": record.get("status_description", ""),
                "previous_eval": ",".join(sorted(predecessors.get(eval_id, set()) & connected)),
                "next_eval": ",".join(sorted(successors.get(eval_id, set()) & connected)),
                "blocked_eval": record.get("blocked_eval", "") or "",
                "related_allocations": ",".join(sorted(allocs_by_eval.get(eval_id, []))),
                "first_seen_interval": record.get("first_seen_interval", ""),
                "last_seen_interval": record.get("last_seen_interval", ""),
                "source_count": len(record.get("sources", [])),
            })


def write_markdown(
    path,
    seed_eval,
    seed_alloc,
    connected,
    evaluations,
    relationships,
    predecessors,
    successors,
    depth_map,
    related_allocs,
    allocs_by_eval,
    cycles,
    paths,
    missing_evals,
    stats,
):
    roots = sorted(
        node for node in connected
        if not (predecessors.get(node, set()) & connected)
    )

    leaves = sorted(
        node for node in connected
        if not (successors.get(node, set()) & connected)
    )

    branches = sorted(
        node for node in connected
        if len(successors.get(node, set()) & connected) > 1
    )

    with path.open("w", encoding="utf-8") as fh:
        fh.write(f"# Evaluation Trace: `{seed_eval}`\n\n")

        if seed_alloc:
            fh.write(f"- Seed allocation: `{seed_alloc}`\n")

        fh.write(f"- Connected evaluations: **{len(connected)}**\n")
        fh.write(f"- Relationship edges: **{len(relationships)}**\n")
        fh.write(f"- Related allocations: **{len(related_allocs)}**\n")
        fh.write(f"- Roots: **{len(roots)}**\n")
        fh.write(f"- Leaves: **{len(leaves)}**\n")
        fh.write(f"- Branch points: **{len(branches)}**\n")
        fh.write(f"- Cycles: **{len(cycles)}**\n")
        fh.write(f"- Referenced evaluations missing from captured state: **{len(missing_evals)}**\n\n")

        fh.write("## Evaluation Paths\n\n")

        for idx, chain in enumerate(paths, 1):
            rendered = " → ".join(
                f"`{short_id(x)}`" + (" **seed**" if x == seed_eval else "")
                for x in chain
            )
            fh.write(f"{idx}. {rendered}\n")

        if not paths:
            fh.write("No evaluation path could be constructed.\n")

        fh.write("\n## Evaluation State\n\n")
        fh.write(
            "| Evaluation | Depth | Created | Job | Trigger | Status | Previous | Next | Blocked | Allocations |\n"
        )
        fh.write("|---|---:|---|---|---|---|---|---|---|---|\n")

        rows = [
            evaluations.get(eval_id, {"id": eval_id})
            for eval_id in connected
        ]
        rows.sort(key=lambda x: (x.get("create_time_utc") or "", x.get("id") or ""))

        for record in rows:
            eval_id = record.get("id", "")
            prevs = sorted(predecessors.get(eval_id, set()) & connected)
            nexts = sorted(successors.get(eval_id, set()) & connected)
            alloc_ids = sorted(allocs_by_eval.get(eval_id, []))

            fh.write(
                f"| `{md_escape(eval_id)}`"
                f"{' **seed**' if eval_id == seed_eval else ''} | "
                f"{depth_map.get(eval_id, '')} | "
                f"{md_escape(record.get('create_time_utc', ''))} | "
                f"{md_escape(record.get('job_id', ''))} | "
                f"{md_escape(record.get('triggered_by', ''))} | "
                f"{md_escape(record.get('status', ''))} | "
                f"{', '.join(f'`{short_id(x)}`' for x in prevs)} | "
                f"{', '.join(f'`{short_id(x)}`' for x in nexts)} | "
                f"{md_escape(record.get('blocked_eval', ''))} | "
                f"{', '.join(f'`{short_id(x)}`' for x in alloc_ids)} |\n"
            )

        fh.write("\n## Evaluation Relationships\n\n")
        fh.write("| From | To | Relationship | Evidence | Source |\n")
        fh.write("|---|---|---|---|---|\n")

        for rel in relationships:
            fh.write(
                f"| `{md_escape(rel.from_eval)}` | "
                f"`{md_escape(rel.to_eval)}` | "
                f"{md_escape(rel.relation)} | "
                f"{md_escape(rel.evidence_strength)} | "
                f"`{md_escape(rel.source_file)}` |\n"
            )

        fh.write("\n## Related Allocations\n\n")

        if not related_allocs:
            fh.write("No captured allocations reference the connected evaluation set.\n")
        else:
            fh.write(
                "| Allocation | Evaluation | Job / Group | Node | Desired | Client | Created |\n"
            )
            fh.write("|---|---|---|---|---|---|---|\n")

            rows = list(related_allocs.values())
            rows.sort(key=lambda x: (x.get("create_time_utc") or "", x.get("id") or ""))

            for alloc in rows:
                fh.write(
                    f"| `{md_escape(alloc.get('id'))}` | "
                    f"`{md_escape(alloc.get('eval_id'))}` | "
                    f"{md_escape(alloc.get('job_id'))} / {md_escape(alloc.get('task_group'))} | "
                    f"`{md_escape(alloc.get('node_id'))}` | "
                    f"{md_escape(alloc.get('desired_status'))} | "
                    f"{md_escape(alloc.get('client_status'))} | "
                    f"{md_escape(alloc.get('create_time_utc'))} |\n"
                )

        if missing_evals:
            fh.write("\n## Referenced But Missing Evaluations\n\n")
            for eval_id in sorted(missing_evals):
                fh.write(
                    f"- `{eval_id}` is referenced by captured evaluation metadata, "
                    "but no state for it was present in the bundle.\n"
                )

        if cycles:
            fh.write("\n## Cycles\n\n")
            for cycle in cycles:
                fh.write("- " + " → ".join(f"`{x}`" for x in cycle) + "\n")

        fh.write("\n## Input Coverage\n\n")
        fh.write(f"- Interval captures: **{stats['intervals']}**\n")
        fh.write(f"- Evaluation records read: **{stats['evaluation_records']}**\n")
        fh.write(f"- Allocation records read: **{stats['allocation_records']}**\n")
        fh.write(f"- Evaluation JSON-lines files: **{stats['evaluation_json_lines_files']}**\n")
        fh.write(f"- Allocation JSON-lines files: **{stats['allocation_json_lines_files']}**\n")
        fh.write(f"- Empty evaluation files: **{stats['evaluation_empty_files']}**\n")
        fh.write(f"- Empty allocation files: **{stats['allocation_empty_files']}**\n\n")

        fh.write("## Notes\n\n")
        fh.write(
            "- `PreviousEval`, `NextEval`, and `BlockedEval` are treated as captured "
            "authoritative evaluation relationships.\n"
        )
        fh.write(
            "- Allocations are associated to evaluations only through captured `EvalID`; "
            "the tool does not infer evaluation ownership from job/time proximity.\n"
        )
        fh.write(
            "- A referenced-but-missing evaluation may predate or postdate the debug "
            "capture; the relationship is preserved rather than hidden.\n"
        )


def parse_args():
    parser = argparse.ArgumentParser(
        description="Trace Nomad evaluation chains from an eval ID or allocation ID."
    )

    parser.add_argument("bundle", type=Path)

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--eval", dest="eval_id")
    group.add_argument("--alloc", dest="alloc_id")

    parser.add_argument("--max-depth", type=int, default=50)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--overwrite", action="store_true")

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    root = args.bundle.expanduser().resolve()

    if not root.is_dir():
        print(f"ERROR: bundle directory does not exist: {root}", file=sys.stderr)
        return 2

    seed_input = args.eval_id or args.alloc_id

    if not UUID_RE.fullmatch(seed_input):
        print("ERROR: --eval/--alloc must be a full UUID.", file=sys.stderr)
        return 2

    if args.max_depth <= 0:
        print("ERROR: --max-depth must be greater than zero.", file=sys.stderr)
        return 2

    bundle_root = find_bundle_root(root)

    if bundle_root is None:
        print("ERROR: standard Nomad operator debug layout not detected.", file=sys.stderr)
        return 2

    base_output = (
        args.output.expanduser().resolve()
        if args.output
        else (root.parent / "analysis_eval_trace").resolve()
    )

    run_dir = base_output / seed_input

    if run_dir.exists():
        if not args.overwrite:
            print(
                f"ERROR: derived eval trace already exists: {run_dir}\n"
                "Use --overwrite to replace it.",
                file=sys.stderr,
            )
            return 2

        shutil.rmtree(run_dir)

    run_dir.mkdir(parents=True, exist_ok=True)

    print(f"Search root      : {root}")
    print(f"Bundle root      : {bundle_root}")
    print(f"Input type       : {'evaluation' if args.eval_id else 'allocation'}")
    print(f"Input ID         : {seed_input}")
    print(f"Max depth        : {args.max_depth}")
    print(f"Output directory : {run_dir}")
    print("Source artifacts are opened read-only.")
    print()

    evaluations, allocations, stats = collect_interval_data(bundle_root, root)
    event_counts = collect_eventstream(
        bundle_root, root, evaluations, allocations
    )

    seed_alloc = ""

    if args.alloc_id:
        seed_alloc = args.alloc_id
        alloc = allocations.get(args.alloc_id)

        if not alloc:
            print(
                f"ERROR: allocation {args.alloc_id} was not found in captured "
                "allocation state/eventstream.",
                file=sys.stderr,
            )
            return 3

        seed_eval = alloc.get("eval_id")

        if not isinstance(seed_eval, str) or not seed_eval:
            print(
                f"ERROR: allocation {args.alloc_id} does not contain a captured EvalID.",
                file=sys.stderr,
            )
            return 3

        print(f"Resolved EvalID  : {seed_eval}")
    else:
        seed_eval = args.eval_id

    relationships, successors, predecessors = build_relationships(evaluations)

    graph_nodes = set(evaluations)
    for rel in relationships:
        graph_nodes.add(rel.from_eval)
        graph_nodes.add(rel.to_eval)

    if seed_eval not in graph_nodes:
        print(
            "WARNING: seed evaluation was not found in captured state or "
            "evaluation relationship references.",
            file=sys.stderr,
        )
        connected = {seed_eval}
        depth_map = {seed_eval: 0}
    else:
        connected, depth_map = discover_connected(
            seed_eval,
            successors,
            predecessors,
            args.max_depth,
        )

    connected_relationships = [
        rel for rel in relationships
        if rel.from_eval in connected and rel.to_eval in connected
    ]

    missing_evals = {
        eval_id for eval_id in connected
        if eval_id not in evaluations
    }

    related_allocs = related_allocations(connected, allocations)

    allocs_by_eval = defaultdict(list)
    for alloc_id, alloc in related_allocs.items():
        eval_id = alloc.get("eval_id")
        if eval_id:
            allocs_by_eval[eval_id].append(alloc_id)

    cycles = detect_cycles(connected, successors)
    paths = canonical_paths(connected, successors, predecessors)

    eval_trace_csv = run_dir / "eval_trace.csv"
    eval_trace_md = run_dir / "eval_trace.md"

    write_csv(
        eval_trace_csv,
        connected,
        evaluations,
        predecessors,
        successors,
        depth_map,
        allocs_by_eval,
    )

    write_markdown(
        eval_trace_md,
        seed_eval,
        seed_alloc,
        connected,
        evaluations,
        connected_relationships,
        predecessors,
        successors,
        depth_map,
        related_allocs,
        allocs_by_eval,
        cycles,
        paths,
        missing_evals,
        stats,
    )

    eval_out = {}
    for eval_id in sorted(connected):
        record = dict(evaluations.get(eval_id, {"id": eval_id}))
        record["predecessors"] = sorted(predecessors.get(eval_id, set()) & connected)
        record["successors"] = sorted(successors.get(eval_id, set()) & connected)
        record["depth_from_seed"] = depth_map.get(eval_id)
        record["related_allocations"] = sorted(allocs_by_eval.get(eval_id, []))
        eval_out[eval_id] = record

    with (run_dir / "evaluations.json").open("w", encoding="utf-8") as fh:
        json.dump(eval_out, fh, indent=2)
        fh.write("\n")

    with (run_dir / "allocations.json").open("w", encoding="utf-8") as fh:
        json.dump(related_allocs, fh, indent=2)
        fh.write("\n")

    with (run_dir / "relationships.json").open("w", encoding="utf-8") as fh:
        json.dump([asdict(rel) for rel in connected_relationships], fh, indent=2)
        fh.write("\n")

    roots = [
        node for node in connected
        if not (predecessors.get(node, set()) & connected)
    ]

    leaves = [
        node for node in connected
        if not (successors.get(node, set()) & connected)
    ]

    branches = [
        node for node in connected
        if len(successors.get(node, set()) & connected) > 1
    ]

    summary = {
        "input_type": "evaluation" if args.eval_id else "allocation",
        "input_id": seed_input,
        "seed_evaluation": seed_eval,
        "seed_allocation": seed_alloc or None,
        "connected_evaluation_count": len(connected),
        "relationship_count": len(connected_relationships),
        "related_allocation_count": len(related_allocs),
        "roots": sorted(roots),
        "leaves": sorted(leaves),
        "branch_points": sorted(branches),
        "missing_evaluations": sorted(missing_evals),
        "cycles": cycles,
        "paths": paths,
        "input_stats": stats,
        "eventstream_counts": event_counts,
    }

    with (run_dir / "summary.json").open("w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
        fh.write("\n")

    print()
    print("Done.")
    print(f"  Seed evaluation       : {seed_eval}")
    print(f"  Connected evaluations : {len(connected)}")
    print(f"  Relationship edges    : {len(connected_relationships)}")
    print(f"  Related allocations   : {len(related_allocs)}")
    print(f"  Roots                 : {len(roots)}")
    print(f"  Leaves                : {len(leaves)}")
    print(f"  Branch points         : {len(branches)}")
    print(f"  Cycles                : {len(cycles)}")
    print(f"  Missing eval state    : {len(missing_evals)}")

    for rel in connected_relationships[:10]:
        print(
            f"    {rel.relation:<16} "
            f"{short_id(rel.from_eval)} -> {short_id(rel.to_eval)}"
        )

    if len(connected_relationships) > 10:
        print(f"    ... {len(connected_relationships) - 10} more relationship(s) in output files")

    print()
    print(f"Trace Markdown    : {eval_trace_md}")
    print(f"Trace CSV         : {eval_trace_csv}")
    print(f"Evaluations JSON  : {run_dir / 'evaluations.json'}")
    print(f"Allocations JSON  : {run_dir / 'allocations.json'}")
    print(f"Relationships JSON: {run_dir / 'relationships.json'}")
    print(f"Summary JSON      : {run_dir / 'summary.json'}")
    print()
    print("Tip: inspect eval_trace.md first.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
