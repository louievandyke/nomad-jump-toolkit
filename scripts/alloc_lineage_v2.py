#!/usr/bin/env python3
"""
alloc_lineage_v2.py

Trace Nomad allocation predecessor/replacement relationships across an unpacked
`nomad operator debug` bundle.

Version 2 improvements:
- Supports ordinary JSON, JSON arrays, wrapper objects, and multiple JSON
  documents/records per line in interval allocations.json files.
- Reports empty / unparseable allocation snapshots instead of silently skipping them.
- Adds lineage edges from RescheduleTracker.Events[].PrevAllocID / PrevNodeID.
- Keeps PreviousAllocation / NextAllocation edges when present.
- Distinguishes relationship evidence types instead of inferring lineage merely
  from job/group/time proximity.
- Preserves referenced-but-missing allocations in the graph.
- Detects branches and cycles.

Examples:
    python3 alloc_lineage_v2.py ./nomad-debug-2026-01-22-213719Z \
      --alloc 153de10e-8d03-4592-7c43-49bca569364e

    python3 alloc_lineage_v2.py ./bundle \
      --alloc 306d3777-9090-f8f5-e7b0-12aa25d0877b \
      --overwrite

Output:
    analysis_alloc_lineage/<alloc-id>/
      lineage.md
      lineage.csv
      allocations.json
      graph.json
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
class Relationship:
    from_alloc: str
    to_alloc: str
    relation: str
    evidence_strength: str
    source_type: str
    source_file: str
    source_detail: str
    previous_node_id: str = ""
    reschedule_time_utc: str = ""


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


def first_value(d: dict, keys: Iterable[str]) -> Any:
    for key in keys:
        if key in d:
            return d[key]
    return None


def expand_json_value(value: Any) -> list[dict]:
    if isinstance(value, list):
        return [x for x in value if isinstance(x, dict)]

    if isinstance(value, dict):
        for key in ("Allocations", "Items"):
            if isinstance(value.get(key), list):
                return [x for x in value[key] if isinstance(x, dict)]

        if first_value(value, ("ID", "AllocID", "AllocationID")):
            return [value]

    return []


def read_allocation_records(path: Path) -> tuple[list[dict], str]:
    """
    Return (records, parse_mode).

    parse_mode:
      empty
      json
      json-lines
      unparseable
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], "unparseable"

    if not text.strip():
        return [], "empty"

    try:
        value = json.loads(text)
        return expand_json_value(value), "json"
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
        records.extend(expand_json_value(value))

    if parsed_any:
        return records, "json-lines"

    return [], "unparseable"


def summarize_allocation(record: dict) -> dict:
    job = record.get("Job")

    job_id = first_value(record, ("JobID",))
    namespace = first_value(record, ("Namespace",))

    if isinstance(job, dict):
        job_id = job_id or first_value(job, ("ID", "Name"))
        namespace = namespace or first_value(job, ("Namespace",))

    create_dt = unixish_to_dt(
        first_value(record, ("CreateTime", "CreateTimestamp", "CreatedAt"))
    )
    modify_dt = unixish_to_dt(
        first_value(record, ("ModifyTime", "ModifyTimestamp", "UpdatedAt"))
    )

    return {
        "id": str(first_value(record, ("ID", "AllocID", "AllocationID")) or ""),
        "job_id": job_id,
        "namespace": namespace,
        "task_group": first_value(record, ("TaskGroup", "TaskGroupName")),
        "node_id": first_value(record, ("NodeID",)),
        "node_name": first_value(record, ("NodeName",)),
        "eval_id": first_value(record, ("EvalID",)),
        "deployment_id": first_value(record, ("DeploymentID",)),
        "desired_status": first_value(record, ("DesiredStatus",)),
        "client_status": first_value(record, ("ClientStatus",)),
        "previous_allocation": first_value(
            record, ("PreviousAllocation", "PreviousAllocID")
        ),
        "next_allocation": first_value(
            record, ("NextAllocation", "NextAllocID")
        ),
        "create_time_utc": iso(create_dt),
        "modify_time_utc": iso(modify_dt),
        "client_description": first_value(record, ("ClientDescription",)),
        "desired_description": first_value(record, ("DesiredDescription",)),
        "reschedule_tracker": record.get("RescheduleTracker"),
        "desired_transition": record.get("DesiredTransition"),
    }


def merge_allocation(existing: dict, incoming: dict, source_file: str, interval_id: str) -> dict:
    if not existing:
        result = dict(incoming)
        result["first_seen_interval"] = interval_id
        result["last_seen_interval"] = interval_id
        result["sources"] = [source_file]
        return result

    result = dict(existing)

    for key, value in incoming.items():
        if value not in (None, "", [], {}):
            result[key] = value

    result["last_seen_interval"] = interval_id

    sources = list(result.get("sources", []))
    if source_file not in sources:
        sources.append(source_file)

    result["sources"] = sources
    return result


def collect_interval_allocations(
    bundle_root: Path,
    root: Path,
) -> tuple[dict[str, dict], dict[str, int]]:
    allocations: dict[str, dict] = {}
    interval_root = bundle_root / "interval"

    interval_dirs = sorted(
        p for p in interval_root.iterdir()
        if p.is_dir() and p.name.isdigit()
    )

    stats = {
        "intervals": len(interval_dirs),
        "allocation_files": 0,
        "empty_files": 0,
        "json_files": 0,
        "json_lines_files": 0,
        "unparseable_files": 0,
        "records_read": 0,
    }

    print(f"Inspecting {len(interval_dirs)} interval allocation snapshot(s)...")

    for interval_dir in interval_dirs:
        path = interval_dir / "allocations.json"

        if not path.is_file():
            continue

        stats["allocation_files"] += 1

        records, mode = read_allocation_records(path)

        if mode == "empty":
            stats["empty_files"] += 1
        elif mode == "json":
            stats["json_files"] += 1
        elif mode == "json-lines":
            stats["json_lines_files"] += 1
        else:
            stats["unparseable_files"] += 1

        stats["records_read"] += len(records)

        for record in records:
            summary = summarize_allocation(record)
            alloc_id = summary["id"]

            if not alloc_id:
                continue

            allocations[alloc_id] = merge_allocation(
                allocations.get(alloc_id, {}),
                summary,
                str(path.relative_to(root)),
                interval_dir.name,
            )

    print(f"Unique allocations found : {len(allocations)}")
    print(f"Allocation records read   : {stats['records_read']}")

    if stats["json_lines_files"]:
        print(f"JSON-lines snapshot files : {stats['json_lines_files']}")

    if stats["empty_files"]:
        print(f"Empty snapshot files      : {stats['empty_files']}")

    if stats["unparseable_files"]:
        print(f"Unparseable snapshot files: {stats['unparseable_files']}")

    return allocations, stats


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


def collect_eventstream_allocations(
    bundle_root: Path,
    root: Path,
    allocations: dict[str, dict],
) -> dict[str, dict]:
    path = bundle_root / "cluster" / "eventstream.json"

    if not path.is_file():
        return allocations

    print("Parsing cluster/eventstream.json for allocation metadata...")

    matched = 0

    for line_no, record in iter_eventstream(path):
        payload = record.get("Payload")

        if not isinstance(payload, dict):
            continue

        alloc = payload.get("Allocation")

        if not isinstance(alloc, dict):
            continue

        summary = summarize_allocation(alloc)
        alloc_id = summary["id"]

        if not alloc_id:
            continue

        matched += 1
        source_file = f"{path.relative_to(root)}:{line_no}"

        existing = allocations.get(alloc_id, {})

        if not existing:
            result = dict(summary)
            result["first_seen_interval"] = ""
            result["last_seen_interval"] = ""
            result["sources"] = [source_file]
            allocations[alloc_id] = result
            continue

        result = dict(existing)

        for key, value in summary.items():
            if value not in (None, "", [], {}) and result.get(key) in (None, "", [], {}):
                result[key] = value

        sources = list(result.get("sources", []))

        if source_file not in sources:
            sources.append(source_file)

        result["sources"] = sources
        allocations[alloc_id] = result

    print(f"Allocation event-stream records: {matched}")
    return allocations


def add_edge(
    relationships: list[Relationship],
    successors: dict[str, set[str]],
    predecessors: dict[str, set[str]],
    seen_edges: set[tuple[str, str, str]],
    relationship: Relationship,
) -> None:
    key = (relationship.from_alloc, relationship.to_alloc, relationship.relation)

    if key in seen_edges:
        return

    seen_edges.add(key)
    relationships.append(relationship)
    successors[relationship.from_alloc].add(relationship.to_alloc)
    predecessors[relationship.to_alloc].add(relationship.from_alloc)


def build_relationships(
    allocations: dict[str, dict]
) -> tuple[list[Relationship], dict[str, set[str]], dict[str, set[str]]]:
    relationships: list[Relationship] = []
    successors: dict[str, set[str]] = defaultdict(set)
    predecessors: dict[str, set[str]] = defaultdict(set)
    seen_edges: set[tuple[str, str, str]] = set()

    for alloc_id, record in allocations.items():
        source_file = ", ".join(record.get("sources", [])[:3])

        prev_id = record.get("previous_allocation")

        if isinstance(prev_id, str) and prev_id:
            add_edge(
                relationships,
                successors,
                predecessors,
                seen_edges,
                Relationship(
                    from_alloc=prev_id,
                    to_alloc=alloc_id,
                    relation="PreviousAllocation",
                    evidence_strength="authoritative",
                    source_type="allocation_state",
                    source_file=source_file,
                    source_detail=f"{alloc_id}.PreviousAllocation={prev_id}",
                ),
            )

        next_id = record.get("next_allocation")

        if isinstance(next_id, str) and next_id:
            add_edge(
                relationships,
                successors,
                predecessors,
                seen_edges,
                Relationship(
                    from_alloc=alloc_id,
                    to_alloc=next_id,
                    relation="NextAllocation",
                    evidence_strength="authoritative",
                    source_type="allocation_state",
                    source_file=source_file,
                    source_detail=f"{alloc_id}.NextAllocation={next_id}",
                ),
            )

        tracker = record.get("reschedule_tracker")

        if isinstance(tracker, dict):
            events = tracker.get("Events")

            if isinstance(events, list):
                for event in events:
                    if not isinstance(event, dict):
                        continue

                    previous_id = event.get("PrevAllocID")

                    if not isinstance(previous_id, str) or not previous_id:
                        continue

                    reschedule_dt = unixish_to_dt(event.get("RescheduleTime"))

                    add_edge(
                        relationships,
                        successors,
                        predecessors,
                        seen_edges,
                        Relationship(
                            from_alloc=previous_id,
                            to_alloc=alloc_id,
                            relation="RescheduleTracker.PrevAllocID",
                            evidence_strength="authoritative",
                            source_type="reschedule_tracker",
                            source_file=source_file,
                            source_detail=(
                                f"{alloc_id}.RescheduleTracker references "
                                f"previous allocation {previous_id}"
                            ),
                            previous_node_id=str(event.get("PrevNodeID") or ""),
                            reschedule_time_utc=iso(reschedule_dt),
                        ),
                    )

    return relationships, successors, predecessors


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


def allocation_sort_key(record: dict) -> tuple:
    return (
        record.get("create_time_utc") or "",
        record.get("id") or "",
    )


def md_escape(value: Any) -> str:
    return str(value or "").replace("|", r"\|").replace("\n", " ")


def short_id(value: str) -> str:
    return value[:8] if value else ""


def write_csv(
    path: Path,
    connected: set[str],
    allocations: dict[str, dict],
    predecessors: dict[str, set[str]],
    successors: dict[str, set[str]],
    depth_map: dict[str, int],
) -> None:
    fields = [
        "allocation_id",
        "depth_from_seed",
        "job_id",
        "namespace",
        "task_group",
        "node_id",
        "node_name",
        "eval_id",
        "deployment_id",
        "desired_status",
        "client_status",
        "create_time_utc",
        "modify_time_utc",
        "predecessors",
        "successors",
        "first_seen_interval",
        "last_seen_interval",
        "source_count",
    ]

    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()

        records = [
            allocations.get(alloc_id, {"id": alloc_id})
            for alloc_id in connected
        ]

        records.sort(key=allocation_sort_key)

        for record in records:
            alloc_id = record.get("id", "")

            writer.writerow(
                {
                    "allocation_id": alloc_id,
                    "depth_from_seed": depth_map.get(alloc_id, ""),
                    "job_id": record.get("job_id", ""),
                    "namespace": record.get("namespace", ""),
                    "task_group": record.get("task_group", ""),
                    "node_id": record.get("node_id", ""),
                    "node_name": record.get("node_name", ""),
                    "eval_id": record.get("eval_id", ""),
                    "deployment_id": record.get("deployment_id", ""),
                    "desired_status": record.get("desired_status", ""),
                    "client_status": record.get("client_status", ""),
                    "create_time_utc": record.get("create_time_utc", ""),
                    "modify_time_utc": record.get("modify_time_utc", ""),
                    "predecessors": ",".join(sorted(predecessors.get(alloc_id, set()) & connected)),
                    "successors": ",".join(sorted(successors.get(alloc_id, set()) & connected)),
                    "first_seen_interval": record.get("first_seen_interval", ""),
                    "last_seen_interval": record.get("last_seen_interval", ""),
                    "source_count": len(record.get("sources", [])),
                }
            )


def write_markdown(
    path: Path,
    seed: str,
    connected: set[str],
    allocations: dict[str, dict],
    relationships: list[Relationship],
    predecessors: dict[str, set[str]],
    successors: dict[str, set[str]],
    depth_map: dict[str, int],
    cycles: list[list[str]],
    paths: list[list[str]],
    missing_nodes: set[str],
    stats: dict[str, int],
) -> None:
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
        fh.write(f"# Allocation Lineage: `{seed}`\n\n")
        fh.write(f"- Connected allocations: **{len(connected)}**\n")
        fh.write(f"- Relationship edges: **{len(relationships)}**\n")
        fh.write(f"- Roots: **{len(roots)}**\n")
        fh.write(f"- Leaves: **{len(leaves)}**\n")
        fh.write(f"- Branch points: **{len(branches)}**\n")
        fh.write(f"- Cycles detected: **{len(cycles)}**\n")
        fh.write(f"- Referenced allocations missing from captured state: **{len(missing_nodes)}**\n")
        fh.write(f"- Allocation records read: **{stats.get('records_read', 0)}**\n")
        fh.write(f"- JSON-lines allocation files: **{stats.get('json_lines_files', 0)}**\n")
        fh.write(f"- Empty allocation files: **{stats.get('empty_files', 0)}**\n")
        fh.write(f"- Unparseable allocation files: **{stats.get('unparseable_files', 0)}**\n\n")

        fh.write("## Lineage Paths\n\n")

        if paths:
            for idx, chain in enumerate(paths, 1):
                rendered = " → ".join(
                    f"`{short_id(node)}`"
                    + (" **(seed)**" if node == seed else "")
                    for node in chain
                )
                fh.write(f"{idx}. {rendered}\n")
        else:
            fh.write("No predecessor/successor path could be constructed.\n")

        fh.write("\n## Allocation State\n\n")
        fh.write(
            "| Allocation | Depth | Created | Job / Group | Node | Desired | Client | "
            "Previous | Next |\n"
        )
        fh.write("|---|---:|---|---|---|---|---|---|---|\n")

        records = [
            allocations.get(alloc_id, {"id": alloc_id})
            for alloc_id in connected
        ]

        records.sort(key=allocation_sort_key)

        for record in records:
            alloc_id = record.get("id", "")
            prevs = sorted(predecessors.get(alloc_id, set()) & connected)
            nexts = sorted(successors.get(alloc_id, set()) & connected)

            fh.write(
                f"| `{md_escape(alloc_id)}`"
                f"{' **seed**' if alloc_id == seed else ''} | "
                f"{depth_map.get(alloc_id, '')} | "
                f"{md_escape(record.get('create_time_utc', ''))} | "
                f"{md_escape(record.get('job_id', ''))} / "
                f"{md_escape(record.get('task_group', ''))} | "
                f"`{md_escape(record.get('node_id', ''))}` | "
                f"{md_escape(record.get('desired_status', ''))} | "
                f"{md_escape(record.get('client_status', ''))} | "
                f"{', '.join(f'`{short_id(x)}`' for x in prevs)} | "
                f"{', '.join(f'`{short_id(x)}`' for x in nexts)} |\n"
            )

        fh.write("\n## Relationships\n\n")
        fh.write(
            "| From | To | Relationship | Evidence | Reschedule Time | Previous Node | Source |\n"
        )
        fh.write("|---|---|---|---|---|---|---|\n")

        for rel in relationships:
            fh.write(
                f"| `{md_escape(rel.from_alloc)}` | "
                f"`{md_escape(rel.to_alloc)}` | "
                f"{md_escape(rel.relation)} | "
                f"{md_escape(rel.evidence_strength)} | "
                f"{md_escape(rel.reschedule_time_utc)} | "
                f"`{md_escape(rel.previous_node_id)}` | "
                f"`{md_escape(rel.source_file)}` |\n"
            )

        if missing_nodes:
            fh.write("\n## Referenced But Missing Allocations\n\n")

            for alloc_id in sorted(missing_nodes):
                fh.write(
                    f"- `{alloc_id}` is referenced by authoritative lineage metadata, "
                    "but no captured allocation state for it was found.\n"
                )

        if branches:
            fh.write("\n## Branch Points\n\n")

            for alloc_id in branches:
                children = sorted(successors.get(alloc_id, set()) & connected)
                fh.write(
                    f"- `{alloc_id}` has {len(children)} captured successors: "
                    + ", ".join(f"`{child}`" for child in children)
                    + "\n"
                )

        if cycles:
            fh.write("\n## Cycles\n\n")

            for cycle in cycles:
                fh.write("- " + " → ".join(f"`{x}`" for x in cycle) + "\n")

        fh.write("\n## Notes\n\n")
        fh.write(
            "- `PreviousAllocation`, `NextAllocation`, and "
            "`RescheduleTracker.Events[].PrevAllocID` are treated as authoritative "
            "captured lineage evidence.\n"
        )
        fh.write(
            "- Allocations are not linked merely because they share a job/task group "
            "or appear close together in time.\n"
        )
        fh.write(
            "- Missing predecessor state may simply mean the predecessor predates the "
            "debug capture; the reference itself is preserved.\n"
        )


def write_json_outputs(
    run_dir: Path,
    seed: str,
    connected: set[str],
    allocations: dict[str, dict],
    relationships: list[Relationship],
    predecessors: dict[str, set[str]],
    successors: dict[str, set[str]],
    depth_map: dict[str, int],
    cycles: list[list[str]],
    paths: list[list[str]],
    missing_nodes: set[str],
    stats: dict[str, int],
) -> None:
    alloc_out = {}

    for alloc_id in sorted(connected):
        record = dict(allocations.get(alloc_id, {"id": alloc_id}))
        record["predecessors"] = sorted(predecessors.get(alloc_id, set()) & connected)
        record["successors"] = sorted(successors.get(alloc_id, set()) & connected)
        record["depth_from_seed"] = depth_map.get(alloc_id)
        alloc_out[alloc_id] = record

    with (run_dir / "allocations.json").open("w", encoding="utf-8") as fh:
        json.dump(alloc_out, fh, indent=2)
        fh.write("\n")

    graph = {
        "seed": seed,
        "nodes": sorted(connected),
        "edges": [asdict(rel) for rel in relationships],
        "paths": paths,
        "cycles": cycles,
    }

    with (run_dir / "graph.json").open("w", encoding="utf-8") as fh:
        json.dump(graph, fh, indent=2)
        fh.write("\n")

    summary = {
        "seed_allocation": seed,
        "connected_allocation_count": len(connected),
        "relationship_count": len(relationships),
        "missing_allocations": sorted(missing_nodes),
        "cycles": cycles,
        "paths": paths,
        "input_stats": stats,
    }

    with (run_dir / "summary.json").open("w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
        fh.write("\n")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Trace Nomad allocation predecessor/replacement lineage."
    )

    parser.add_argument("bundle", type=Path)
    parser.add_argument("--alloc", required=True)
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

    if not UUID_RE.fullmatch(args.alloc):
        print("ERROR: --alloc must be a full allocation UUID.", file=sys.stderr)
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
        else (root.parent / "analysis_alloc_lineage").resolve()
    )

    run_dir = base_output / args.alloc

    if run_dir.exists():
        if not args.overwrite:
            print(
                f"ERROR: derived lineage report already exists: {run_dir}\n"
                "Use --overwrite to replace it.",
                file=sys.stderr,
            )
            return 2

        shutil.rmtree(run_dir)

    run_dir.mkdir(parents=True, exist_ok=True)

    print(f"Search root      : {root}")
    print(f"Bundle root      : {bundle_root}")
    print(f"Seed allocation  : {args.alloc}")
    print(f"Max depth        : {args.max_depth}")
    print(f"Output directory : {run_dir}")
    print("Source artifacts are opened read-only.")
    print()

    allocations, stats = collect_interval_allocations(bundle_root, root)
    allocations = collect_eventstream_allocations(bundle_root, root, allocations)

    relationships, successors, predecessors = build_relationships(allocations)

    all_graph_nodes = set(allocations)

    for rel in relationships:
        all_graph_nodes.add(rel.from_alloc)
        all_graph_nodes.add(rel.to_alloc)

    if args.alloc not in all_graph_nodes:
        print(
            "WARNING: seed allocation was not found in captured state or lineage references.",
            file=sys.stderr,
        )
        connected = {args.alloc}
        depth_map = {args.alloc: 0}
    else:
        connected, depth_map = discover_connected(
            args.alloc,
            successors,
            predecessors,
            args.max_depth,
        )

    connected_relationships = [
        rel for rel in relationships
        if rel.from_alloc in connected and rel.to_alloc in connected
    ]

    missing_nodes = {
        node for node in connected
        if node not in allocations
    }

    cycles = detect_cycles(connected, successors)
    paths = canonical_paths(
        connected,
        successors,
        predecessors,
    )

    lineage_md = run_dir / "lineage.md"
    lineage_csv = run_dir / "lineage.csv"

    write_csv(
        lineage_csv,
        connected,
        allocations,
        predecessors,
        successors,
        depth_map,
    )

    write_markdown(
        lineage_md,
        args.alloc,
        connected,
        allocations,
        connected_relationships,
        predecessors,
        successors,
        depth_map,
        cycles,
        paths,
        missing_nodes,
        stats,
    )

    write_json_outputs(
        run_dir,
        args.alloc,
        connected,
        allocations,
        connected_relationships,
        predecessors,
        successors,
        depth_map,
        cycles,
        paths,
        missing_nodes,
        stats,
    )

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

    print()
    print("Done.")
    print(f"  Connected allocations : {len(connected)}")
    print(f"  Relationship edges    : {len(connected_relationships)}")
    print(f"  Roots                 : {len(roots)}")
    print(f"  Leaves                : {len(leaves)}")
    print(f"  Branch points         : {len(branches)}")
    print(f"  Cycles                : {len(cycles)}")
    print(f"  Missing alloc state   : {len(missing_nodes)}")

    for rel in connected_relationships:
        print(
            f"    {rel.relation:<32} "
            f"{rel.from_alloc[:8]} -> {rel.to_alloc[:8]}"
        )

    print()
    print(f"Lineage Markdown : {lineage_md}")
    print(f"Lineage CSV      : {lineage_csv}")
    print(f"Allocations JSON : {run_dir / 'allocations.json'}")
    print(f"Graph JSON       : {run_dir / 'graph.json'}")
    print(f"Summary JSON     : {run_dir / 'summary.json'}")
    print()
    print("Tip: inspect lineage.md first; missing predecessor state is preserved explicitly.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
