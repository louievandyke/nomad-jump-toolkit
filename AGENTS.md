# AGENTS.md

## Purpose

This file contains operating rules for any AI or coding agent working on the Nomad Jump Toolkit.

Read this file and `README.md` before modifying the project.

## Project Intent

Build small, reusable, offline forensic tools for `nomad operator debug` bundles that can be copied to restricted customer jump boxes.

The toolkit should help an engineer move from raw bundle artifacts to defensible evidence without altering customer data or flooding the terminal.

## Non-Negotiable Rules

### Source data is read-only

Never modify files under `bundles/` or any user-supplied Nomad debug bundle.

Open source artifacts read-only. Write all derived files to `analysis/` or another explicitly derived output directory.

### No network dependency

Assume the target jump box has no internet access.

Do not add dependencies that require downloads, package managers, external APIs, SaaS services, remote models, or network calls.

Prefer Python 3 standard library.

### Keep stdout bounded

Do not print entire large JSON files, minified payloads, recursive grep output, full goroutine dumps, or unbounded log matches.

Summarize counts and print only small, useful samples. Put complete derived results in CSV, JSON, or Markdown files.

### Preserve provenance

Every conclusion should retain enough source information to show where it came from.

When practical, derived records should include:

- source artifact
- interval/capture
- host or role
- source line for line-oriented artifacts
- evidence type

Do not erase contradictory or partial evidence merely to simplify a report.

### Distinguish observation time from state-change time

A timestamp recorded inside a Nomad object is not necessarily the same thing as the interval capture time.

Do not substitute `ModifyTime` for snapshot observation time or otherwise blur these concepts.

### Do not invent relationships

Only label a Nomad relationship authoritative when it is supported by explicit captured evidence.

Examples of acceptable authoritative fields include:

- `PreviousAllocation`
- `NextAllocation`
- `RescheduleTracker.Events[].PrevAllocID`
- `PreviousEval`
- `NextEval`
- `BlockedEval`
- allocation `EvalID`

Do not claim two allocations or evaluations are directly related merely because they share a job, task group, node, or nearby timestamps.

If heuristic/candidate relationships are ever added, label them clearly as inferred/candidate and keep them separate from authoritative edges.

### Preserve missing references

If captured state references an allocation/evaluation that is absent from the bundle, keep the referenced ID in the output and mark its state as missing.

Do not silently discard broken or out-of-window relationships.

## Parsing Rules

Nomad debug artifacts vary across versions and environments.

A parser should tolerate, where relevant:

- ordinary JSON object
- ordinary JSON array
- wrapper objects such as `Allocations`, `Evaluations`, or `Items`
- JSON-lines / multiple JSON documents
- empty files
- partially missing fields
- eventstream records

A `.json` suffix is not proof that the file contains one conventional JSON document.

Parsing failures should be counted and reported. Do not silently treat an unparseable file as valid empty data.

## Monitor Log Rules

When correlating monitor logs:

- parse timestamps carefully, including offsets such as `-0700`
- suppress known operator-debug self-observation traffic by default when it creates noise
- retain an option to include that traffic when needed
- collapse identical multi-source log events only when the normalization is defensible
- never let generic identifier matching pull in large profiling/debug text blobs

## Script Design

Scripts should generally:

- run with `python3`
- use `argparse`
- provide useful `--help`
- accept either an unpacked bundle root or a parent directory containing one unambiguous bundle
- refuse destructive overwrite unless `--overwrite` is provided
- produce deterministic output directories when practical
- exit non-zero on invalid input or unrecoverable errors
- give a short terminal summary and point to the main Markdown report
- avoid hidden mutation of source or previous analysis

Prefer clear standalone scripts over a large framework until repeated code is stable enough to justify shared modules.

## Output Conventions

Prefer:

```text
analysis_<tool>/<seed-or-window>/
    report.md
    report.csv
    supporting.json
    summary.json
```

The exact filenames can vary by tool, but outputs should be easy to inspect and easy for another script or agent to consume.

Markdown should prioritize forensic usefulness over visual decoration.

CSV should contain normalized fields suitable for filtering.

JSON should retain richer provenance and relationships.

## Current Validated Scripts

Treat these as known-good baselines unless a test demonstrates a defect:

- `inventory_bundle_v2.py`
- `find_identifiers_v2.py`
- `extract_window_v2.py`
- `alloc_lifecycle_v2.py`
- `correlate_timeline_v2.py`
- `alloc_lineage_v2.py`
- `eval_trace.py`

Do not casually rewrite or replace a validated script. If making a substantial change:

1. preserve the current working copy
2. make the change explicitly
3. test it against representative bundles
4. compare behavior with the prior version
5. only then consider the new version the baseline

## Known Bundle/Test Characteristics

The local test corpus may contain bundles with different serialization and evidence quality.

Important cases already encountered include:

- standard JSON interval data
- JSON-lines / multiple JSON documents in `allocations.json` and `evaluations.json`
- zero-byte allocation snapshots
- bundles with no useful lineage
- allocation lineage visible only through `RescheduleTracker`
- eval chains whose previous eval is referenced but outside the captured state
- eventstream data that supplements interval snapshots

Do not optimize a parser for only one bundle shape.

## Forensic Language

Use precise wording:

Prefer:

- "captured"
- "observed"
- "referenced"
- "authoritative field"
- "missing from captured state"
- "candidate/inferred"
- "suppressed debug-collection noise"

Avoid unsupported claims such as:

- "caused by" when evidence only shows correlation
- "replacement" when no lineage field supports it
- "missing" when the artifact may simply fall outside the capture window
- "corrupt" when a different serialization format may explain parsing

## Before Starting New Work

1. Read `README.md`.
2. Read this file.
3. Inspect `scripts/` before creating a new implementation.
4. Identify which bundle artifacts actually support the requested conclusion.
5. Reuse validated parsing/safety patterns.
6. Keep customer/source data untouched.
7. Test on at least one representative bundle before calling the work complete.

## Planned Direction

Likely future tools include:

- job allocation/count auditing
- event-rate analysis
- anomaly scanning

These should follow the same read-only, offline, bounded-output, provenance-first design.
