# AGENTS.md

## Purpose

This file contains operating rules for any AI or coding agent working on the Nomad Jump Toolkit.

Read this file and `README.md` before modifying the project.

## Project Intent

Build small, reusable, offline forensic tools for `nomad operator debug` bundles that can be copied to restricted customer jump boxes.

The toolkit should help an engineer move from raw bundle artifacts to defensible evidence without altering customer data or flooding the terminal.

## Origin

These rules are not generic engineering caution — they come from a real production
incident investigation. Early in that investigation, a customer's own account of
what caused the incident looked plausible and matched the surface-level timeline,
but cross-checking primary timestamps against the actual graphs showed the
suspected cause started complaining only *after* the real trigger was already
underway. Getting from the plausible-but-wrong story to the actual causal chain
took weeks of manual log correlation, much of it fighting terminal output limits
and half-remembered field semantics rather than the analysis itself.

Every non-negotiable rule below maps to a specific way that process went wrong
before it went right: unbounded output that buried the signal, a metric read at
the wrong scale, a relationship assumed from timing instead of an authoritative
field, evidence quietly dropped because it didn't fit the working theory. Treat
these rules as load-bearing, not stylistic — relaxing one reintroduces a failure
mode this toolkit exists to prevent.

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

- `_bundlelib.py` (shared helpers; not a standalone tool, imported by all seven below)
- `inventory_bundle_v2.py`
- `find_identifiers_v2.py`
- `extract_window_v2.py`
- `alloc_lifecycle_v2.py`
- `correlate_timeline_v2.py`
- `alloc_lineage_v2.py`
- `eval_trace.py`

`_bundlelib.py` must stay next to the scripts that import it (`import _bundlelib`
relies on Python putting the executed script's own directory on `sys.path`).
Any change to it is a change to all seven scripts at once: follow the same
preserve/test/compare process below, and re-run every script against a
representative bundle, not just the one that motivated the change.

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

## Shared Module Extraction (2026-08-17)

The duplication previously logged here was extracted into `_bundlelib.py`
after auditing all 7 scripts function-by-function, reconciling every
behavioral difference deliberately, and testing the result against
`bundles/nomad-debug-test` (before/after diffs on every output file for
every script; identical unless a fix is listed below).

Genuinely domain-specific code was deliberately left duplicated rather than
forced into a shared abstraction: `add_edge`/`build_relationships` in
`alloc_lineage_v2.py` and `eval_trace.py` build different edge types from
different Nomad fields and read different dataclass field names
(`from_alloc`/`to_alloc` vs `from_eval`/`to_eval`) — only the
domain-agnostic graph traversal beneath them (`discover_connected`,
`detect_cycles`, `canonical_paths`, confirmed byte-identical modulo
variable names) moved to `_bundlelib.py`. Sample/excerpt truncation
(`sample_around_match`, `excerpt_around`, `excerpt`) and log-line
classification (`classify_monitor_line`, `classify_log`) were also left
local: each has genuinely different signatures or taxonomy per tool, and
unifying truncation logic that touches evidence sample text is exactly the
kind of "silently pick one variant" risk this process exists to avoid.

Consolidating the duplication surfaced defects that had already resulted
from four/five copies of the same logic drifting apart — not hypothetical
risks, confirmed by diffing real output against `bundles/nomad-debug-test`:

- **`correlate_timeline_v2.py` silently dropped interval-snapshot evidence
  on JSON-lines bundles.** Unlike the other scripts, it read
  `allocations.json`/`evaluations.json`/`nodes.json` with a single
  `json.loads()` and no JSON-lines fallback — a shape this project's own
  "Known Bundle/Test Characteristics" section documents as real. Against
  the test bundle (whose `evaluations.json` files are JSON-lines) this
  silently produced 0 of 10 interval observations for a traced evaluation.
  After the fix: 10 of 10, and the JSON-lines file count is now printed
  and included in `summary.json`. This is the one violating AGENTS.md's
  own "parsing failures should be counted and reported" rule in the wild.
- **`extract_window_v2.py` could double-count a timestamp and mis-window a
  log line.** Its `timestamps_in_text()` was the one copy (of five) that
  didn't mask overlapping regex spans, so an offset-qualified monitor.log
  timestamp like `...T10:18:17.883-0700` could also match the trailing
  naive-timestamp pattern and yield a second, wrong-by-the-offset reading
  of the same instant. A monitor.log line could then be included in (or
  excluded from) an extracted window based on the spurious reading instead
  of the correct one.
- **`inventory_bundle_v2.py` under-detected and mis-labeled timestamps.**
  Its `TIMESTAMP_PATTERNS` list was missing the offset-without-colon and
  `... UTC` forms the other four scripts already had, and its timestamp
  parser didn't apply an offset even when one was captured elsewhere —
  so a monitor.log line's detected first/last timestamp could be silently
  off by the local UTC offset (confirmed on the test bundle: a `-0700`
  monitor.log timestamp was reported as if it were already UTC).
- **`alloc_lineage_v2.py` and `eval_trace.py`'s `unixish_to_dt()` silently
  failed on more timestamp string forms** than `alloc_lifecycle_v2.py`'s
  and `correlate_timeline_v2.py`'s copies (no offset-without-colon or
  `... UTC` handling for string-typed CreateTime/ModifyTime fields).
- **`md_escape()` could blank out a legitimate falsy value.** Two of the
  seven copies used `str(value or "")`, which also empties `0`/`False`,
  not just `None` — a retry count or exit code of 0 would silently vanish
  from a Markdown table instead of being shown, contradicting "do not
  erase contradictory or partial evidence."
- **`find_bundle_root()`'s missing `try/except OSError`** (one of four
  copies, formerly in `correlate_timeline_v2.py`) would have raised an
  unhandled exception and dumped a Python traceback instead of the tool's
  normal bounded error output, if bundle-root iteration ever hit a
  permission error.

None of these were hypothetical: each is the direct, predictable result of
copy-paste-and-adapt across seven scripts over time, which is exactly what
this section warned about before the extraction. See `_bundlelib.py`'s
module docstring and per-function docstrings for the reconciliation
rationale on each one.

## Real-World Bundle Validation (2026-08-17)

After the `_bundlelib.py` extraction above, the local bundle corpus grew to
include three real-world bundles from actual incidents (previously only the
synthetic `bundles/nomad-debug-test` was present locally). All 7 scripts
were run against all of them as a regression pass:

- `nomad-debug-2026-01-22-213719Z` — `allocations.json`/`evaluations.json`
  are JSON-lines in every interval. `eval_trace.py` reproduced a known-good
  historical result exactly (same resolved eval, same missing
  `PreviousEval`). `correlate_timeline_v2.py`'s JSON-lines fix (see above)
  held up on this independent bundle too.
- `nomad-debug-2026-02-04-153233Z` — `allocations.json` is genuinely
  zero-byte in every interval; confirmed as the already-documented
  zero-byte case below, not a defect.
- `nomad-debug-2026-07-27-214257Z` — ordinary single-JSON format; used as a
  positive control.

This surfaced one more real defect, not caused by the `_bundlelib.py` work
(this code path was never touched by that extraction) but caught because a
JSON-lines bundle finally exercised it:

- **`alloc_lifecycle_v2.py`'s `collect_snapshots()` silently returned zero
  interval snapshots on JSON-lines bundles.** It parsed each interval's
  `allocations.json` with a single-document `json.load()` and caught
  `JSONDecodeError` with a bare `continue` — so for
  `nomad-debug-2026-01-22-213719Z`, an allocation present in all 12
  intervals (confirmed via `alloc_lineage_v2.py`/`eval_trace.py`) reported
  "present in 0 interval snapshot(s)", silently, for every interval. Fixed
  by adding `_bundlelib.parse_json_documents()` — a JSON/JSON-lines-tolerant
  parser that returns raw top-level values instead of flattened records,
  since this script's `find_alloc_objects()` needs to recurse into
  arbitrary nested structure itself rather than receive normalized records.
  Verified: 0 → 12 snapshots on the real bundle; unchanged (still
  byte-identical output) on the single-JSON synthetic test bundle and the
  July positive-control bundle; still silent-and-correct (not
  "unparseable") on the genuinely-empty February bundle.

The lesson for future work on this toolkit: a synthetic test bundle and one
real bundle are not enough to exercise every documented shape in "Known
Bundle/Test Characteristics" below. Real incident bundles found this defect
within minutes that the single-bundle test process during the
`_bundlelib.py` extraction could not have caught, because that extraction's
only available real-shape bundle (`nomad-debug-test`) happens to use
single-JSON `allocations.json`, not JSON-lines. Test new/changed parsing
logic against every distinct bundle shape available, not just one.
