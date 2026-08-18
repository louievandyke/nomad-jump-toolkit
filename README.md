# Nomad Jump Toolkit

[![GitHub repo](https://img.shields.io/badge/GitHub-nomad--jump--toolkit-181717?logo=github)](https://github.com/louievandyke/nomad-jump-toolkit)

Offline, read-only forensic helpers for unpacked `nomad operator debug` bundles.

The toolkit is designed for restricted jump boxes where customer artifacts should remain local. Scripts use Python's standard library where practical, avoid network access, keep terminal output bounded, and write derived analysis separately from source bundles.

## Layout

```text
jumptoolkit/
├── README.md
├── AGENTS.md
├── scripts/
├── bundles/
└── analysis/
```

- `scripts/` — analysis scripts.
- `bundles/` — source Nomad debug bundles and test fixtures. Treat these as read-only.
- `analysis/` — generated output from toolkit scripts. Safe to delete and regenerate.

## Current Scripts

| Script | Purpose |
|---|---|
| `inventory_bundle_v2.py` | Inventory bundle structure, intervals, servers/clients, artifacts, sizes, hashes, and coverage. |
| `find_identifiers_v2.py` | Search safely for allocation, node, eval, deployment, job, and other identifiers with bounded context. |
| `extract_window_v2.py` | Extract artifacts and filtered logs for a requested UTC time window. |
| `alloc_lifecycle_v2.py` | Build a chronological lifecycle for one allocation from snapshots, eventstream data, and monitor logs. |
| `correlate_timeline_v2.py` | Correlate allocation/node/eval identifiers across structured data and monitor logs while suppressing debug-collection noise. |
| `alloc_lineage_v2.py` | Trace allocation predecessor/replacement lineage using captured `PreviousAllocation`, `NextAllocation`, and `RescheduleTracker` evidence. |
| `eval_trace.py` | Trace evaluation relationships using `PreviousEval`, `NextEval`, and `BlockedEval`, and associate allocations through `EvalID`. |

`_bundlelib.py` is a shared internal module (bundle-root detection, timestamp
parsing, eventstream iteration, and similar helpers) used by all seven
scripts above. It is not a standalone tool and has no CLI of its own; keep it
next to the scripts when copying the toolkit to a jump box.

## Quick Start

From the project root:

```bash
python3 scripts/inventory_bundle_v2.py bundles/<bundle>
```

Find an identifier:

```bash
python3 scripts/find_identifiers_v2.py bundles/<bundle>   --id <UUID>
```

Trace an allocation lifecycle:

```bash
python3 scripts/alloc_lifecycle_v2.py bundles/<bundle>   --alloc <ALLOC_ID>
```

Trace allocation lineage:

```bash
python3 scripts/alloc_lineage_v2.py bundles/<bundle>   --alloc <ALLOC_ID>
```

Trace an evaluation directly:

```bash
python3 scripts/eval_trace.py bundles/<bundle>   --eval <EVAL_ID>
```

Or resolve the evaluation from an allocation:

```bash
python3 scripts/eval_trace.py bundles/<bundle>   --alloc <ALLOC_ID>
```

## Output

Scripts generate derived artifacts under `analysis/` or a script-specific analysis directory. Common output formats include:

- Markdown for quick human review
- CSV for filtering/comparison
- JSON for machine-readable provenance and follow-on analysis

Inspect the Markdown output first unless a script says otherwise.

## Safety Model

The toolkit follows these rules:

1. Source bundles are opened read-only.
2. Source artifacts are never modified in place.
3. Derived data is written outside the source bundle.
4. Scripts do not require network access.
5. Customer data should remain on the jump box.
6. Terminal output must be bounded; avoid recursive unbounded greps or dumping large/minified JSON.
7. Missing or partial evidence should be surfaced explicitly rather than silently discarded.
8. Relationships should be reported as authoritative only when backed by captured Nomad fields or other explicit evidence.

## Bundle Compatibility

Real Nomad debug bundles are not always serialized identically. Toolkit parsers should expect:

- conventional JSON arrays or objects
- wrapper objects such as `Allocations` or `Evaluations`
- multiple JSON documents / JSON-lines
- empty artifact files
- missing records that are still referenced by another artifact

Do not assume a `.json` filename always contains one conventional JSON document.

## Development

Before changing a script, read `AGENTS.md`.

When a script version is validated against representative bundles, keep that known-good version stable. Experimental changes should not silently replace a validated implementation.

The project intentionally favors conservative forensic conclusions over speculative inference.
