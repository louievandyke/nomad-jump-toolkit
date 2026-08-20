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
| `case_review.py` | Review exact identifiers from a structured, case-reported investigation brief while keeping case context separate from bundle-derived evidence. |
| `case_intake.py` | Discover nested debug bundles in a case artifact directory, map adjacent artifacts, and generate bounded next-step commands. |

`_bundlelib.py` is a shared internal module (bundle-root detection, timestamp
parsing, eventstream iteration, and similar helpers) used by all seven
scripts above. It is not a standalone tool and has no CLI of its own; keep it
next to the scripts when copying the toolkit to a jump box.

## Quick Start

From the project root:

```bash
python3 scripts/inventory_bundle_v2.py bundles/<bundle>
```

Find an identifier or exact string:

```bash
python3 scripts/find_identifiers_v2.py bundles/<bundle> \
  --id <IDENTIFIER>
```

`<IDENTIFIER>` is not limited to a NodeID or even to a UUID. It is the exact
value you want to locate across the bundle. Common examples include an
allocation ID, node ID, evaluation ID, deployment ID, job ID/name, namespace,
hostname, or IP address.

Examples:

```bash
# Allocation ID
python3 scripts/find_identifiers_v2.py bundles/<bundle> \
  --id ee943c77-0149-b085-fad0-de0f30f23c2c

# Node ID
python3 scripts/find_identifiers_v2.py bundles/<bundle> \
  --id 027c010c-e769-eb1b-2ebe-a4b819fcbbd4

# Evaluation ID
python3 scripts/find_identifiers_v2.py bundles/<bundle> \
  --id ced8afab-16e4-87ce-2f01-e297b45ba3c3

# Search several related identifiers in one pass
python3 scripts/find_identifiers_v2.py bundles/<bundle> \
  --id ee943c77-0149-b085-fad0-de0f30f23c2c \
  --id 027c010c-e769-eb1b-2ebe-a4b819fcbbd4 \
  --id ced8afab-16e4-87ce-2f01-e297b45ba3c3
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

Review case-reported leads without treating them as bundle evidence:

```bash
python3 scripts/case_review.py bundles/<bundle> \
  --case-context examples/case_context.example.json
```

Use `examples/case_context.example.json` as the schema template. The case
context is optional to the broader toolkit workflow; `case_review.py` requires
it because its sole purpose is to review that structured input against a bundle.

After using your jump-box `ticket <CASE-ID>` command, run intake directly from
the ticket directory. This is useful when the bundle is nested inside an
unpacked diagnostic archive:

```bash
python3 /path/to/jumptoolkit/scripts/case_intake.py \
  --case-context /path/to/case_context.json
```

An explicit case directory is also accepted as the optional first argument.
Derived intake output defaults to `~/analysis_case_intake`, outside the ticket
directory; use `--output` to select another approved analysis location.

`case_intake.py` never unpacks archives or reads case artifact contents. If it
finds more than one standard bundle, it refuses to choose and prints compact
candidate paths for `--bundle` selection. Its `next_steps.md` contains the
copy/paste commands for the selected bundle.

## Finding Identifiers

`find_identifiers_v2.py` is the toolkit's exact cross-bundle search tool. Use
it when you already have a value from a case, log line, Nomad object, or another
tool and want to determine where that value appears in the collected artifacts.

The script does **not** assume that `--id` is a particular Nomad object type.
It searches for the supplied value exactly and lets the source artifact provide
the context. This makes the same command useful for:

- allocation IDs
- node IDs
- evaluation IDs
- deployment IDs
- job IDs or names
- namespaces
- hostnames
- IP addresses
- other exact strings present in searchable bundle artifacts

It scans searchable text artifacts while skipping obvious binary/profile/archive
files, streams files line by line, counts all matches, and retains only a bounded
number of context samples. Matches are categorized so higher-value forensic
sources such as eventstream, allocation/evaluation/deployment/job/node snapshots,
scheduler snapshots, and monitor logs can be distinguished from repetitive
metrics or generic text.

Typical output is written to:

```text
analysis_find_identifiers/
├── results.csv
├── results.md
└── summary.json
```

Inspect `results.md` first. `results.csv` contains the detailed source-attributed
matches, including source path and line information, while `summary.json`
provides machine-readable counts.

Useful options include:

```text
--id <VALUE>            Exact value to search for; repeat for multiple values.
--ignore-case           Perform a case-insensitive search.
--samples-per-file N    Bound the number of retained sample lines per file/value.
--sample-width N        Bound the amount of context retained around each match.
--output <DIR>          Choose a derived output directory.
```

`find_identifiers_v2.py` is a discovery tool: it tells you where an exact value
appears, but it does not interpret the relationships between those references.
Use the object-aware tools for that interpretation:

- `alloc_lifecycle_v2.py` reconstructs what happened to an allocation over time.
- `alloc_lineage_v2.py` follows allocation predecessor, replacement, and reschedule relationships.
- `eval_trace.py` follows scheduler evaluation chains and allocation-to-evaluation links.
- `correlate_timeline_v2.py` combines related allocations, nodes, evaluations, jobs, structured events, and logs into a shared timeline.

A practical workflow looks like this:

```text
I have this UUID or exact value from a customer log.
        │
        ▼
find_identifiers_v2.py
"What is this showing up in?"
        │
        ├── looks like an allocation
        │       │
        │       ├── alloc_lifecycle_v2.py
        │       │   "What happened to it?"
        │       │
        │       └── alloc_lineage_v2.py
        │           "What replaced it / what did it replace?"
        │
        ├── allocation has EvalID
        │       │
        │       └── eval_trace.py
        │           "Why did the scheduler create/re-evaluate it?"
        │
        └── I now have alloc + node + eval
                │
                └── correlate_timeline_v2.py
                    "Show me the combined incident timeline."
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
