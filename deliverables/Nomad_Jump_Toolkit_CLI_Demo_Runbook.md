# Nomad Jump Toolkit — CLI Demo Runbook

Audience: Nomad operators and SREs
Length: 6–8 minutes
Goal: show how a raw `nomad operator debug` bundle becomes bounded, reviewable evidence on an offline jump box.

## Before you record

- Use a non-customer bundle or a sanitized copy. Do not show real hostnames, job names, allocation IDs, or log contents without approval.
- Open a terminal at 20–24 pt font and a second pane for the generated Markdown reports.
- Start from the toolkit root. The scripts use only Python 3 standard-library modules and do not modify the bundle.
- Clear prior demo output, or use a new output folder for each take. The commands below write only under `analysis/`.

```bash
export BUNDLE="bundles/<sanitized-debug-bundle>"
export ALLOC_ID="<allocation-id-from-your-demo-bundle>"
mkdir -p analysis/demo
```

## 0:00–0:45 — Set the frame

Say:

> A Nomad debug bundle is valuable primary evidence, but it is not a pleasant investigation interface. It can be large, incomplete, and captured across multiple intervals. This toolkit is deliberately narrow: it runs offline, opens source artifacts read-only, keeps terminal output bounded, and writes the reasoning out as inspectable Markdown, CSV, and JSON.

On screen: show the repository root and `scripts/`. Do not scroll through the bundle.

## 0:45–1:45 — Establish what was captured

```bash
python3 scripts/inventory_bundle_v2.py "$BUNDLE" --output analysis/demo/inventory --overwrite
less analysis/demo/inventory/inventory.md
```

Say:

> First I establish the capture boundary. I want the interval range, the nodes and roles present, and the artifacts available before I form a theory. The inventory report is derived output; the bundle remains untouched.

Point out: interval coverage, server/client count, eventstream presence, and the report location. Avoid presenting a file listing as an investigation result.

## 1:45–2:45 — Locate the seed safely

```bash
python3 scripts/find_identifiers_v2.py "$BUNDLE" \
  --id "$ALLOC_ID" \
  --output analysis/demo/identifier --overwrite
less analysis/demo/identifier/report.md
```

Say:

> I start with a concrete seed: an allocation ID from an alert, a ticket, or a Nomad query. This search keeps context bounded and records where it found the identifier, rather than dumping every log line that happens to match.

Point out: source artifact, interval/capture, and source line or structured-record provenance.

## 2:45–4:15 — Build a lifecycle from multiple evidence types

```bash
python3 scripts/alloc_lifecycle_v2.py "$BUNDLE" \
  --alloc "$ALLOC_ID" \
  --output analysis/demo/lifecycle --overwrite
less analysis/demo/lifecycle/timeline.md
```

Say:

> This gives us a chronological lifecycle from interval snapshots, eventstream records when present, and relevant monitor logs. Notice the distinction between an interval capture—when we observed state—and an object timestamp—which may describe when that state changed. That prevents a common false timeline.

Point out: snapshot count, JSON-lines or empty-file handling if the bundle exhibits it, and the timeline’s provenance columns.

## 4:15–5:30 — Trace authoritative relationships

```bash
python3 scripts/alloc_lineage_v2.py "$BUNDLE" \
  --alloc "$ALLOC_ID" \
  --output analysis/demo/lineage --overwrite
less analysis/demo/lineage/lineage.md

python3 scripts/eval_trace.py "$BUNDLE" \
  --alloc "$ALLOC_ID" \
  --output analysis/demo/eval --overwrite
less analysis/demo/eval/eval_trace.md
```

Say:

> Here is the discipline that matters: a nearby timestamp, shared job, or shared node does not make two allocations related. The lineage and evaluation traces label relationships only when an authoritative captured field supports them—such as `PreviousAllocation`, `NextAllocation`, `PreviousEval`, or an allocation’s `EvalID`. If a referenced record is outside captured state, the report keeps that reference and marks it as missing from captured state.

If no lineage exists in this bundle, say so directly. A clean “no authoritative relationship captured” result is a valid and useful outcome.

## 5:30–6:30 — Close on the deliverable

```bash
find analysis/demo -maxdepth 3 -type f | sort | sed -n '1,30p'
```

Say:

> The terminal is only the index. The real handoff is the bounded report set: Markdown for review, CSV for filtering, and JSON that preserves richer provenance. The investigator can make a defensible statement about what the bundle captured—and just as importantly, what it did not capture—without modifying the source data or needing network access.

## Recording notes

- Keep each command on one or two lines; use shell variables to avoid retyping sensitive IDs.
- Pause after each terminal summary, then open the generated Markdown report instead of scrolling raw JSON or monitor logs.
- If a command produces a result that is sparse, treat it as evidence about the capture rather than a failed demo.
- Stop the recording before displaying customer-derived filenames or report contents unless they have been reviewed for disclosure.
