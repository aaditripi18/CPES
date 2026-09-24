# M5 context and windowing contract

M5 implements C7 Context Builder and C8 Window Manager. Both components accept
backend-neutral objects supplied by their caller; neither component reads files,
parses telemetry, retrieves events, or connects to external systems.

## C7 descriptive context

`ContextBuilder` exposes only these factual categories:

- parent-child relationships;
- lineage relationships;
- integrity transitions;
- privilege inheritance;
- command-line context;
- registry context;
- image/module context;
- temporal context.

The resulting `LineageContext` preserves `is_truncated`, `is_incomplete`, and
`is_fragmented` exactly as supplied by C6. It assigns no evaluative meaning to
any context fact.

## C8 bounded event groups

`WindowManager` receives explicit start, horizon, span, and advancement values.
It uses only supplied timestamps to assemble full bounded intervals and their
event groups. It does not choose parameter values, create missing events, merge
intervals, or alter ordering beyond deterministic sorting by supplied timestamp
and event identifier.

## M5-to-M6 boundary

M5 ends with descriptive lineage context and deterministic event groups. The
next component may consume those structures, but no evaluative fields or
decisions are produced by M5.

## Manual spot check

Populate the M5 templates only from actual corpus evidence and M3/M4 records.
Confirm factual context, supplied-window membership, ordering, and preserved
lineage status without modifying the corpus.
