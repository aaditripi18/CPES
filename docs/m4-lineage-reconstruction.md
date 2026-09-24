# M4 structural lineage reconstruction

M4 implements C6 as a backend-neutral structural component. Its input is a
collection of supplied `ProcessNode` objects; it does not read telemetry files,
connect to a backend, or parse endpoint logs.

## Structural contract

- `process_guid` is the only process identity key.
- `process_id` is retained as non-identity metadata only and never joins nodes.
- Parent-child relationships are accepted only when the supplied parent
  ProcessGUID exists in the same input.
- A missing parent produces a truncated, fragmented lineage result with the
  unresolved parent identifier recorded.
- A supplied incomplete flag propagates to the lineage result unchanged.
- Disconnected structures remain separate; no relationship is inferred.
- Parent cycles are rejected as invalid structural input rather than repaired.

## Boundary

M4 does not construct runtime context, windows, event groups, scores,
explanations, detections, labels, or ATT&CK attribution. A later retrieval
adapter provides C6 with backend-neutral process records; M4 does not provide
that adapter.

## Manual spot check

Populate the M4 spot-check templates only from actual M2 corpus evidence and
completed M3 validation records. Confirm that reconstructed parent-child
relationships, incompleteness, truncation, and fragmentation match the recorded
facts without adding missing ancestry.
