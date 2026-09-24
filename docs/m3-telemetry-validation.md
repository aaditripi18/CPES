# M3 telemetry validation procedure

M3 validates and documents the manually generated M2 corpus. Repository
validators consume only manually completed validation records; they never read
raw telemetry or connect to an external system.

## Manual review records

- Record every coverage status in `coverage-observations.csv`.
- Record label-integrity spot-audit outcomes in `label-integrity-audit.csv`.
- Record evidence for every required benign hard-negative category in
  `benign-hard-negative-review.csv`.
- Preserve missing or incomplete telemetry exactly as observed. Do not infer,
  reconstruct, or repair it.

## M3 completion gate

M3 is complete when every selected technique passes coverage or is explicitly
flagged and handled, the label-integrity spot audit is complete, and the benign
partition is manually confirmed to contain genuine hard negatives.

## DG-1

Use `m3-dg1-decision-record.md` only after completing the relevant evidence.
The WMI contingency remains disabled without explicit user approval.

## Boundary

M3 does not parse telemetry, calculate coverage, infer labels, reconstruct
lineage, modify the M2 corpus, or implement any M4-or-later component.
