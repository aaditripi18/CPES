# M6 deterministic CPES scoring contract

M6 implements C9 additive signed-evidence arithmetic and C10 structured
threshold decisions. It is a pure backend-neutral computation layer.

## Supplied inputs

- a C8 event group with preserved structural status;
- present/absent signal observations and their source references;
- an evidence model containing prior log-odds and signed log-likelihood terms;
- a detection threshold.

All numerical values are injected by the caller. M6 does not derive priors,
terms, likelihoods, bins, thresholds, or any fitted value.

## Calculation

For present observations only:

```text
CPES Score = prior log-odds + sum(signed log-likelihood contributions)
```

The result retains every applied contribution and its supplied source references.
The threshold emitter compares the resulting scalar with the supplied threshold
and returns a structured decision. No prose, rendering, narrative, or analyst
summary is produced.

## Determinism and boundary

The engine orders supplied signal identifiers deterministically and uses Decimal
arithmetic. Identical inputs yield identical contribution records, scalar score,
and threshold decision.

M6 neither accesses telemetry nor derives model inputs. Retrieval and replay are
outside M6; parameter derivation and tuning are also outside M6.
