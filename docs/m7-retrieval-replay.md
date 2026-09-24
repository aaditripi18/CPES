# M7 — Retrieval Adapter and Replay Driver

## Scope

M7 implements C5 and C13 only. `ElasticRetrievalAdapter` is the sole module that imports or accepts the Elasticsearch client. It reads source documents, uses the versioned declarative mapping in `configs/elastic-sysmon-field-mapping-v1.yaml`, and returns backend-neutral `CanonicalEvent` values.

The mapping copies only declared source-field values. It does not calculate, transform, infer, normalize, enrich, or derive any value. An absent optional source field is represented as `None`; a missing required ordering field is rejected. The mapping file declares the source field, destination field, and whether the source field is optional.

## Canonical stream contract

Both live retrieval and `ReplayDriver` return canonical events ordered by the supplied `source_timestamp` followed by the supplied immutable `source_event_id`. Neither component changes event values, creates missing fields, nor calls C6–C10.

`ReplayDriver` accepts already canonical events. The later corpus-backed invocation must supply the frozen `cpes-replay-v1` input and preserve its original event timestamps. The manifest and determinism record are intentionally unpopulated templates until actual laboratory evidence is available.

## Validation

Unit tests use supplied in-memory metadata only. They contract-test direct field mapping, missing optional values, rejection of missing required ordering fields, Elasticsearch-hit extraction through a fake client, and equality of live/replay canonical streams across repeated replay runs. They do not connect to Elastic or inspect a telemetry corpus.
