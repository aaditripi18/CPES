# CPES Orchestration Pipeline

`CpesPipeline` coordinates supplied C5 canonical events through C6 lineage, C7 context, C8 windows, a caller-injected `ObservationGenerator`, C9 scoring, and C10 threshold decisions. It has no Elasticsearch dependency or I/O.

The immutable `PipelineContext` preserves canonical events, translated process/context inputs, lineage chains, contexts, windows, observations, scores, and decisions. Window-aligned artifact tuples preserve full in-memory provenance for later export and evaluation work.

Observation generation is a strategy boundary. `EventFieldPresenceObservationGenerator` is a factual implementation based only on explicitly declared event fields; callers may inject another implementation without changing the pipeline.
