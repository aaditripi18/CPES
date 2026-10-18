"""Protocol stream-replay-v3: replay corpus-v3 through the streaming scorer.

Measures (a) agreement between alerts raised live (each window scored once, when
it closes, with what had arrived) and the batch result computed in hindsight, and
(b) time-to-alert: event time from an attack process's creation to the watermark
at which a live alert first referenced it.
"""

from __future__ import annotations

import statistics
import time
from datetime import datetime, timedelta
from decimal import Decimal

from cpes.adapters.evidence import EvidenceRecordMapper, load_evidence_mapping
from cpes.adapters.mapping import CanonicalEventMapper, load_mapping_configuration
from cpes.orchestration import CpesPipeline, PipelineConfiguration
from cpes.orchestration.evidence import EvidenceChannelBuilder
from cpes.streaming import ReplaySource, StreamingScorer
from cpes.windowing.models import SlidingWindowParameters

from . import data
from .engine import EVIDENCE_MAPPING, EVIDENCE_SETTINGS, MAPPING, frozen_model, make_generator, make_resolver

SPAN, ADVANCE, TICK = 300.0, 150.0, 30.0


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def run() -> dict:
    docs = list(data.documents())
    mapper = CanonicalEventMapper(load_mapping_configuration(MAPPING))
    evidence_mapper = EvidenceRecordMapper(load_evidence_mapping(EVIDENCE_MAPPING))
    builder = EvidenceChannelBuilder(**EVIDENCE_SETTINGS)
    model, threshold = frozen_model(), Decimal("0.5")
    source = ReplaySource(docs, timestamp_of=lambda d: d.get("@timestamp"), tick_seconds=TICK)
    start = source.start

    live = StreamingScorer(start_at=start, span_seconds=SPAN, advance_seconds=ADVANCE, evidence_model=model, detection_threshold=threshold, observation_generator=make_generator(make_resolver()))
    live_alerts: dict[tuple[str, datetime], dict] = {}
    first_alert_for: dict[str, datetime] = {}
    live_anchor_keys: set[tuple] = set()
    tick_seconds: list[float] = []
    for batch in source.batches():
        events = [mapper.map_document(d) for d in batch.documents]
        evidence = builder.build(evidence_mapper.map_document(d) for d in batch.documents).items
        began = time.perf_counter()
        live.ingest(events, evidence)
        closed = live.advance_to(batch.watermark)
        tick_seconds.append(time.perf_counter() - began)
        for window in closed:
            if window.decision.is_detected:
                result = window.decision.cpes_score_result
                key = (result.lineage_chain_id, window.window.detection_window.start_at)
                live_alerts[key] = {"score": result.cpes_score, "at": window.scored_at_watermark}
                for contribution in result.evidence_contributions:
                    live_anchor_keys.update((window.window.detection_window.start_at, contribution.signal_id, r.process_guid) for r in contribution.source_references)
                    for reference in contribution.source_references:
                        first_alert_for.setdefault(reference.process_guid, window.scored_at_watermark)
    for window in live.flush():
        if window.decision.is_detected:
            result = window.decision.cpes_score_result
            live_alerts[(result.lineage_chain_id, window.window.detection_window.start_at)] = {"score": result.cpes_score, "at": window.scored_at_watermark}
            for contribution in result.evidence_contributions:
                live_anchor_keys.update((window.window.detection_window.start_at, contribution.signal_id, r.process_guid) for r in contribution.source_references)

    events = [mapper.map_document(d) for d in docs]
    evidence = builder.build(evidence_mapper.map_document(d) for d in docs).items
    stamps = [_ts(e.source_timestamp) for e in events]
    params = SlidingWindowParameters(start, max(stamps) + timedelta(seconds=SPAN), SPAN, ADVANCE)
    context = CpesPipeline().run(events, PipelineConfiguration(params, model, threshold, make_generator(make_resolver())), evidence=evidence)
    batch_alerts = {(d.cpes_score_result.lineage_chain_id, w.detection_window.start_at) for w, d in zip(context.window_observations, context.threshold_decisions) if d.is_detected}
    batch_anchor_keys = {
        (w.detection_window.start_at, c.signal_id, r.process_guid)
        for w, d in zip(context.window_observations, context.threshold_decisions) if d.is_detected
        for c in d.cpes_score_result.evidence_contributions for r in c.source_references
    }

    units = {u.guid: u for u in data.units()}
    latencies = {}
    for guid, at in first_alert_for.items():
        unit = units.get(guid)
        if unit and unit.is_attack:
            latencies[guid] = (at - unit.created_at).total_seconds()
    values = sorted(latencies.values())

    def pct(q: float) -> float | None:
        return values[min(len(values) - 1, int(round(q * (len(values) - 1))))] if values else None

    live_keys = set(live_alerts)
    images = {}
    for document in docs:
        process = document.get("process") or {}
        if process.get("entity_id") and process.get("executable") and process["entity_id"] not in images:
            images[process["entity_id"]] = process["executable"].replace("/", "\\").split("\\")[-1].lower()

    def describe(keys):
        return sorted(f"{start.isoformat()} {signal} {images.get(guid, guid)}" for start, signal, guid in keys)

    return {
        "settings": {"span_seconds": SPAN, "advance_seconds": ADVANCE, "tick_seconds": TICK, "events": len(docs)},
        "agreement": {
            "unit": "alert = (window start, signal, anchored process); chain IDs are not compared because a chain's root, and so its ID, can change as more of the tree arrives",
            "live": len(live_anchor_keys),
            "batch": len(batch_anchor_keys),
            "both": len(live_anchor_keys & batch_anchor_keys),
            "live_only": describe(live_anchor_keys - batch_anchor_keys),
            "batch_only": describe(batch_anchor_keys - live_anchor_keys),
            "chain_keyed_counts": {"live_windows": len(live_keys), "batch_windows": len(batch_alerts), "same_chain_id": len(live_keys & batch_alerts)},
        },
        "time_to_alert_seconds": {
            "attack_units_alerted": len(values),
            "median": statistics.median(values) if values else None,
            "p95": pct(0.95),
            "max": values[-1] if values else None,
            "note": "Event time from the attack process's creation to the watermark of its first live alert. With overlapping windows the earliest window containing an event closes at most `advance` seconds after it, plus up to one tick of watermark granularity, so the bound is advance + tick.",
        },
        "cost": {"ticks": len(tick_seconds), "median_tick_seconds": statistics.median(tick_seconds), "max_tick_seconds": max(tick_seconds), "total_seconds": sum(tick_seconds)},
        "summary": {"live_alerts": len(live_anchor_keys), "batch_alerts": len(batch_anchor_keys), "agree": len(live_anchor_keys & batch_anchor_keys), "median_time_to_alert_s": statistics.median(values) if values else None},
    }
