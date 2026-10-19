"""Live detection sessions: stream a dataset (replay) or an Elasticsearch index
through ``cpes.streaming.StreamingScorer`` and publish alerts as windows close.

A replay session is honest about what it is: recorded telemetry re-played at a
chosen speed. An Elasticsearch session reads live telemetry (configured with the
CPES_ES_* environment variables) and closes windows only behind the poller's
lateness watermark.
"""

from __future__ import annotations

import os
import threading
import time
import traceback
from collections import Counter
from datetime import datetime
from decimal import Decimal
from typing import Any

from cpes.adapters.evidence import EvidenceRecordMapper, load_evidence_mapping
from cpes.adapters.mapping import CanonicalEventMapper
from cpes.orchestration.evidence import EvidenceChannelBuilder
from cpes.streaming import ReplaySource, StreamingScorer

from evaluation.engine import EVIDENCE_MAPPING, EVIDENCE_SETTINGS, make_generator, make_resolver

from .evidence import load_model, to_evidence_model
from .ingest import map_records, resolve_mapping
from .runner import SIGNAL_IDS, RunStore
from .storage import DatasetStore, new_id, now

MAX_ALERTS = 2000


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _basename(path: Any) -> str | None:
    return str(path).replace("/", "\\").split("\\")[-1] if path else None


def elastic_settings() -> dict[str, Any]:
    url = os.environ.get("CPES_ES_URL")
    configured = bool(url and os.environ.get("CPES_ES_PASSWORD"))
    return {
        "configured": configured,
        "url": url,
        "index": os.environ.get("CPES_ES_INDEX", "cpes-live-*"),
        "how": "Set CPES_ES_URL, CPES_ES_PASSWORD (and optionally CPES_ES_INDEX) before starting the server. See lab/README.md.",
    }


class LiveSession:
    def __init__(self, session_id: str, *, source: str, dataset_id: str | None, speed: float | None, span: float, advance: float, threshold: Decimal, model_id: str) -> None:
        self.id = session_id
        self.source = source
        self.dataset_id = dataset_id
        self.speed = speed
        self.span = span
        self.advance = advance
        self.threshold = threshold
        self.model_id = model_id
        self.state = "starting"
        self.error: str | None = None
        self.trace: str | None = None
        self.started_at = now()
        self.finished_at: str | None = None
        self.event_start: datetime | None = None
        self.event_end: datetime | None = None
        self.watermark: datetime | None = None
        self.events = 0
        self.windows_scored = 0
        self.signals: Counter = Counter()
        self.alerts: list[dict[str, Any]] = []
        self._stop = threading.Event()
        self._images: dict[str, str] = {}

    def stop(self) -> None:
        self._stop.set()

    def snapshot(self, since: int = 0) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "dataset_id": self.dataset_id,
            "speed": self.speed,
            "state": self.state,
            "error": self.error,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "settings": {"span_seconds": self.span, "advance_seconds": self.advance, "threshold": str(self.threshold), "evidence_model": self.model_id},
            "event_start": self.event_start.isoformat() if self.event_start else None,
            "event_end": self.event_end.isoformat() if self.event_end else None,
            "watermark": self.watermark.isoformat() if self.watermark else None,
            "events": self.events,
            "windows_scored": self.windows_scored,
            "signals": dict(self.signals),
            "alert_count": len(self.alerts),
            "alerts": self.alerts[since:],
        }

    # ----------------------------------------------------------------- scoring
    def _scorer(self, start: datetime) -> tuple[StreamingScorer, Any]:
        resolver = make_resolver()
        model = to_evidence_model(load_model(self.model_id), SIGNAL_IDS)
        scorer = StreamingScorer(start_at=start, span_seconds=self.span, advance_seconds=self.advance, evidence_model=model, detection_threshold=self.threshold, observation_generator=make_generator(resolver))
        return scorer, resolver

    def _remember_images(self, events) -> None:
        for event in events:
            if isinstance(event.process_guid, str) and event.image_path and event.process_guid not in self._images:
                self._images[event.process_guid] = _basename(event.image_path)

    def _publish(self, closed, resolver) -> None:
        for window in closed:
            self.windows_scored += 1
            decision = window.decision
            if not decision.is_detected:
                continue
            result = decision.cpes_score_result
            group = window.window.detection_window.event_group
            resolved = resolver.resolve(group, pipe_evidence=group.pipe_evidence, remote_thread_evidence=group.remote_thread_evidence)
            contributions = []
            for contribution in result.evidence_contributions:
                self.signals[contribution.signal_id] += 1
                contributions.append({
                    "signal_id": contribution.signal_id,
                    "weight": str(contribution.signed_log_likelihood),
                    "anchors": [{"process_guid": r.process_guid, "image": self._images.get(r.process_guid)} for r in contribution.source_references],
                })
            if len(self.alerts) < MAX_ALERTS:
                self.alerts.append({
                    "n": len(self.alerts),
                    "raised_at": now(),
                    "watermark": window.scored_at_watermark.isoformat(),
                    "window_start": window.window.detection_window.start_at.isoformat(),
                    "window_end": window.window.detection_window.end_at.isoformat(),
                    "lineage_chain_id": result.lineage_chain_id,
                    "score": str(result.cpes_score),
                    "threshold": str(decision.detection_threshold),
                    "contributions": contributions,
                    "explanation": [line for r in resolved for line in r.resolution_path],
                    "events_known": window.events_known,
                })

    # ----------------------------------------------------------------- sources
    def run_replay(self, datasets: DatasetStore) -> None:
        meta = datasets.meta(self.dataset_id)
        parsed, _ = datasets.load(self.dataset_id)
        configuration, spec = resolve_mapping(meta.get("suggested_mapping"))
        mapped = map_records(parsed, configuration, spec["event_id_from_position"])
        if not mapped.events:
            raise ValueError("no record of this dataset passes validation; nothing to stream.")
        evidence, _report = RunStore._evidence(parsed, mapped.record_indices, {"evidence_channels": True, "mapping_spec": spec})
        self._remember_images(mapped.events)
        items = [("event", e) for e in mapped.events] + [("evidence", e) for e in evidence]
        source = ReplaySource(
            items,
            timestamp_of=lambda item: item[1].source_timestamp if item[0] == "event" else item[1].occurred_at.isoformat(),
            tick_seconds=max(1.0, min(30.0, self.advance / 5)),
            speed=self.speed,
            sleep=lambda seconds: self._stop.wait(seconds),
        )
        self.event_start, self.event_end = source.start, source.end
        scorer, resolver = self._scorer(source.start)
        self.state = "running"
        for batch in source.batches():
            if self._stop.is_set():
                break
            scorer.ingest([i[1] for i in batch.documents if i[0] == "event"], [i[1] for i in batch.documents if i[0] == "evidence"])
            self.events += sum(1 for i in batch.documents if i[0] == "event")
            self.watermark = batch.watermark
            self._publish(scorer.advance_to(batch.watermark), resolver)
        if not self._stop.is_set():
            self._publish(scorer.flush(), resolver)

    def run_elastic(self, client_factory) -> None:
        from cpes.adapters.elastic import ElasticPollingSource
        from cpes.adapters.mapping import load_mapping_configuration

        from .ingest import MAPPING_PRESETS

        settings = elastic_settings()
        client = client_factory(settings)
        poller = ElasticPollingSource(client, index=settings["index"], lateness_seconds=30.0)
        mapper = CanonicalEventMapper(load_mapping_configuration(MAPPING_PRESETS["elastic-sysmon-field-mapping-v1"]))
        evidence_mapper = EvidenceRecordMapper(load_evidence_mapping(EVIDENCE_MAPPING))
        builder = EvidenceChannelBuilder(**EVIDENCE_SETTINGS)
        scorer = resolver = None
        self.state = "running"
        while not self._stop.is_set():
            documents = poller.poll()
            events, records = [], []
            for document in documents:
                try:
                    events.append(mapper.map_document(document))
                    records.append(evidence_mapper.map_document(document))
                except (ValueError, TypeError):
                    continue  # a document the mapping cannot read is not scored (counted below)
            if events and scorer is None:
                first = min(_ts(e.source_timestamp) for e in events)
                self.event_start = first
                scorer, resolver = self._scorer(first)
            if scorer is not None:
                self._remember_images(events)
                scorer.ingest(events, builder.build(records).items)
                self.events += len(events)
                safe = poller.safe_watermark()
                if safe is not None and safe > scorer.watermark:
                    self.watermark = safe
                    self.event_end = safe
                    self._publish(scorer.advance_to(safe), resolver)
            self._stop.wait(2.0)


class LiveStore:
    def __init__(self, datasets: DatasetStore) -> None:
        self.datasets = datasets
        self.sessions: dict[str, LiveSession] = {}
        self._lock = threading.Lock()

    def start(self, request: dict[str, Any], *, client_factory=None) -> dict[str, Any]:
        source = request.get("source", "replay")
        if source not in ("replay", "elasticsearch"):
            raise ValueError("source must be 'replay' or 'elasticsearch'.")
        with self._lock:
            if any(s.state in ("starting", "running") for s in self.sessions.values()):
                raise ValueError("a live session is already running; stop it first.")
        if source == "replay":
            self.datasets.meta(request.get("dataset_id"))  # raises KeyError if unknown
        elif not elastic_settings()["configured"]:
            raise ValueError("Elasticsearch is not configured. " + elastic_settings()["how"])
        speed = request.get("speed")
        speed = None if speed in (None, "max", 0) else float(speed)
        session = LiveSession(
            new_id("live"), source=source, dataset_id=request.get("dataset_id") if source == "replay" else None, speed=speed,
            span=float(request.get("span_seconds", 300)), advance=float(request.get("advance_seconds", 150)),
            threshold=Decimal(str(request.get("threshold", "0.5"))), model_id=request.get("evidence_model_id", "research-v3-full-table"),
        )
        if session.advance > session.span:
            raise ValueError("advance must not exceed span.")
        self.sessions[session.id] = session

        def target() -> None:
            try:
                if source == "replay":
                    session.run_replay(self.datasets)
                else:
                    session.run_elastic(client_factory or _elastic_client)
                session.state = "stopped" if session._stop.is_set() else "completed"
            except Exception as error:  # surfaced in the UI, never swallowed
                session.state = "failed"
                session.error = f"{type(error).__name__}: {error}"
                session.trace = traceback.format_exc()[-3000:]
            session.finished_at = now()

        threading.Thread(target=target, daemon=True).start()
        return session.snapshot()

    def get(self, session_id: str, since: int = 0) -> dict[str, Any]:
        if session_id not in self.sessions:
            raise KeyError(session_id)
        return self.sessions[session_id].snapshot(since)

    def stop(self, session_id: str) -> dict[str, Any]:
        if session_id not in self.sessions:
            raise KeyError(session_id)
        self.sessions[session_id].stop()
        time.sleep(0.05)
        return self.sessions[session_id].snapshot()

    def list(self) -> list[dict[str, Any]]:
        return [{k: v for k, v in s.snapshot().items() if k != "alerts"} for s in sorted(self.sessions.values(), key=lambda s: s.started_at, reverse=True)]


def _elastic_client(settings: dict[str, Any]):
    from elasticsearch import Elasticsearch

    return Elasticsearch(settings["url"], basic_auth=(os.environ.get("CPES_ES_USER", "elastic"), os.environ["CPES_ES_PASSWORD"]), verify_certs=False, ssl_show_warn=False, request_timeout=10)
