"""Streaming scorer, replay source and Elasticsearch polling source."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import unittest

from cpes.adapters.elastic import ElasticPollingSource
from cpes.adapters.models import CanonicalEvent
from cpes.context.resolver import ContextResolver
from cpes.orchestration import CompositeObservationGenerator, CpesPipeline, PipelineConfiguration
from cpes.orchestration.resolved_observations import ResolvedSignalObservationGenerator
from cpes.scoring.models import EvidenceModel, EvidenceTerm
from cpes.streaming import ReplaySource, StreamingScorer
from cpes.windowing.models import SlidingWindowParameters

T0 = datetime(2026, 7, 20, 10, 0, tzinfo=timezone.utc)


def iso(seconds: float) -> str:
    return (T0 + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def event(eid, seconds, guid, parent=None, image=None, integrity=None, registry=None) -> CanonicalEvent:
    return CanonicalEvent(iso(seconds), eid, "1" if registry is None else "13", guid, parent, None, integrity, None, registry, image, None)


def uac_events(offset: float = 0.0) -> list[CanonicalEvent]:
    return [
        event(f"e1-{offset}", offset + 0, f"{{EXP{offset}}}", image="C:\\Windows\\explorer.exe", integrity="Medium"),
        event(f"e2-{offset}", offset + 10, f"{{CMD{offset}}}", parent=f"{{EXP{offset}}}", image="C:\\Windows\\System32\\cmd.exe", integrity="Medium"),
        event(f"e3-{offset}", offset + 12, f"{{CMD{offset}}}", image="C:\\Windows\\System32\\reg.exe", registry="HKU\\x\\ms-settings\\shell\\open\\command"),
        event(f"e4-{offset}", offset + 15, f"{{FOD{offset}}}", parent=f"{{CMD{offset}}}", image="C:\\Windows\\System32\\fodhelper.exe", integrity="High"),
    ]


def generator():
    resolver = ContextResolver(("Untrusted", "Low", "Medium", "High", "System"), ("fodhelper.exe",), ("ms-settings",))
    return CompositeObservationGenerator((ResolvedSignalObservationGenerator("autoelevation_lolbin", resolver, "autoelevation_lolbin"),))


MODEL = EvidenceModel(Decimal(0), (EvidenceTerm("autoelevation_lolbin", Decimal("7.4")),))
SPAN, ADVANCE = 60.0, 30.0


def scorer(start: datetime = T0) -> StreamingScorer:
    return StreamingScorer(start_at=start, span_seconds=SPAN, advance_seconds=ADVANCE, evidence_model=MODEL, detection_threshold=Decimal("0.5"), observation_generator=generator())


def batch(events) -> dict:
    stamps = [datetime.fromisoformat(e.source_timestamp.replace("Z", "+00:00")) for e in events]
    params = SlidingWindowParameters(min(stamps), max(stamps) + timedelta(seconds=SPAN), SPAN, ADVANCE)
    context = CpesPipeline().run(events, PipelineConfiguration(params, MODEL, Decimal("0.5"), generator()))
    return {(d.cpes_score_result.lineage_chain_id, w.detection_window.start_at): d.cpes_score_result.cpes_score for w, d in zip(context.window_observations, context.threshold_decisions)}


class StreamingScorerTests(unittest.TestCase):
    def test_all_events_then_flush_equals_batch(self) -> None:
        events = uac_events() + uac_events(400)
        live = scorer()
        live.ingest(events)
        closed = live.flush()
        streamed = {(c.decision.cpes_score_result.lineage_chain_id, c.window.detection_window.start_at): c.decision.cpes_score_result.cpes_score for c in closed}
        self.assertEqual(streamed, batch(events))

    def test_incremental_arrival_scores_each_window_once_and_alerts_on_close(self) -> None:
        events = uac_events() + uac_events(400)
        live = scorer()
        seen, alerts = [], []
        for second in range(0, 600, 10):
            live.ingest([e for e in events if second <= (datetime.fromisoformat(e.source_timestamp.replace("Z", "+00:00")) - T0).total_seconds() < second + 10])
            for window in live.advance_to(T0 + timedelta(seconds=second + 10)):
                seen.append((window.decision.cpes_score_result.lineage_chain_id, window.index))
                if window.decision.is_detected:
                    alerts.append((window.index, window.scored_at_watermark))
        seen += [(c.decision.cpes_score_result.lineage_chain_id, c.index) for c in live.flush()]
        self.assertEqual(len(seen), len(set(seen)))
        detected_batch = {k for k, v in batch(events).items() if v >= Decimal("0.5")}
        self.assertEqual(len({a[0] for a in alerts}), len(detected_batch))
        first_alert = min(a[1] for a in alerts)
        self.assertLessEqual(first_alert - (T0 + timedelta(seconds=15)), timedelta(seconds=SPAN))  # alert within one span of the elevation

    def test_watermark_cannot_go_backwards_and_parameters_are_checked(self) -> None:
        live = scorer()
        live.advance_to(T0 + timedelta(seconds=100))
        with self.assertRaises(ValueError):
            live.advance_to(T0)
        with self.assertRaises(ValueError):
            StreamingScorer(start_at=T0, span_seconds=30, advance_seconds=60, evidence_model=MODEL, detection_threshold=Decimal("0.5"), observation_generator=generator())


class ReplaySourceTests(unittest.TestCase):
    def test_batches_cover_every_document_in_time_order_with_pacing(self) -> None:
        documents = [{"t": iso(s), "n": s} for s in (25, 0, 5, 61, 40)] + [{"n": "no time"}]
        sleeps = []
        source = ReplaySource(documents, timestamp_of=lambda d: d.get("t"), tick_seconds=20, speed=10, sleep=sleeps.append)
        batches = list(source.batches())
        self.assertEqual([d["n"] for b in batches for d in b.documents], [0, 5, 25, 40, 61])
        self.assertEqual(len(source), 5)
        self.assertTrue(all(abs(s - 2.0) < 1e-9 for s in sleeps))
        self.assertTrue(all(b.watermark - b.start == timedelta(seconds=20) for b in batches))


class FakeElastic:
    def __init__(self, hits):
        self.hits = hits
        self.calls = []

    def search(self, **kwargs):
        self.calls.append(kwargs)
        after = kwargs.get("search_after")
        rows = sorted(self.hits, key=lambda h: (h["_source"]["@timestamp"], h["_id"]))
        rangefilter = [m for m in kwargs["query"].get("bool", {}).get("must", []) if "range" in m]
        if rangefilter:
            low = datetime.fromisoformat(rangefilter[0]["range"]["@timestamp"]["gte"])
            rows = [r for r in rows if datetime.fromisoformat(r["_source"]["@timestamp"].replace("Z", "+00:00")) >= low]
        if after:
            rows = [r for r in rows if (r["_source"]["@timestamp"], r["_id"]) > tuple(after)]
        page = rows[: kwargs["size"]]
        return {"hits": {"hits": [{**r, "sort": [r["_source"]["@timestamp"], r["_id"]]} for r in page]}}


def hit(identifier: str, seconds: float) -> dict:
    return {"_id": identifier, "_source": {"@timestamp": iso(seconds), "id": identifier}}


class ElasticPollingSourceTests(unittest.TestCase):
    def test_pages_dedupes_and_rereads_the_lateness_horizon(self) -> None:
        client = FakeElastic([hit("a", 0), hit("b", 10), hit("c", 20)])
        source = ElasticPollingSource(client, index="cpes-live-*", lateness_seconds=15, page_size=2)
        self.assertEqual([d["id"] for d in source.poll()], ["a", "b", "c"])
        self.assertEqual(source.safe_watermark(), T0 + timedelta(seconds=5))
        client.hits.append(hit("late", 12))  # indexed late but timestamped inside the horizon
        client.hits.append(hit("d", 30))
        self.assertEqual(sorted(d["id"] for d in source.poll()), ["d", "late"])
        self.assertEqual(source.poll(), ())


if __name__ == "__main__":
    unittest.main()
