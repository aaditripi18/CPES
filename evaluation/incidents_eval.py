"""Protocol incidents-lab-v3 (pre-registered in docs/design/incident-correlation.md)."""

from __future__ import annotations

import statistics
from datetime import datetime, timedelta
from decimal import Decimal

from cpes.adapters.evidence import EvidenceRecordMapper, load_evidence_mapping
from cpes.adapters.mapping import CanonicalEventMapper, load_mapping_configuration
from cpes.correlation import Alert, correlate
from cpes.orchestration import CpesPipeline, PipelineConfiguration
from cpes.orchestration.evidence import EvidenceChannelBuilder
from cpes.windowing.models import SlidingWindowParameters

from . import data, research_signals, sigma_eval
from .engine import EVIDENCE_MAPPING, EVIDENCE_SETTINGS, MAPPING, frozen_model, make_generator, make_resolver

GAP = 300.0


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def cpes_alerts(docs) -> list[Alert]:
    """One alert per (elevated process, signal), timed at the process's first event."""

    mapper = CanonicalEventMapper(load_mapping_configuration(MAPPING))
    events = [mapper.map_document(d) for d in docs]
    evidence = EvidenceChannelBuilder(**EVIDENCE_SETTINGS).build(EvidenceRecordMapper(load_evidence_mapping(EVIDENCE_MAPPING)).map_document(d) for d in docs).items
    stamps = [_ts(e.source_timestamp) for e in events]
    resolver = make_resolver()
    params = SlidingWindowParameters(min(stamps), max(stamps) + timedelta(seconds=300), 300, 150)
    context = CpesPipeline().run(events, PipelineConfiguration(params, frozen_model(), Decimal("0.5"), make_generator(resolver)), evidence=evidence)
    first_seen: dict[str, datetime] = {}
    for event in events:
        if isinstance(event.process_guid, str):
            first_seen.setdefault(event.process_guid, _ts(event.source_timestamp))
    out: dict[tuple[str, str], Alert] = {}
    for item, decision in zip(context.window_observations, context.threshold_decisions):
        if not decision.is_detected:
            continue
        group = item.detection_window.event_group
        resolved = resolver.resolve(group, pipe_evidence=group.pipe_evidence, remote_thread_evidence=group.remote_thread_evidence)
        actors = {r.anchor_process_guid: r.actor_process_guid for r in resolved}
        for contribution in decision.cpes_score_result.evidence_contributions:
            for reference in contribution.source_references:
                key = (reference.process_guid, contribution.signal_id)
                if key in out:
                    continue
                actor = actors.get(reference.process_guid)
                out[key] = Alert(
                    id=f"cpes:{contribution.signal_id}:{reference.process_guid}", source="cpes",
                    time=first_seen.get(reference.process_guid, item.detection_window.start_at), process_guid=reference.process_guid,
                    title=f"CPES {contribution.signal_id}", level="high",
                    related_guids=(actor,) if actor and actor != reference.process_guid else (),
                )
    return list(out.values())


def sigma_alerts(docs) -> list[Alert]:
    ruleset, _ = sigma_eval._lab_ruleset("core")
    out = []
    for n, a in enumerate(sigma_eval.lab_alerts(docs, ruleset)):
        if a["level"] in sigma_eval.LEVELS_HIGH:
            out.append(Alert(id=f"sigma:{n}", source="sigma", time=a["t"], process_guid=a["guid"], title=a["rule"], level=a["level"], tags=tuple(sorted(a["tags"]))))
    return out


def measure(incidents, alerts, runs) -> dict:
    near = lambda t, at: abs((t - at).total_seconds()) <= data.TOLERANCE_SECONDS  # noqa: E731
    touching = []
    for _, at in runs:
        hit = [i for i in incidents if any(near(a.time, at) for a in i.alerts)]
        touching.append(hit)
    runs_with_incident = sum(bool(h) for h in touching)
    fragmentation = [len(h) for h in touching if h]
    attributed = sum(any(i.outcome_processes for i in h) for h in touching)
    spanning = sum(1 for i in incidents if sum(any(near(a.time, at) for a in i.alerts) for _, at in runs) > 1)
    noise = [i for i in incidents if not any(near(a.time, at) for a in i.alerts for _, at in runs)]
    return {
        "alerts": len(alerts),
        "incidents": len(incidents),
        "compression": round(len(alerts) / len(incidents), 2) if incidents else None,
        "runs_with_an_incident": f"{runs_with_incident}/{len(runs)}",
        "incidents_per_run_median": statistics.median(fragmentation) if fragmentation else None,
        "incidents_per_run_max": max(fragmentation) if fragmentation else None,
        "runs_whose_incident_names_the_elevated_process": f"{attributed}/{len(runs)}",
        "incidents_spanning_more_than_one_run": spanning,
        "noise_incidents_outside_runs": len(noise),
        "largest_incident_alerts": max((len(i.alerts) for i in incidents), default=0),
        # descriptive, added after the first run (not pre-registered):
        "incidents_with_both_sources": sum(1 for i in incidents if len(i.sources) > 1),
        "cpes_alerts_joined_to_sigma": sum(1 for i in incidents if len(i.sources) > 1 for a in i.alerts if a.source == "cpes"),
    }


def run() -> dict:
    docs = list(data.documents())
    parent_of = {guid: node.parent for guid, node in research_signals.nodes(docs).items()}
    runs = data.ledger_runs()
    sigma, cpes = sigma_alerts(docs), cpes_alerts(docs)
    configurations = {"sigma_alone": sigma, "cpes_alone": cpes, "fused": sigma + cpes}
    results = {name: measure(correlate(alerts, parent_of, gap_seconds=GAP), alerts, runs) for name, alerts in configurations.items()}
    fused = correlate(sigma + cpes, parent_of, gap_seconds=GAP)
    examples = []
    for incident in fused:
        if incident.outcome_processes and "sigma" in incident.sources and len(examples) < 5:
            examples.append({"id": incident.id, "start": incident.start.isoformat(), "alerts": [f"{a.source}: {a.title}" for a in incident.alerts][:8], "outcome_processes": len(incident.outcome_processes)})
    separate = results["sigma_alone"]["incidents"] + results["cpes_alone"]["incidents"]
    return {"gap_seconds": GAP, "configurations": results, "fused_examples": examples,
            "items_to_open": {"sigma_and_cpes_separately": separate, "fused": results["fused"]["incidents"], "reduction": round(1 - results["fused"]["incidents"] / separate, 3) if separate else None},
            "note": "Runs in this corpus are ~75 s apart, so ±150 s run windows overlap; per-run fragmentation and the 'spanning more than one run' count are dominated by that overlap and are not informative here.",
            "summary": {k: {"alerts": v["alerts"], "incidents": v["incidents"], "attributed": v["runs_whose_incident_names_the_elevated_process"]} for k, v in results.items()}}
