"""Run the cpes package on corpus-v3 and reduce its observations to process flags.

The resolver discriminators are the same tokens the research scripts use
(demo/cpes_demo.py, analysis/corpus_eval_grouped.py). Observations do not depend
on weights, so any evidence model with terms for the four signals gives the same
flags; the frozen research model is used.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path

from cpes.adapters.evidence import EvidenceRecordMapper, load_evidence_mapping
from cpes.adapters.mapping import CanonicalEventMapper, load_mapping_configuration
from cpes.baseline import SingleEventBaselineDetector
from cpes.context.resolver import ContextResolver
from cpes.orchestration import CompositeObservationGenerator, CpesPipeline, PipelineConfiguration
from cpes.orchestration.evidence import EvidenceChannelBuilder
from cpes.orchestration.resolved_observations import ResolvedSignalObservationGenerator
from cpes.scoring.models import EvidenceModel, EvidenceTerm
from cpes.windowing.models import SlidingWindowParameters

from .data import ROOT, SIGNALS, documents

INTEGRITY_ORDER = ("Untrusted", "Low", "Medium", "High", "System")
RESOLVER_SETTINGS = {
    "integrity_order": INTEGRITY_ORDER,
    "auto_elevating_images": ("fodhelper.exe", "eventvwr.exe", "sdclt.exe", "computerdefaults.exe"),
    "hijack_registry_tokens": ("ms-settings", "mscfile", "\\shell\\open\\command"),
    "elevated_levels": ("high", "system"),
    "system_path_tokens": ("\\windows\\", "\\program files"),
    "service_registry_tokens": ("\\services\\",),
    "interactive_shell_images": ("cmd.exe", "powershell.exe", "pwsh.exe"),
}
EVIDENCE_SETTINGS = {
    "pipe_create_codes": ("17",),
    "pipe_connect_codes": ("18",),
    "remote_thread_codes": ("8",),
    "system_user_names": ("SYSTEM",),
}
MAPPING = ROOT / "configs" / "elastic-sysmon-field-mapping-v1.yaml"
EVIDENCE_MAPPING = ROOT / "configs" / "elastic-sysmon-evidence-mapping-v1.yaml"
MAPPING_V2 = ROOT / "configs" / "elastic-sysmon-field-mapping-v2.yaml"
EVIDENCE_MAPPING_V2 = ROOT / "configs" / "elastic-sysmon-evidence-mapping-v2.yaml"
SERVICE_INSTALL_CODES = ("7045", "4697")

# Resolver variants (docs/design/package-v3-and-vm2.md). "package-v2" is the
# package as every earlier result used it.
MODES = {
    "package-v2": {},
    # Replication of the published research rules, including their two NAME RULES
    # (mavinject.exe for injection, "atomicservice" for service).
    "research-v3": {
        "uac_requires_hijack_write": False,
        "service_parent_images": ("services.exe",),
        "service_image_tokens": ("atomicservice",),
        "injection_images": ("mavinject.exe",),
        "remote_thread_source_images": ("mavinject.exe",),
        "token_first_creator_only": True,
    },
    # Structural fixes B1 (+ B2 when the data has service-install records).
    "structural-v3": {"service_parent_images": ("services.exe",), "require_service_install": True},
}
MODEL = ROOT / "dashboard" / "models" / "research-v3-full-table.json"


def make_resolver(validly_signed_process_guids: frozenset[str] = frozenset(), mode: str = "package-v2", *, has_service_installs: bool = False) -> ContextResolver:
    s = RESOLVER_SETTINGS
    options = dict(MODES[mode])
    if options.get("require_service_install") and not has_service_installs:
        options["require_service_install"] = False  # B2 applies only to telemetry that records installs
    return ContextResolver(
        s["integrity_order"], s["auto_elevating_images"], s["hijack_registry_tokens"],
        elevated_levels=s["elevated_levels"], system_path_tokens=s["system_path_tokens"],
        service_registry_tokens=s["service_registry_tokens"], interactive_shell_images=s["interactive_shell_images"],
        validly_signed_process_guids=validly_signed_process_guids, **options,
    )


def make_generator(resolver: ContextResolver) -> CompositeObservationGenerator:
    return CompositeObservationGenerator(tuple(ResolvedSignalObservationGenerator(signal, resolver, signal) for signal in SIGNALS))


def frozen_model() -> EvidenceModel:
    model = json.loads(MODEL.read_text(encoding="utf-8"))
    terms = {t["signal_id"]: Decimal(t["signed_log_likelihood"]) for t in model["terms"]}
    return EvidenceModel(Decimal(model["prior_applied"]), tuple(EvidenceTerm(s, terms[s]) for s in SIGNALS))


def build_evidence(docs, *, v2: bool = False) -> tuple:
    mapper = EvidenceRecordMapper(load_evidence_mapping(EVIDENCE_MAPPING_V2 if v2 else EVIDENCE_MAPPING))
    settings = {**EVIDENCE_SETTINGS, "service_install_codes": SERVICE_INSTALL_CODES} if v2 else EVIDENCE_SETTINGS
    return EvidenceChannelBuilder(**settings).build(mapper.map_document(d) for d in docs)


def run_package(*, with_evidence: bool, span: float = 300.0, advance: float = 150.0, docs=None, generic: bool = False,
                bounds: tuple[datetime, datetime] | None = None, mode: str = "package-v2") -> dict:
    """``bounds`` fixes the window grid (start, end); by default it spans the documents.

    ``mode`` other than "package-v2" uses the v2 mappings (parent image, service installs).
    Service-install records (System/Security) feed only the evidence channel.
    """

    docs = documents() if docs is None else docs
    v2 = mode != "package-v2"
    mapper = CanonicalEventMapper(load_mapping_configuration(MAPPING_V2 if v2 else MAPPING))
    install_codes = set(SERVICE_INSTALL_CODES)
    # Service-install records (System/Security) are not process events in any mode.
    process_docs = [d for d in docs if str((d.get("event") or {}).get("code")) not in install_codes]
    events = [mapper.map_document(d) for d in process_docs]
    stamps = [datetime.fromisoformat(e.source_timestamp.replace("Z", "+00:00")) for e in events]
    start, end = bounds if bounds else (min(stamps), max(stamps) + timedelta(seconds=span))
    params = SlidingWindowParameters(start, end, span, advance)
    channels = build_evidence(docs, v2=v2) if with_evidence else None
    resolver = make_resolver(mode=mode, has_service_installs=bool(channels and channels.service_installs))
    configuration = PipelineConfiguration(params, frozen_model(), Decimal("0.5"), make_generator(resolver))
    context = CpesPipeline().run(events, configuration, evidence=channels.items if channels else ())

    flags: dict[str, set[str]] = defaultdict(set)
    window_anchors: list[tuple[str, tuple[str, ...]]] = []  # one entry per present observation per window
    for item in context.window_observations:
        for observation in item.observations:
            if observation.is_present:
                window_anchors.append((observation.signal_id, tuple(r.process_guid for r in observation.source_references)))
                for reference in observation.source_references:
                    flags[reference.process_guid].add(observation.signal_id)
    generic_flags: set[str] = set()
    if generic:
        from cpes.detection.generic import GenericEscalationObservationGenerator

        detector = GenericEscalationObservationGenerator("unexplained_privilege_gain", INTEGRITY_ORDER, resolver)
        generic_flags = {
            reference.process_guid
            for window in context.detection_windows
            for observation in detector.generate(window.event_group) if observation.is_present
            for reference in observation.source_references
        }
    baseline = SingleEventBaselineDetector(INTEGRITY_ORDER)
    baseline_flags = {g for item in context.window_observations for g in baseline.evaluate(item.detection_window.event_group).triggering_process_guids}
    chain_of = {guid: chain.lineage_chain_id for chain in context.lineage_chains for guid in chain.process_guids}
    return {
        "flags": {guid: tuple(sorted(signals)) for guid, signals in flags.items()},
        "window_anchors": window_anchors,
        "single_event_package": baseline_flags,
        "generic_flags": generic_flags,
        "chain_of": chain_of,
        "windows": len(context.detection_windows),
        "evidence": None if channels is None else {
            "pipes": len(channels.pipes),
            "remote_threads": len(channels.remote_threads),
            "service_installs": len(channels.service_installs),
            "skipped": dict(channels.skipped),
        },
        "settings": {"span_seconds": span, "advance_seconds": advance, "mode": mode, "mode_options": {k: (list(v) if isinstance(v, tuple) else v) for k, v in MODES[mode].items()},
                     "resolver": {k: list(v) for k, v in RESOLVER_SETTINGS.items()}, "evidence": {k: list(v) for k, v in EVIDENCE_SETTINGS.items()} if with_evidence else None},
    }
