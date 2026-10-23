"""Protocol ext-evtx-privesc: the shipped package engine on EVTX-ATTACK-SAMPLES.

Pre-registered in docs/design/external-and-evasion-evaluation.md (Part A). The
category of every file is fixed below from its published name, before running.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path

from cpes.adapters.evidence import EvidenceRecordMapper, load_evidence_mapping
from cpes.adapters.mapping import CanonicalEventMapper, load_mapping_configuration
from cpes.baseline import SingleEventBaselineDetector
from cpes.detection.generic import GenericEscalationObservationGenerator
from cpes.orchestration import CpesPipeline, PipelineConfiguration
from cpes.orchestration.evidence import EvidenceChannelBuilder
from cpes.orchestration.translation import CanonicalEventTranslator
from cpes.windowing.models import SlidingWindowParameters

from . import evtx_source
from .data import ROOT
from .engine import EVIDENCE_SETTINGS, INTEGRITY_ORDER, frozen_model, make_generator, make_resolver

SAMPLES = ROOT / "external" / "evtx-attack-samples" / "privesc"
MANIFEST = ROOT / "configs" / "external-datasets.json"
CANONICAL_MAPPING = ROOT / "configs" / "evtx-sysmon-field-mapping-v1.yaml"
CANONICAL_MAPPING_V2 = ROOT / "configs" / "evtx-sysmon-field-mapping-v2.yaml"
PIPE_MAPPING = ROOT / "configs" / "evtx-sysmon-evidence-pipes-v1.yaml"
THREAD_MAPPING = ROOT / "configs" / "evtx-sysmon-evidence-threads-v1.yaml"
SPAN, ADVANCE = 300.0, 150.0

UAC_LISTED = {"Sysmon_13_1_UACBypass_SDCLTBypass.evtx", "Sysmon_13_1_UAC_Bypass_EventVwrBypass.evtx"}
TOKEN = {
    "EfsPotato_sysmon_17_18_privesc_seimpersonate_to_system.evtx",
    "PrivEsc_Imperson_NetSvc_to_Sys_Decoder_Sysmon_1_17_18.evtx",
    "privesc_roguepotato_sysmon_17_18.evtx",
    "privesc_seimpersonate_tosys_spoolsv_sysmon_17_18.evtx",
    "sysmon_13_1_meterpreter_getsystem_NamedPipeImpersonation.evtx",
    "privesc_rotten_potato_from_webshell_metasploit_sysmon_1_8_3.evtx",
    "RogueWinRM.evtx",
}
SERVICE = {"privesc_unquoted_svc_sysmon_1_11.evtx", "sysmon_privesc_psexec_dwell.evtx"}
OTHER = {
    "CVE-2020-0796_SMBV3Ghost_LocalPrivEsc_Sysmon_3_1_10.evtx",
    "PrivEsc_CVE-2020-1313_Sysmon_13_UScheduler_Cmdline.evtx",
    "eop_appcontainer_il_broker_filewrite.evtx",
    "privesc_registry_symlink_CVE-2020-1377.evtx",
    "privesc_spoolfool_mahdihtm_sysmon_1_11_7_13.evtx",
    "privesc_spoolsv_spl_file_write_sysmon11.evtx",
    "privesc_sysmon_cve_20201030_spooler.evtx",
    "sysmon_1_11_exec_as_system_via_schedtask.evtx",
    "sysmon_privesc_from_admin_to_system_handle_inheritance.evtx",
}
CATEGORY_ORDER = ("uac_listed_lolbin", "uac_other_method", "token_impersonation", "service_abuse", "other_exploit", "not_applicable_no_sysmon")


def category(name: str, has_sysmon: bool) -> str:
    if not has_sysmon:
        return "not_applicable_no_sysmon"
    if name in UAC_LISTED:
        return "uac_listed_lolbin"
    if name in TOKEN:
        return "token_impersonation"
    if name in SERVICE:
        return "service_abuse"
    if name in OTHER:
        return "other_exploit"
    lowered = name.lower()
    if "uacme" in lowered or "uac" in lowered or "migwiz" in lowered:
        return "uac_other_method"
    raise ValueError(f"uncategorised Sysmon sample {name!r}; add it to the pre-registered table first.")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def verify_manifest() -> list[dict]:
    """Check every downloaded file against the committed SHA-256 manifest."""

    entry = next(d for d in manifest()["datasets"] if d["id"] == "evtx-attack-samples-privesc")
    problems = []
    for item in entry["files"]:
        path = SAMPLES / item["name"]
        if not path.exists():
            problems.append({"file": item["name"], "problem": "missing"})
        elif _sha256(path) != item["sha256"]:
            problems.append({"file": item["name"], "problem": "sha256 mismatch"})
    if problems:
        raise ValueError(f"external dataset does not match configs/external-datasets.json: {problems[:5]}")
    return [{"path": f"external/evtx-attack-samples/privesc/{i['name']}", "sha256": i["sha256"]} for i in entry["files"]]


def _basename(path) -> str:
    return str(path or "").replace("/", "\\").split("\\")[-1].lower()


def evaluate_file(path: Path, mode: str = "package-v2") -> dict:
    docs = evtx_source.sysmon_records(path)
    out: dict = {"file": path.name, "sysmon_records": len(docs), "category": category(path.name, bool(docs))}
    if not docs:
        out["outcome"] = "not_applicable"
        return out
    mapper = CanonicalEventMapper(load_mapping_configuration(CANONICAL_MAPPING if mode == "package-v2" else CANONICAL_MAPPING_V2))
    translator = CanonicalEventTranslator()
    events, rejections = [], Counter()
    for document in docs:
        try:
            event = mapper.map_document(document)
            translator.translate([event])
            events.append(event)
        except (ValueError, TypeError) as error:
            rejections[str(error)] += 1
    out["records_accepted"] = len(events)
    out["records_rejected"] = dict(rejections)
    pipe_mapper = EvidenceRecordMapper(load_evidence_mapping(PIPE_MAPPING))
    thread_mapper = EvidenceRecordMapper(load_evidence_mapping(THREAD_MAPPING))
    evidence_records = []
    for document in docs:
        code = str(document["Event"]["System"].get("EventID"))
        if code in ("17", "18"):
            evidence_records.append(pipe_mapper.map_document(document))
        elif code == "8":
            evidence_records.append(thread_mapper.map_document(document))
    channels = EvidenceChannelBuilder(**EVIDENCE_SETTINGS).build(evidence_records)
    out["evidence"] = {"pipe": len(channels.pipes), "remote_thread": len(channels.remote_threads), "skipped": dict(channels.skipped)}
    if not events:
        out["outcome"] = "no_usable_records"
        return out

    stamps = [datetime.fromisoformat(e.source_timestamp.replace("Z", "+00:00")) for e in events]
    resolver = make_resolver(mode=mode)
    configuration = PipelineConfiguration(
        SlidingWindowParameters(min(stamps), max(stamps) + timedelta(seconds=SPAN), SPAN, ADVANCE),
        frozen_model(), Decimal("0.5"), make_generator(resolver),
    )
    try:
        context = CpesPipeline().run(events, configuration, evidence=channels.items)
    except ValueError as error:  # e.g. conflicting parent assertions in the capture
        out["outcome"] = "pipeline_refused"
        out["error"] = str(error)
        return out

    images = {}
    for event in events:
        if isinstance(event.process_guid, str) and event.image_path and event.process_guid not in images:
            images[event.process_guid] = _basename(event.image_path)
    detected_signals: Counter = Counter()
    anchors: set[tuple[str, str]] = set()
    max_score = Decimal("-1")
    for item, decision in zip(context.window_observations, context.threshold_decisions):
        max_score = max(max_score, decision.cpes_score_result.cpes_score)
        if decision.is_detected:
            for contribution in decision.cpes_score_result.evidence_contributions:
                detected_signals[contribution.signal_id] += 1
                for reference in contribution.source_references:
                    anchors.add((contribution.signal_id, images.get(reference.process_guid, "not in capture")))
    generic = GenericEscalationObservationGenerator("unexplained_privilege_gain", INTEGRITY_ORDER, resolver)
    generic_anchors = {
        images.get(reference.process_guid, "not in capture")
        for window in context.detection_windows
        for observation in generic.generate(window.event_group) if observation.is_present
        for reference in observation.source_references
    }
    baseline = SingleEventBaselineDetector(INTEGRITY_ORDER)
    baseline_anchors = {images.get(g, "not in capture") for window in context.detection_windows for g in baseline.evaluate(window.event_group).triggering_process_guids}
    out.update(
        outcome="detected" if detected_signals else "not_detected",
        cpes_signals=dict(detected_signals),
        cpes_anchors=sorted(f"{signal}: {image}" for signal, image in anchors),
        max_score=str(max_score),
        generic_fired=bool(generic_anchors),
        generic_anchors=sorted(generic_anchors),
        baseline_fired=bool(baseline_anchors),
        baseline_anchors=sorted(baseline_anchors),
        lineage_chains=len(context.lineage_chains),
        integrity_levels=dict(Counter(e.integrity_level for e in events if e.integrity_level)),
    )
    return out


def run() -> dict:
    inputs = verify_manifest()
    files = [evaluate_file(SAMPLES / item["path"].split("/")[-1]) for item in inputs]
    summary = {}
    for name in CATEGORY_ORDER:
        rows = [f for f in files if f["category"] == name]
        if not rows:
            continue
        summary[name] = {
            "files": len(rows),
            "cpes_detected": sum(f.get("outcome") == "detected" for f in rows),
            "generic_fired": sum(bool(f.get("generic_fired")) for f in rows),
            "single_event_fired": sum(bool(f.get("baseline_fired")) for f in rows),
            "cpes_or_generic": sum(f.get("outcome") == "detected" or bool(f.get("generic_fired")) for f in rows),
            "pipeline_refused": sum(f.get("outcome") == "pipeline_refused" for f in rows),
        }
    return {
        "dataset": "sbousseaden/EVTX-ATTACK-SAMPLES Privilege Escalation @ 4ceed2f",
        "engine": {"span_seconds": SPAN, "advance_seconds": ADVANCE, "threshold": "0.5", "weights": "research-v3-full-table (lab corpus only; held out from this data)", "evidence_settings": {k: list(v) for k, v in EVIDENCE_SETTINGS.items()}},
        "summary_by_category": summary,
        "files": files,
        "note": "Unit = sample file; all files are attacks, so precision is not estimated. Every alert lists the image it is anchored on.",
    }
