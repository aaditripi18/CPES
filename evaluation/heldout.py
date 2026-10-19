"""Protocol heldout-otrf-v2: CPES v1 vs v2 (and baselines, Sigma) on OTRF captures.

Pre-registered in docs/design/cpes-v2-heldout.md (committed before this ran).
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path

from cpes.adapters.evidence import EvidenceRecordMapper, load_evidence_mapping
from cpes.adapters.mapping import CanonicalEventMapper, load_mapping_configuration
from cpes.baseline import SingleEventBaselineDetector
from cpes.detection.generic import GenericEscalationObservationGenerator
from cpes.orchestration import CompositeObservationGenerator, CpesPipeline, PipelineConfiguration
from cpes.orchestration.evidence import EvidenceChannelBuilder
from cpes.orchestration.resolved_observations import ResolvedSignalObservationGenerator
from cpes.orchestration.translation import CanonicalEventTranslator
from cpes.scoring.models import EvidenceModel, EvidenceTerm
from cpes.windowing.models import SlidingWindowParameters

from . import otrf_source
from .data import ROOT, SIGNALS
from .engine import EVIDENCE_SETTINGS, INTEGRITY_ORDER, make_resolver

ARCHIVES = ROOT / "external" / "otrf" / "zips"
MANIFEST = ROOT / "configs" / "external-datasets.json"
CANONICAL = ROOT / "configs" / "otrf-sysmon-field-mapping-v1.yaml"
PIPES = ROOT / "configs" / "otrf-sysmon-evidence-pipes-v1.yaml"
THREADS = ROOT / "configs" / "otrf-sysmon-evidence-threads-v1.yaml"
MODELS = ROOT / "dashboard" / "models"
SPAN, ADVANCE = 300.0, 150.0
GENERIC = "unexplained_privilege_gain"

CATEGORIES = {  # fixed from published file names/folders before running
    "empire_uac_shellapi_fodhelper.zip": "uac_listed_binary",
    "psh_cmstp_execution_bypassuac.zip": "uac_other_method",
    "empire_dllinjection_LoadLibrary_CreateRemoteThread.zip": "code_injection",
    "empire_psinject_PEinjection.zip": "code_injection",
    "psh_mavinject_dll_notepad.zip": "code_injection",
    "purplesharp_pe_injection_createremotethread.zip": "code_injection",
    "cmd_service_mod_fax.zip": "service_as_system",
    "cmd_psexec_lsa_secrets_dump.zip": "service_as_system",
    "empire_psexec_dcerpc_tcp_svcctl.zip": "service_as_system",
    "empire_smbexec_dcerpc_smb_svcctl.zip": "service_as_system",
    "covenant_sharpsc_create_dcerpc_smb_svcctl.zip": "service_as_system",
    "covenant_sharpsc_start_dcerpc_smb_svcctl.zip": "service_as_system",
    "empire_shell_dcerpc_smb_service_dll_hijack.zip": "service_as_system",
    "empire_invoke_runas.tar.gz": "token_runas",
    "empire_persistence_registry_modification_run_keys_elevated_user.zip": "control_not_privesc",
    "empire_schtasks_creation_execution_elevated_user.zip": "control_not_privesc",
    "empire_wmi_local_event_subscriptions_elevated_user.zip": "control_not_privesc",
    "cmd_disable_eventlog_service_startuptype_modification_via_registry.zip": "control_not_privesc",
    "psh_disable_eventlog_service_startuptype_modification.zip": "control_not_privesc",
    "reg_disable_eventlog_service_startuptype_modification_via_registry.zip": "control_not_privesc",
    "psh_lsass_memory_dump_comsvcs.zip": "control_not_privesc",
}
CATEGORY_ORDER = ("uac_listed_binary", "uac_other_method", "code_injection", "service_as_system", "token_runas", "control_not_privesc")
PRIVESC = {"uac_listed_binary", "uac_other_method", "code_injection", "service_as_system", "token_runas"}


def verify_manifest() -> list[dict]:
    import hashlib

    entry = next(d for d in json.loads(MANIFEST.read_text(encoding="utf-8"))["datasets"] if d["id"] == "otrf-security-datasets")
    out = []
    for item in entry["files"]:
        path = ARCHIVES / item["name"]
        if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError(f"OTRF file missing or changed: {item['name']} (run python scripts/fetch_external.py)")
        out.append({"path": f"external/otrf/zips/{item['name']}", "sha256": item["sha256"]})
    if set(CATEGORIES) != {item["name"] for item in entry["files"]}:
        raise ValueError("category table and manifest disagree")
    return out


def _model(model_id: str) -> tuple[EvidenceModel, tuple[str, ...]]:
    model = json.loads((MODELS / f"{model_id}.json").read_text(encoding="utf-8"))
    terms = tuple(EvidenceTerm(t["signal_id"], Decimal(t["signed_log_likelihood"])) for t in model["terms"])
    return EvidenceModel(Decimal(model["prior_applied"]), terms), tuple(t.signal_id for t in terms)


def _generator(resolver, signal_ids: tuple[str, ...]) -> CompositeObservationGenerator:
    parts = [ResolvedSignalObservationGenerator(s, resolver, s) for s in SIGNALS]
    if GENERIC in signal_ids:
        parts.append(GenericEscalationObservationGenerator(GENERIC, INTEGRITY_ORDER, resolver))
    return CompositeObservationGenerator(tuple(parts))


def _basename(path) -> str:
    return str(path or "").replace("/", "\\").split("\\")[-1].lower()


def prepare(document: dict, position: int) -> dict:
    """Copy of a record with the two documented derived fields (Amendment 1)."""

    copy = dict(document)
    utc = document.get("UtcTime")
    if isinstance(utc, str) and utc.strip():
        copy["__cpes_utc_time"] = utc.strip().replace(" ", "T") + "Z"
    record = document.get("RecordNumber")
    copy["__cpes_event_id"] = str(record) if record not in (None, "") else f"pos-{position + 1:07d}"
    return copy


def evaluate_file(path: Path, sigma_rules=None) -> dict:
    docs = [prepare(d, i) for i, d in enumerate(otrf_source.sysmon_records(path))]
    out: dict = {"file": path.name, "category": CATEGORIES[path.name], "sysmon_records": len(docs)}
    if not docs:
        out["outcome"] = "not_applicable_no_sysmon"
        return out
    mapper, translator = CanonicalEventMapper(load_mapping_configuration(CANONICAL)), CanonicalEventTranslator()
    events, rejected = [], Counter()
    for document in docs:
        try:
            event = mapper.map_document(document)
            translator.translate([event])
            events.append(event)
        except (ValueError, TypeError) as error:
            rejected[str(error)] += 1
    pipes, threads = EvidenceRecordMapper(load_evidence_mapping(PIPES)), EvidenceRecordMapper(load_evidence_mapping(THREADS))
    evidence_records, evidence_unmappable = [], Counter()
    for d in docs:
        code = str(d.get("EventID"))
        if code not in ("8", "17", "18"):
            continue
        try:
            evidence_records.append((pipes if code in ("17", "18") else threads).map_document(d))
        except ValueError as error:
            evidence_unmappable[str(error)] += 1
    channels = EvidenceChannelBuilder(**EVIDENCE_SETTINGS).build(evidence_records)
    out.update(records_accepted=len(events), records_rejected=dict(rejected), evidence={"pipe": len(channels.pipes), "remote_thread": len(channels.remote_threads), "skipped": dict(channels.skipped), "unmappable": dict(evidence_unmappable)})
    if not events:
        out["outcome"] = "no_usable_records"
        return out
    images = {}
    for event in events:
        if isinstance(event.process_guid, str) and event.image_path and event.process_guid not in images:
            images[event.process_guid] = _basename(event.image_path)
    stamps = [datetime.fromisoformat(e.source_timestamp.replace("Z", "+00:00")) for e in events]
    params = SlidingWindowParameters(min(stamps), max(stamps) + timedelta(seconds=SPAN), SPAN, ADVANCE)
    detectors = {}
    windows = None
    for model_id in ("research-v3-full-table", "cpes-v2"):
        resolver = make_resolver()
        model, signal_ids = _model(model_id)
        try:
            context = CpesPipeline().run(events, PipelineConfiguration(params, model, Decimal("0.5"), _generator(resolver, signal_ids)), evidence=channels.items)
        except ValueError as error:
            detectors[model_id] = {"refused": str(error)}
            continue
        windows = windows or context.detection_windows
        anchors = sorted({f"{c.signal_id}: {images.get(r.process_guid, 'not in capture')}" for d in context.threshold_decisions if d.is_detected for c in d.cpes_score_result.evidence_contributions for r in c.source_references})
        detectors[model_id] = {"detected": bool(anchors), "anchors": anchors, "alert_windows": sum(d.is_detected for d in context.threshold_decisions)}
    if windows is not None:
        baseline = SingleEventBaselineDetector(INTEGRITY_ORDER)
        hits = sorted({images.get(g, "not in capture") for w in windows for g in baseline.evaluate(w.event_group).triggering_process_guids})
        detectors["single_event"] = {"detected": bool(hits), "anchors": hits}
        generic = GenericEscalationObservationGenerator(GENERIC, INTEGRITY_ORDER, make_resolver())
        hits = sorted({images.get(r.process_guid, "not in capture") for w in windows for o in generic.generate(w.event_group) if o.is_present for r in o.source_references})
        detectors["generic_alone"] = {"detected": bool(hits), "anchors": hits}
    if sigma_rules is not None:
        from .sigma import match_events

        views = [(str(d.get("EventID")), {**d, "EventID": str(d.get("EventID"))}) for d in docs]
        titles = sorted({r.title for _, r in match_events(sigma_rules, views) if r.level in ("high", "critical")})
        detectors["sigma_core_high"] = {"detected": bool(titles), "anchors": titles[:12], "rules": len(titles)}
    out["detectors"] = detectors
    return out


def run() -> dict:
    from .sigma import load_rules

    verify_manifest()
    sigma = load_rules(ROOT / "external" / "sigma" / "core")
    files = [evaluate_file(ARCHIVES / name, sigma) for name in sorted(CATEGORIES)]
    names = ("research-v3-full-table", "cpes-v2", "generic_alone", "single_event", "sigma_core_high")
    summary = {}
    for category in CATEGORY_ORDER:
        rows = [f for f in files if f["category"] == category and "detectors" in f]
        summary[category] = {"files": sum(f["category"] == category for f in files), "applicable": len(rows), **{n: sum(bool(f["detectors"].get(n, {}).get("detected")) for f in rows) for n in names}}
    privesc = [f for f in files if f["category"] in PRIVESC and "detectors" in f]
    controls = [f for f in files if f["category"] == "control_not_privesc" and "detectors" in f]
    control_events = sum(f["sysmon_records"] for f in controls)
    primary = {
        n: {
            "privesc_files_detected": f"{sum(bool(f['detectors'].get(n, {}).get('detected')) for f in privesc)}/{len(privesc)}",
            "control_files_alerted": f"{sum(bool(f['detectors'].get(n, {}).get('detected')) for f in controls)}/{len(controls)}",
        }
        for n in names
    }
    for n in ("research-v3-full-table", "cpes-v2"):
        alerts = sum(f["detectors"].get(n, {}).get("alert_windows", 0) for f in controls)
        primary[n]["control_alert_windows_per_10k_events"] = round(alerts / control_events * 10000, 2) if control_events else None
    v1, v2 = primary["research-v3-full-table"], primary["cpes-v2"]
    gain = int(v2["privesc_files_detected"].split("/")[0]) - int(v1["privesc_files_detected"].split("/")[0])
    cost = int(v2["control_files_alerted"].split("/")[0]) - int(v1["control_files_alerted"].split("/")[0])
    verdict = "improvement" if gain > 0 and cost <= 1 else "no improvement" if gain <= 0 else "gain with control cost above the pre-registered bound"
    return {"dataset": "OTRF Security-Datasets @ d9d40ef (21 archives)", "summary_by_category": summary, "primary": primary,
            "v2_verdict": {"gain_privesc_files": gain, "extra_control_files": cost, "verdict": verdict, "rule": "improvement iff v2 detects more privesc files and alerts on at most one more control file than v1 (pre-registered)"},
            "files": files, "summary": {"v1": v1["privesc_files_detected"], "v2": v2["privesc_files_detected"], "verdict": verdict}}
