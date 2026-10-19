"""Protocol service-signature-v1 (pre-registered in docs/design/service-signature-suppressor.md).

S0 = the service rule as is; S1 = S0 with the own-image signature suppressor.
Test set T: 100 OTRF host archives never used before. Non-regression: lab
corpus-v3 (package engine) and EVTX-ATTACK-SAMPLES privilege escalation.
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
from cpes.context.signatures import ImageLoad, validly_signed_processes
from cpes.orchestration import CpesPipeline, PipelineConfiguration
from cpes.orchestration.evidence import EvidenceChannelBuilder
from cpes.orchestration.translation import CanonicalEventTranslator
from cpes.windowing.models import SlidingWindowParameters

from . import data, evtx_source, external, heldout, otrf_source
from .engine import EVIDENCE_SETTINGS, MAPPING, build_evidence, frozen_model, make_generator, make_resolver

SIGNAL = "service_dropped_binary"
TEST_DIR = data.ROOT / "external" / "otrf" / "test"
SPAN, ADVANCE = 300.0, 150.0
VENDOR_PREFIXES = ("c:\\programdata\\microsoft\\windows defender\\", "c:\\windowsazure\\", "c:\\packages\\plugins\\")


def vendor(image_path: str | None) -> bool:
    return str(image_path or "").lower().startswith(VENDOR_PREFIXES)


def service_anchors(events, evidence_items, signed: frozenset[str]) -> dict[str, str]:
    """process_guid -> image path for every service anchor in a detected window."""

    stamps = [datetime.fromisoformat(e.source_timestamp.replace("Z", "+00:00")) for e in events]
    params = SlidingWindowParameters(min(stamps), max(stamps) + timedelta(seconds=SPAN), SPAN, ADVANCE)
    configuration = PipelineConfiguration(params, frozen_model(), Decimal("0.5"), make_generator(make_resolver(signed)))
    context = CpesPipeline().run(events, configuration, evidence=evidence_items)
    images = {}
    for event in events:
        if isinstance(event.process_guid, str) and event.image_path and event.process_guid not in images:
            images[event.process_guid] = event.image_path
    return {
        r.process_guid: images.get(r.process_guid, "not in capture")
        for d in context.threshold_decisions if d.is_detected
        for c in d.cpes_score_result.evidence_contributions if c.signal_id == SIGNAL
        for r in c.source_references
    }


def compare(name: str, events, evidence_items, loads) -> dict:
    signed = validly_signed_processes(loads)
    try:
        s0 = service_anchors(events, evidence_items, frozenset())
        s1 = service_anchors(events, evidence_items, signed)
    except ValueError as error:
        return {"file": name, "outcome": "pipeline_refused", "error": str(error)}
    removed = {g: s0[g] for g in s0 if g not in s1}
    return {
        "file": name, "own_image_load_records": sum(1 for l in loads if str(l.image_path or "").lower() == str(l.loaded_path or "").lower() and l.image_path),
        "validly_signed_processes": len(signed),
        "s0": sorted({(img, vendor(img)) for img in s0.values()}), "s1": sorted({(img, vendor(img)) for img in s1.values()}),
        "removed": sorted({(img, vendor(img)) for img in removed.values()}), "added": sorted(set(s1) - set(s0)),
    }


# ---------------------------------------------------------------- test set T


def _otrf_loads(docs) -> list[ImageLoad]:
    return [ImageLoad(d.get("ProcessGuid"), d.get("Image"), d.get("ImageLoaded"), d.get("Signed"), d.get("SignatureStatus")) for d in docs if str(d.get("EventID")) == "7"]


def evaluate_otrf(path: Path) -> dict:
    docs = [heldout.prepare(d, i) for i, d in enumerate(otrf_source.sysmon_records(path))]
    if not docs:
        return {"file": path.name, "outcome": "not_applicable_no_sysmon"}
    mapper, translator = CanonicalEventMapper(load_mapping_configuration(heldout.CANONICAL)), CanonicalEventTranslator()
    events = []
    for document in docs:
        try:
            event = mapper.map_document(document)
            translator.translate([event])
            events.append(event)
        except (ValueError, TypeError):
            continue
    if not events:
        return {"file": path.name, "outcome": "no_usable_records"}
    pipes, threads = EvidenceRecordMapper(load_evidence_mapping(heldout.PIPES)), EvidenceRecordMapper(load_evidence_mapping(heldout.THREADS))
    records = []
    for d in docs:
        code = str(d.get("EventID"))
        if code in ("8", "17", "18"):
            try:
                records.append((pipes if code != "8" else threads).map_document(d))
            except ValueError:
                pass
    channels = EvidenceChannelBuilder(**EVIDENCE_SETTINGS).build(records)
    return compare(path.name, events, channels.items, _otrf_loads(docs))


def verify_test_manifest() -> list[dict]:
    entry = next(d for d in json.loads(heldout.MANIFEST.read_text(encoding="utf-8"))["datasets"] if d["id"] == "otrf-security-datasets-test-t")
    out = []
    for item in entry["files"]:
        path = TEST_DIR / item["name"]
        if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError(f"test archive missing or changed: {item['name']} (run python scripts/fetch_external.py)")
        out.append(item["name"])
    return out


# ------------------------------------------------------------ non-regression


def evaluate_evtx(path: Path) -> dict:
    docs = evtx_source.sysmon_records(path)
    if not docs:
        return {"file": path.name, "outcome": "not_applicable"}
    mapper, translator = CanonicalEventMapper(load_mapping_configuration(external.CANONICAL_MAPPING)), CanonicalEventTranslator()
    events = []
    for document in docs:
        try:
            event = mapper.map_document(document)
            translator.translate([event])
            events.append(event)
        except (ValueError, TypeError):
            continue
    if not events:
        return {"file": path.name, "outcome": "no_usable_records"}
    pipes = EvidenceRecordMapper(load_evidence_mapping(external.PIPE_MAPPING))
    threads = EvidenceRecordMapper(load_evidence_mapping(external.THREAD_MAPPING))
    records = []
    for document in docs:
        code = str(document["Event"]["System"].get("EventID"))
        if code in ("17", "18"):
            records.append(pipes.map_document(document))
        elif code == "8":
            records.append(threads.map_document(document))
    channels = EvidenceChannelBuilder(**EVIDENCE_SETTINGS).build(records)
    loads = []
    for document in docs:
        if str(document["Event"]["System"].get("EventID")) == "7":
            e = document["Event"].get("EventData") or {}
            loads.append(ImageLoad(e.get("ProcessGuid"), e.get("Image"), e.get("ImageLoaded"), e.get("Signed"), e.get("SignatureStatus")))
    return compare(path.name, events, channels.items, loads)


def evaluate_lab() -> dict:
    docs = list(data.documents())
    mapper = CanonicalEventMapper(load_mapping_configuration(MAPPING))
    events = [mapper.map_document(d) for d in docs]
    loads = []
    for d in docs:
        if str((d.get("event") or {}).get("code")) == "7":
            p, ed = d.get("process") or {}, (d.get("winlog") or {}).get("event_data") or {}
            loads.append(ImageLoad(p.get("entity_id"), p.get("executable"), (d.get("file") or {}).get("path"), ed.get("Signed"), ed.get("SignatureStatus")))
    return compare("corpus-v3", events, build_evidence(docs).items, loads)


def run() -> dict:
    names = verify_test_manifest()
    files = [evaluate_otrf(TEST_DIR / name) for name in names]
    scored = [f for f in files if "s0" in f]
    s0 = [(f["file"], img, v) for f in scored for img, v in f["s0"]]
    s1 = [(f["file"], img, v) for f in scored for img, v in f["s1"]]
    removed = [(f["file"], img, v) for f in scored for img, v in f["removed"]]
    added = sum(len(f["added"]) for f in scored)
    duplicate = {"defense_evasion__empire_wmic_add_user_backdoor.zip", "lateral_movement__empire_wmic_add_user_backdoor.zip"}
    dedup = lambda rows: [r for r in rows if r[0] != "lateral_movement__empire_wmic_add_user_backdoor.zip"]  # noqa: E731
    test = {
        "archives": len(files), "outcomes": dict(Counter(f.get("outcome", "scored") for f in files)),
        "archives_with_own_image_signature_records": sum(1 for f in scored if f["own_image_load_records"]),
        "s0_anchors": len(s0), "s0_vendor": sum(v for *_, v in s0), "s0_other": sum(not v for *_, v in s0),
        "s1_anchors": len(s1), "s1_vendor": sum(v for *_, v in s1), "s1_other": sum(not v for *_, v in s1),
        "removed_vendor": sum(v for *_, v in removed), "removed_other": sum(not v for *_, v in removed), "anchors_added": added,
        "deduplicated": {"note": "the same capture is published under two tactics; counted once here", "duplicates": sorted(duplicate),
                         "s0_vendor": sum(v for *_, v in dedup(s0)), "removed_vendor": sum(v for *_, v in dedup(removed))},
        "s0_other_anchors": sorted({(f, img) for f, img, v in s0 if not v}),
        "removed_anchors": sorted({(f, img, "vendor" if v else "other") for f, img, v in removed}),
    }
    evtx = [evaluate_evtx(p) for p in sorted(external.SAMPLES.glob("*.evtx"))]
    evtx_changed = [f["file"] for f in evtx if "s0" in f and (f["removed"] or f["added"])]
    try:
        lab = evaluate_lab()
        lab_summary = {k: (len(v) if isinstance(v, list) else v) for k, v in lab.items() if k != "file"}
        lab_summary["s0_images"] = sorted({img.split("\\")[-1] for img, _ in lab.get("s0", [])})
        lab_changed = bool(lab.get("removed") or lab.get("added"))
    except FileNotFoundError:
        lab_summary, lab_changed = {"outcome": "lab corpus not available"}, None
    safety = test["removed_other"] == 0 and not evtx_changed and lab_changed is False
    adopt = safety and test["removed_vendor"] >= 1
    return {
        "test_set": test, "files": files,
        "non_regression": {"evtx_files": len(evtx), "evtx_files_changed": evtx_changed, "lab": lab_summary, "lab_changed": lab_changed},
        "verdict": {"adopt_s1": adopt, "safety_held": safety,
                    "rule": "adopt iff S1 removes >= 1 vendor anchor on T, removes no other anchor on T, and leaves the non-regression sets unchanged (pre-registered)"},
        "summary": {"s0_vendor": test["s0_vendor"], "removed_vendor": test["removed_vendor"], "removed_other": test["removed_other"], "adopt_s1": adopt},
    }
