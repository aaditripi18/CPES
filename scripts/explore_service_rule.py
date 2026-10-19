"""Exploratory check (2026-10-19): can the service rule's vendor false alarms be separated from attacker
binaries with the telemetry we have? Development data only (lab corpus-v3, EVTX-ATTACK-SAMPLES,
the 21 OTRF captures already used). Prints, per SYSTEM binary outside \Windows\ and \Program Files:
own-image signature (EID 7), whether it was written in the capture (EID 11), \Services\ registry
writes in the 300 s before it started, and service-install events (7045/4697) naming it.

Results are summarised in docs/design/service-rule-feasibility.md."""

from __future__ import annotations

import glob
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from evaluation import data, evtx_source, otrf_source  # noqa: E402

SYSTEM_PATHS = ("\windows\\", "\program files")


def low(value) -> str:
    return str(value or "").lower()


def ts(value) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(str(value).replace("Z", "").replace("T", " ")[:26])


def probe(name: str, records: list[dict]) -> None:
    procs, signatures, drops, writes, installs = {}, {}, set(), [], []
    for r in records:
        eid, image = r["eid"], r.get("image")
        if eid == "1" and low(r.get("integrity")) == "system" and image and not any(p in low(image) for p in SYSTEM_PATHS):
            procs.setdefault(low(image), (image, ts(r.get("time")), r.get("guid")))
        elif eid == "7" and r.get("loaded"):
            signatures[(r.get("guid"), low(r.get("loaded")))] = r.get("signed")
        elif eid == "11" and r.get("target"):
            drops.add(low(r.get("target")))
        elif eid in ("12", "13", "14") and "\services\\" in low(r.get("object")) and r.get("time"):
            writes.append(ts(r.get("time")))
        elif eid in ("7045", "4697"):
            installs.append(low(r.get("service_path")))
    for key, (image, started, guid) in procs.items():
        before = sum(1 for t in writes if started and 0 <= (started - t).total_seconds() <= 300)
        named = any(key.split("\\")[-1] in p for p in installs)
        print(f"{name[:40]:40} | {image.split(chr(92))[-1]:28} | sig {str(signatures.get((guid, key))):6} | dropped {str(key in drops):5} | svc-writes<=300s {before:5} | install-event {named}")


def sysmon_view(r: dict) -> dict:
    return {"eid": str(r.get("EventID")), "image": r.get("Image"), "integrity": r.get("IntegrityLevel"), "time": r.get("UtcTime"),
            "guid": r.get("ProcessGuid"), "loaded": r.get("ImageLoaded"), "signed": r.get("Signed"), "target": r.get("TargetFilename"),
            "object": r.get("TargetObject"), "service_path": r.get("ImagePath") or r.get("ServiceFileName")}


def ecs_view(d: dict) -> dict:
    p, ed = d.get("process") or {}, (d.get("winlog") or {}).get("event_data") or {}
    return {"eid": str((d.get("event") or {}).get("code")), "image": p.get("executable"), "integrity": ed.get("IntegrityLevel"), "time": d.get("@timestamp"),
            "guid": p.get("entity_id"), "loaded": (d.get("file") or {}).get("path") if str((d.get("event") or {}).get("code")) == "7" else None,
            "signed": ed.get("Signed"), "target": (d.get("file") or {}).get("path"), "object": (d.get("registry") or {}).get("path"), "service_path": ed.get("ImagePath")}


def main() -> None:
    for archive in sorted(glob.glob("external/otrf/zips/*.zip")):
        probe("OTRF " + Path(archive).name, [sysmon_view(r) for r in otrf_source.records(Path(archive))])
    for path in sorted(glob.glob("external/evtx-attack-samples/privesc/*.evtx")):
        rows = [dict(d["Event"].get("EventData") or {}, EventID=d["Event"]["System"]["EventID"]) for d in evtx_source.records(Path(path))]
        probe("EVTX " + Path(path).name, [sysmon_view(r) for r in rows])
    try:
        probe("LAB corpus-v3", [ecs_view(d) for d in data.documents()])
    except FileNotFoundError:
        print("lab corpus not available (private, not in the repository)")


if __name__ == "__main__":
    main()
