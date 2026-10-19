"""Upload, explorer, inventory and system endpoints."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import jsonl, upload


def test_upload_rejects_unsupported_and_empty_files(client):
    assert upload(client, "notes.txt", b"hello").status_code == 400
    assert upload(client, "empty.jsonl", b"   \n").status_code == 400


def test_upload_stores_bytes_and_checksum(client, data_root, uac_documents):
    body = jsonl(uac_documents)
    response = upload(client, "uac.jsonl", body, name="test fixture", declared_synthetic="true", declared_source="hand-written test fixture")
    assert response.status_code == 200
    meta = response.json()
    assert meta["category"] == "synthetic" and meta["records"] == len(uac_documents)
    stored = data_root / "datasets" / meta["id"] / meta["stored_file"]
    assert stored.read_bytes() == body
    import hashlib

    assert meta["sha256"] == hashlib.sha256(body).hexdigest()
    assert meta["validation_report"]["status"] == "valid"
    ids = [d["id"] for d in client.get("/api/inventory").json()["datasets"]]
    assert meta["id"] in ids and "lab-corpus-v3" in ids


def test_csv_upload_validates_through_the_same_mapping(client):
    text = "@timestamp,winlog.record_id,event.code,process.entity_id,process.parent.entity_id,process.executable,winlog.event_data.IntegrityLevel\n2026-07-20T10:00:00Z,1,1,{A},,C:\\x.exe,Medium\n2026-07-20T10:00:01Z,2,1,{B},{A},C:\\y.exe,High\n"
    meta = upload(client, "rows.csv", text.encode()).json()
    report = meta["validation_report"]
    assert report["status"] == "valid" and report["accepted"] == 2
    assert report["lineage_preview"]["chains"] == 1


def test_records_filtering_search_sort_and_inspection(client, uac_documents):
    meta = upload(client, "uac.jsonl", jsonl(uac_documents)).json()
    base = f"/api/datasets/{meta['id']}/records"
    page = client.get(base, params={"f.event.code": "13"}).json()
    assert page["total"] == 1 and page["rows"][0]["cells"]["event.code"] == "13"
    assert client.get(base, params={"q": "fodhelper"}).json()["total"] == 2  # command line + image
    assert client.get(base, params={"missing": "registry.path"}).json()["total"] == len(uac_documents) - 1
    timed = client.get(base, params={"time_from": "2026-07-20T10:01:00Z"}).json()
    assert timed["total"] == 3
    ordered = client.get(base, params={"sort": "__time__", "order": "desc", "limit": 1}).json()
    assert ordered["rows"][0]["cells"]["@timestamp"] == "2026-07-20T10:01:20Z"
    facets = client.get(base).json()["facets"]
    assert dict(facets["event.code"]["values"])["1"] == 6
    record = client.get(f"/api/datasets/{meta['id']}/records/2").json()
    assert record["original"] == uac_documents[2]
    exported = client.get(f"/api/datasets/{meta['id']}/export", params={"f.event.code": "13"}).text.strip().splitlines()
    assert [json.loads(line) for line in exported] == [uac_documents[2]]


def test_upload_with_runs_cannot_be_deleted(client, uac_documents):
    meta = upload(client, "uac.jsonl", jsonl(uac_documents)).json()
    client.post("/api/runs", json={"dataset_id": meta["id"]})
    assert client.delete(f"/api/datasets/{meta['id']}").status_code == 400
    other = upload(client, "other.jsonl", jsonl(uac_documents)).json()
    assert client.delete(f"/api/datasets/{other['id']}").status_code == 200
    assert client.delete("/api/datasets/lab-corpus-v3").status_code == 400


def test_system_reports_signal_wiring(client):
    system = client.get("/api/system").json()
    wiring = {s["signal_id"]: s["wired"] for s in system["signals"]}
    assert wiring == {"autoelevation_lolbin": True, "service_dropped_binary": True, "remote_thread_injection": True, "token_impersonation": True}
    assert any("Single endpoint" in item for item in system["limitations"])


EVTX_SAMPLE = Path(__file__).resolve().parents[2] / "external" / "evtx-attack-samples" / "privesc" / "Sysmon_13_1_UAC_Bypass_EventVwrBypass.evtx"


@pytest.mark.skipif(not EVTX_SAMPLE.exists(), reason="external samples not fetched (python scripts/fetch_external.py)")
def test_evtx_upload_validates_and_detects(client):
    meta = upload(client, "eventvwr.evtx", EVTX_SAMPLE.read_bytes()).json()
    assert meta["format"] == "evtx" and meta["suggested_mapping"]["preset"] == "evtx-sysmon-field-mapping-v1"
    assert meta["validation_report"]["status"] == "valid" and meta["validation_report"]["accepted"] > 0
    run = client.post("/api/runs", json={"dataset_id": meta["id"]}).json()
    status = client.get(f"/api/runs/{run['id']}").json()
    assert status["state"] == "completed", status.get("traceback")
    assert status["summary"]["signals_fired"].get("autoelevation_lolbin", 0) >= 1
    rows = client.get(f"/api/datasets/{meta['id']}/records", params={"f.Event.System.EventID": "13"}).json()
    assert rows["total"] >= 1


def test_live_replay_session_streams_alerts(client, uac_documents):
    import time

    meta = upload(client, "uac.jsonl", jsonl(uac_documents)).json()
    session = client.post("/api/live", json={"source": "replay", "dataset_id": meta["id"], "speed": "max", "span_seconds": 60, "advance_seconds": 30}).json()
    for _ in range(100):
        snap = client.get(f"/api/live/{session['id']}").json()
        if snap["state"] in ("completed", "failed"):
            break
        time.sleep(0.05)
    assert snap["state"] == "completed", snap.get("error")
    assert snap["events"] == len(uac_documents)
    assert snap["alert_count"] >= 1
    first = snap["alerts"][0]
    assert first["contributions"][0]["signal_id"] == "autoelevation_lolbin"
    assert any("re-associated" in line for line in first["explanation"])
    assert client.get(f"/api/live/{session['id']}", params={"since": snap["alert_count"]}).json()["alerts"] == []
    assert client.post("/api/live", json={"source": "elasticsearch"}).status_code == 400  # not configured in tests
