"""Incidents and analyst outputs are derived from the run's own artifacts and agree with each other."""

from __future__ import annotations

import json

import pytest
from conftest import jsonl, upload

from cpes_dashboard import analyst


def start(client, dataset_id, **extra):
    response = client.post("/api/runs", json={"dataset_id": dataset_id, "span_seconds": 60, "advance_seconds": 30, **extra})
    assert response.status_code == 200, response.text
    status = client.get(f"/api/runs/{response.json()['id']}").json()
    assert status["state"] == "completed", status.get("traceback")
    return status


def test_cpes_incident_names_the_elevated_process_and_its_actor(client, uac_documents):
    dataset = upload(client, "uac.jsonl", jsonl(uac_documents)).json()
    run = start(client, dataset["id"])
    data = client.get(f"/api/runs/{run['id']}/incidents").json()
    assert data["sigma"]["enabled"] is False and data["sigma_alerts"] == 0
    assert run["summary"]["incidents"] == len(data["incidents"]) == 1
    incident = data["incidents"][0]
    assert [o["process_guid"] for o in incident["outcome"]] == ["{FOD}"]
    alert = incident["alerts"][0]
    assert alert["signal_id"] == "autoelevation_lolbin" and alert["actor_process_guid"] == "{CMD}"
    assert incident["techniques"] == ["T1548.002"]
    assert incident["processes"] == ["{FOD}"]  # processes that alerted; the actor is recorded on the alert


def test_report_layer_and_ecs_agree_with_the_incidents(client, uac_documents):
    dataset = upload(client, "uac.jsonl", jsonl(uac_documents)).json()
    run = start(client, dataset["id"])
    incident = client.get(f"/api/runs/{run['id']}/incidents").json()["incidents"][0]

    report = client.get(f"/api/runs/{run['id']}/incidents/{incident['id']}/report.md").text
    assert "fodhelper.exe" in report and run["id"] in report and dataset["sha256"][:16] in report
    assert "not a verified attribution" in report

    layer = client.get(f"/api/runs/{run['id']}/download/attack-layer.json").json()
    assert layer["domain"] == "enterprise-attack"
    assert layer["techniques"] == [{"techniqueID": "T1548.002", "score": 1, "comment": "1 alert(s) from cpes"}]

    lines = client.get(f"/api/runs/{run['id']}/download/alerts.ecs.ndjson").text.strip().splitlines()
    documents = [json.loads(line) for line in lines]
    assert len(documents) == 1
    document = documents[0]
    assert document["event"]["kind"] == "alert" and document["process"]["entity_id"] == "{FOD}"
    assert document["threat"]["technique"]["id"] == ["T1548.002"]
    assert document["cpes"]["actor_process_guid"] == "{CMD}"
    assert "risk_score" not in document["event"]  # CPES scores are log-odds, not ECS 0-100 risk

    assert client.get(f"/api/runs/{run['id']}/incidents/INC-9999/report.md").status_code == 404


def test_runs_before_the_incidents_stage_get_the_same_cpes_incidents(client, data_root, uac_documents):
    dataset = upload(client, "uac.jsonl", jsonl(uac_documents)).json()
    run = start(client, dataset["id"])
    recorded = client.get(f"/api/runs/{run['id']}/incidents").json()
    (data_root / "runs" / run["id"] / "incidents.json").unlink()
    rebuilt = client.get(f"/api/runs/{run['id']}/incidents").json()
    assert rebuilt["incidents"] == recorded["incidents"]
    assert "predates" in rebuilt["rule"]


def test_no_detection_means_no_incident(client, uac_documents):
    benign = [d for d in uac_documents if d["process"]["entity_id"] not in ("{FOD}",)]
    dataset = upload(client, "benign.jsonl", jsonl(benign)).json()
    run = start(client, dataset["id"])
    data = client.get(f"/api/runs/{run['id']}/incidents").json()
    assert data["incidents"] == [] and data["cpes_alerts"] == 0
    assert client.get(f"/api/runs/{run['id']}/download/attack-layer.json").json()["techniques"] == []
    assert client.get(f"/api/runs/{run['id']}/download/alerts.ecs.ndjson").text == ""


@pytest.mark.skipif(not analyst.SIGMA_CORE.exists(), reason="SigmaHQ core pack not downloaded (scripts/fetch_external.py)")
def test_sigma_stage_records_what_it_ran(client, uac_documents):
    dataset = upload(client, "uac.jsonl", jsonl(uac_documents)).json()
    run = start(client, dataset["id"], sigma=True)
    data = client.get(f"/api/runs/{run['id']}/incidents").json()
    assert data["sigma"]["enabled"] is True and data["sigma"]["levels"] == "high, critical"
    assert data["sigma"]["rules"] > 100
    every_alert = [a for i in data["incidents"] for a in i["alerts"]]
    assert sum(a["source"] == "sigma" for a in every_alert) == data["sigma_alerts"]
    assert all(a["level"] in ("high", "critical") for a in every_alert if a["source"] == "sigma")
    # ECS output carries CPES alerts only
    assert len(client.get(f"/api/runs/{run['id']}/download/alerts.ecs.ndjson").text.strip().splitlines()) == data["cpes_alerts"]


def test_sigma_is_refused_for_presets_without_a_field_view():
    alerts, report = analyst.run_sigma(None, [], "synthetic-sample-field-mapping-v1")
    assert alerts == [] and report["enabled"] is False


def test_overview_features_a_recorded_chain_with_its_actor(client, uac_documents):
    dataset = upload(client, "uac.jsonl", jsonl(uac_documents)).json()
    run = start(client, dataset["id"])
    featured = client.get("/api/overview").json()["featured"]
    assert featured["run_id"] == run["id"] and featured["signal_id"] == "autoelevation_lolbin"
    assert [node["image"] for node in featured["chain"]] == ["explorer.exe", "cmd.exe", "fodhelper.exe"]
    assert featured["actor"]["process_guid"] == "{CMD}"  # the resolver's actor, not the chain root
    assert featured["chain"][-1]["integrity_level"] == "High"
