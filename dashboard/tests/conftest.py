"""Shared fixtures. Every test uses a temporary data root, never dashboard/data.

The documents below are hand-written ECS-shaped test fixtures (not telemetry):
a UAC-bypass-shaped chain (explorer → cmd → fodhelper at High, with a hijack
registry write by cmd) and an unrelated benign chain.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "dashboard")]


def ecs(record_id: int, ts: str, code: str, guid: str, *, parent: str | None = None, image: str | None = None, integrity: str | None = None, cmd: str | None = None, registry: str | None = None, pid: int | None = None) -> dict:
    process: dict = {"entity_id": guid}
    if parent:
        process["parent"] = {"entity_id": parent}
    if image:
        process["executable"] = image
    if cmd:
        process["command_line"] = cmd
    if pid is not None:
        process["pid"] = pid
    document: dict = {"@timestamp": ts, "event": {"code": code}, "winlog": {"record_id": str(record_id), "event_data": {}}, "process": process}
    if integrity:
        document["winlog"]["event_data"]["IntegrityLevel"] = integrity
    if registry:
        document["registry"] = {"path": registry}
    return document


@pytest.fixture
def uac_documents() -> list[dict]:
    return [
        ecs(1, "2026-07-20T10:00:00Z", "1", "{EXPLORER}", image="C:\\Windows\\explorer.exe", integrity="Medium", pid=100),
        ecs(2, "2026-07-20T10:00:10Z", "1", "{CMD}", parent="{EXPLORER}", image="C:\\Windows\\System32\\cmd.exe", integrity="Medium", cmd="cmd.exe /c fodhelper.exe", pid=200),
        ecs(3, "2026-07-20T10:00:12Z", "13", "{CMD}", image="C:\\Windows\\System32\\reg.exe", registry="HKU\\S-1\\Software\\Classes\\ms-settings\\shell\\open\\command\\(Default)"),
        ecs(4, "2026-07-20T10:00:15Z", "1", "{FOD}", parent="{CMD}", image="C:\\Windows\\System32\\fodhelper.exe", integrity="High", pid=300),
        ecs(5, "2026-07-20T10:01:00Z", "1", "{BENIGN-ROOT}", image="C:\\Windows\\explorer.exe", integrity="Medium", pid=400),
        ecs(6, "2026-07-20T10:01:05Z", "1", "{NOTEPAD}", parent="{BENIGN-ROOT}", image="C:\\Windows\\notepad.exe", integrity="Medium", pid=500),
        ecs(7, "2026-07-20T10:01:20Z", "1", "{ORPHAN}", parent="{NOT-IN-DATA}", image="C:\\Windows\\System32\\svchost.exe", integrity="System", pid=600),
    ]


@pytest.fixture
def data_root(tmp_path, monkeypatch) -> Path:
    root = tmp_path / "dashboard-data"
    monkeypatch.setenv("CPES_DASHBOARD_DATA", str(root))
    return root


@pytest.fixture
def client(data_root):
    from fastapi.testclient import TestClient

    from cpes_dashboard import app as app_module
    from cpes_dashboard.runner import RunStore
    from cpes_dashboard.storage import DatasetStore

    # fresh stores bound to the temporary data root
    app_module.datasets = DatasetStore()
    app_module.runs = RunStore(app_module.datasets)
    original_start = app_module.runs.start
    app_module.runs.start = lambda request, background=True: original_start(request, background=False)  # deterministic tests
    return TestClient(app_module.app)


def jsonl(documents: list[dict]) -> bytes:
    return ("\n".join(json.dumps(d) for d in documents) + "\n").encode()


def upload(client, filename: str, data: bytes, **form):
    response = client.post("/api/datasets/upload", files={"file": (filename, data)}, data=form)
    return response
