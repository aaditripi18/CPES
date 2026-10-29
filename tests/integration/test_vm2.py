"""Logic of the vm2 protocol on synthetic records (the corpus itself is private)."""

from datetime import datetime, timedelta, timezone

import pytest

from evaluation import research_signals, vm2
from evaluation.vm_live import Run

T0 = datetime(2026, 10, 30, 10, 0, tzinfo=timezone.utc)


def _create(guid, image, *, parent_image="explorer.exe", integrity="Medium", at=T0):
    return {"@timestamp": at.isoformat().replace("+00:00", "Z"), "event": {"code": "1"},
            "process": {"entity_id": guid, "executable": f"C:\\Windows\\System32\\{image}", "parent": {"entity_id": "p0", "executable": f"C:\\Windows\\{parent_image}"}},
            "winlog": {"event_data": {"IntegrityLevel": integrity}}}


def _completed(run, docs, pipes=()):
    nodes = research_signals.nodes(docs)
    created = {g: T0 for g in nodes}
    return vm2.escalation_completed(run, nodes, created, list(pipes))


def test_uac_completes_only_when_the_autoelevating_binary_runs_elevated():
    run = Run("T1548.002", "1", T0, "0", False)
    assert _completed(run, [_create("u", "eventvwr.exe", integrity="High")])
    assert not _completed(run, [_create("u", "eventvwr.exe", integrity="Medium")])
    assert not _completed(run, [_create("u", "cmd.exe", integrity="High")])


def test_service_completes_on_a_system_child_of_services_exe_but_not_svchost():
    run = Run("T1543.003", "2", T0, "0", False)
    assert _completed(run, [_create("s", "AtomicService.exe", parent_image="services.exe", integrity="System")])
    assert not _completed(run, [_create("s", "svchost.exe", parent_image="services.exe", integrity="System")])
    assert not _completed(run, [_create("s", "AtomicService.exe", parent_image="services.exe", integrity="High")])


def test_token_completes_on_a_system_shell_child_or_a_system_pipe_connection():
    run = Run("T1134.001", "1", T0, "0", False)
    assert _completed(run, [_create("t", "cmd.exe", parent_image="powershell.exe", integrity="System")])
    assert not _completed(run, [_create("t", "cmd.exe", parent_image="powershell.exe", integrity="High")])
    assert _completed(run, [], pipes=[(T0 + timedelta(seconds=60), "powershell.exe")])
    assert not _completed(run, [], pipes=[(T0 + timedelta(seconds=400), "powershell.exe")])
    # A SYSTEM pipe connection by an unrelated process is not the test's shell.
    assert not _completed(run, [], pipes=[(T0 + timedelta(seconds=60), "ngen.exe")])


def test_injection_completes_when_mavinject_runs():
    run = Run("T1055.001", "1", T0, "0", False)
    assert _completed(run, [_create("i", "mavinject.exe", integrity="High")])
    assert not _completed(run, [_create("i", "notepad.exe")])


def test_completion_respects_the_150_second_tolerance():
    run = Run("T1548.002", "3", T0, "0", False)
    docs = [_create("u", "fodhelper.exe", integrity="High")]
    nodes = research_signals.nodes(docs)
    assert vm2.escalation_completed(run, nodes, {"u": T0 + timedelta(seconds=150)}, [])
    assert not vm2.escalation_completed(run, nodes, {"u": T0 + timedelta(seconds=151)}, [])


def test_sdclt_runs_are_binary_absent_and_the_check_slice_starts_before_part_one():
    assert ("T1548.002", "7") in vm2.ABSENT_TESTS
    runs = (Run("T1548.002", "1", T0, "0", False), Run("T1543.003", "2", T0 + timedelta(hours=2), "0", False))
    start, end = vm2.check_slice(runs)
    assert start == T0 - timedelta(minutes=2) and end - start == timedelta(minutes=30)


def test_inputs_are_refused_until_the_export_hash_is_recorded(monkeypatch, tmp_path):
    for name in ("corpus.ndjson", "atomic-log.csv", "benign-period.csv", "defender-detections.csv", "defender-threats.csv"):
        (tmp_path / name).write_text("x", encoding="utf-8")
    monkeypatch.setattr(vm2, "ROOT", tmp_path)
    for attr, name in (("CORPUS", "corpus.ndjson"), ("ATOMIC_LOG", "atomic-log.csv"), ("BENIGN_LOG", "benign-period.csv"),
                       ("DEFENDER_DETECTIONS", "defender-detections.csv"), ("DEFENDER_THREATS", "defender-threats.csv")):
        monkeypatch.setattr(vm2, attr, tmp_path / name)
    monkeypatch.setattr(vm2, "CORPUS_SHA256", None)
    with pytest.raises(ValueError, match="CORPUS_SHA256 is not set"):
        vm2.inputs_manifest()
    monkeypatch.setattr(vm2, "CORPUS_SHA256", "0" * 64)
    with pytest.raises(ValueError, match="does not match"):
        vm2.inputs_manifest()


def test_defender_times_are_read_as_utc(monkeypatch, tmp_path):
    path = tmp_path / "defender-detections.csv"
    path.write_text('"InitialDetectionTimeUtc","ThreatID"\n"2026-10-30T10:01:00.0000000Z","1"\n', encoding="utf-8")
    monkeypatch.setattr(vm2, "DEFENDER_DETECTIONS", path)
    assert vm2._defender_times() == [T0 + timedelta(minutes=1)]
