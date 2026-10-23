"""Logic of the vm-live-v1 protocol on synthetic records (the corpus itself is private)."""

from datetime import datetime, timedelta, timezone

from evaluation import research_signals
from evaluation.vm_live import Run, install_image, outcome_processes, run_level, service_corroborated

T0 = datetime(2026, 10, 23, 16, 0, tzinfo=timezone.utc)


def _create(guid, image, *, parent="p0", parent_image="explorer.exe", integrity="Medium", at=T0, path=None):
    return {"@timestamp": at.isoformat().replace("+00:00", "Z"), "event": {"code": "1"},
            "process": {"entity_id": guid, "executable": path or f"C:\\Temp\\{image}", "parent": {"entity_id": parent, "executable": f"C:\\Windows\\{parent_image}"}},
            "winlog": {"event_data": {"IntegrityLevel": integrity}}}


def test_install_image_strips_quotes_and_arguments():
    assert install_image('"C:\\AtomicRedTeam\\ExternalPayloads\\AtomicService.exe" -k x') == "atomicservice.exe"
    assert install_image("C:\\Program Files\\Agent\\agent.exe --service") == "agent.exe"
    assert install_image("%SystemRoot%\\System32\\svchost.exe -k netsvcs") == "svchost.exe"
    assert install_image(None) == ""


def test_service_corroboration_needs_matching_install_before_start():
    nodes = research_signals.nodes([_create("s1", "AtomicService.exe", parent_image="services.exe", integrity="System")])
    created = {"s1": T0}
    before = [{"t": T0 - timedelta(seconds=3), "image": "atomicservice.exe", "source": "7045"}]
    after = [{"t": T0 + timedelta(seconds=3), "image": "atomicservice.exe", "source": "7045"}]
    other = [{"t": T0 - timedelta(seconds=3), "image": "other.exe", "source": "4697"}]
    assert service_corroborated("s1", nodes, created, before)
    assert not service_corroborated("s1", nodes, created, after)
    assert not service_corroborated("s1", nodes, created, other)
    assert not service_corroborated("missing", nodes, created, before)


def test_run_level_tolerance_consistency_and_false_alarms():
    runs = (Run("T1543.003", "2", T0, "0", False), Run("T1548.002", "1", T0 + timedelta(minutes=10), "0", True))
    created = {"a": T0 + timedelta(seconds=100), "b": T0 + timedelta(minutes=10, seconds=20), "c": T0 + timedelta(minutes=30)}
    flags = {"a": ("service_dropped_binary",), "b": ("service_dropped_binary",), "c": ("token_impersonation",), "d": ("token_impersonation",)}
    level = run_level(flags, created, runs, with_semantics=True)
    assert level["runs_any"] == 2
    assert level["runs_consistent"] == 1  # the UAC run was flagged only by the service signal
    assert level["false_alarm_processes"] == 1  # c: 20 min from any run
    assert level["flagged_without_creation_record"] == 1  # d


def test_outcome_process_is_the_elevated_binary():
    docs = [
        _create("u1", "fodhelper.exe", integrity="High", path="C:\\Windows\\System32\\fodhelper.exe"),
        _create("u2", "cmd.exe", integrity="Medium"),
        _create("s1", "AtomicService.exe", parent_image="services.exe", integrity="System"),
    ]
    nodes = research_signals.nodes(docs)
    created = {g: T0 for g in nodes}
    assert outcome_processes(nodes, created, Run("T1548.002", "3", T0, "0", False)) == {"u1"}
    assert outcome_processes(nodes, created, Run("T1543.003", "2", T0, "0", False)) == {"s1"}
    assert outcome_processes(nodes, created, Run("T1055.001", "1", T0, "0", False)) == set()


def test_excluded_runs_do_not_create_false_alarms():
    blocked = Run("T1548.002", "3", T0, "", True)
    kept = Run("T1543.003", "2", T0 + timedelta(minutes=10), "0", False)
    created = {"a": T0 + timedelta(seconds=30)}
    level = run_level({"a": ("autoelevation_lolbin",)}, created, (kept,), with_semantics=True, alarm_runs=(blocked, kept))
    assert level["runs"] == 1 and level["false_alarm_processes"] == 0
