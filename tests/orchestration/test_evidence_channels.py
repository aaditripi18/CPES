"""Evidence channels: mapping, building, window attachment, and pipeline integration."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
import unittest

from cpes.adapters.evidence import EvidenceRecord, EvidenceRecordMapper, load_evidence_mapping
from cpes.adapters.models import CanonicalEvent, FieldMapping, MappingConfiguration
from cpes.context.models import PipeEvidence, RemoteThreadEvidence
from cpes.context.resolver import ContextResolver
from cpes.orchestration import CompositeObservationGenerator, CpesPipeline, PipelineConfiguration
from cpes.orchestration.evidence import EvidenceChannelBuilder, TimedEvidence
from cpes.orchestration.resolved_observations import ResolvedSignalObservationGenerator
from cpes.scoring.models import EvidenceModel, EvidenceTerm
from cpes.windowing.evidence import EvidenceWindowAttacher
from cpes.windowing.models import DetectionWindow, EventGroup, SlidingWindowParameters

_CONFIG = Path(__file__).resolve().parents[2] / "configs" / "elastic-sysmon-evidence-mapping-v1.yaml"
_T0 = datetime(2026, 7, 20, 10, 0, tzinfo=timezone.utc)


def _iso(seconds: float) -> str:
    return (_T0 + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def _record(event_id, seconds, code, guid, *, user=None, pipe=None, image=None, target=None) -> EvidenceRecord:
    return EvidenceRecord(_iso(seconds), event_id, code, guid, image, user, pipe, None, target)


def _builder() -> EvidenceChannelBuilder:
    return EvidenceChannelBuilder(pipe_create_codes=("17",), pipe_connect_codes=("18",), remote_thread_codes=("8",), system_user_names=("SYSTEM",))


class EvidenceMappingTests(unittest.TestCase):
    def test_shipped_mapping_copies_raw_fields(self) -> None:
        mapper = EvidenceRecordMapper(load_evidence_mapping(_CONFIG))
        document = {"@timestamp": "2026-07-20T10:00:00Z", "winlog": {"record_id": "7", "event_data": {"EventType": "ConnectPipe"}}, "event": {"code": "18"}, "process": {"entity_id": "{S}", "executable": "C:\\Windows\\System32\\cmd.exe"}, "user": {"name": "SYSTEM"}, "file": {"name": "\\p"}}
        record = mapper.map_document(document)
        self.assertEqual((record.event_code, record.process_guid, record.user_name, record.pipe_name, record.pipe_event_type, record.target_process_guid), ("18", "{S}", "SYSTEM", "\\p", "ConnectPipe", None))

    def test_mapping_must_declare_exactly_the_evidence_fields(self) -> None:
        with self.assertRaises(ValueError):
            EvidenceRecordMapper(MappingConfiguration("v", (FieldMapping("@timestamp", "source_timestamp", False),)))

    def test_missing_required_field_raises(self) -> None:
        with self.assertRaises(ValueError):
            EvidenceRecordMapper(load_evidence_mapping(_CONFIG)).map_document({"@timestamp": "2026-07-20T10:00:00Z"})


class EvidenceBuilderTests(unittest.TestCase):
    def test_builds_pipes_and_threads_and_skips_incomplete(self) -> None:
        channels = _builder().build([
            _record("1", 0, "17", "{U}", user="labuser", pipe="\\x", image="C:\\a\\Evil.exe"),
            _record("2", 1, "18", "{S}", user="SYSTEM", pipe="\\x", image="C:\\Windows\\System32\\cmd.exe"),
            _record("3", 2, "8", "{SRC}", image="C:\\x\\inj.exe", target="{T}"),
            _record("4", 3, "8", "{SRC}", image="C:\\x\\inj.exe"),  # no target -> skipped
            _record("5", 4, "18", "{S}", pipe="\\x"),  # no user -> skipped
            _record("6", 5, "1", "{P}"),  # not an evidence code -> ignored, not counted
        ])
        self.assertEqual(len(channels.pipes), 2)
        create, connect = (item.evidence for item in channels.pipes)
        self.assertEqual((create.action, create.user_is_system, create.image_basename), ("create", False, "evil.exe"))
        self.assertEqual((connect.action, connect.user_is_system), ("connect", True))
        self.assertEqual(channels.remote_threads[0].evidence, RemoteThreadEvidence("3", "{SRC}", "{T}", "inj.exe"))
        self.assertEqual(dict(channels.skipped), {"pipe_missing_field": 1, "remote_thread_missing_guid": 1})

    def test_rejects_overlapping_codes(self) -> None:
        with self.assertRaises(ValueError):
            EvidenceChannelBuilder(pipe_create_codes=("8",), pipe_connect_codes=("18",), remote_thread_codes=("8",), system_user_names=("SYSTEM",))


def _window(chain: str, start: float, end: float) -> DetectionWindow:
    return DetectionWindow(_T0 + timedelta(seconds=start), _T0 + timedelta(seconds=end), EventGroup(chain, (), False, False, False))


def _timed(seconds: float, evidence) -> TimedEvidence:
    return TimedEvidence(_T0 + timedelta(seconds=seconds), evidence)


class WindowAttachmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.create = PipeEvidence("c", "{U}", "\\x", "create", False, "evil.exe")
        self.connect = PipeEvidence("k", "{S}", "\\x", "connect", True, "cmd.exe")
        self.thread = RemoteThreadEvidence("t", "{SRC}", "{T}", "inj.exe")
        self.members = {"chain-s": frozenset({"{S}", "{SRC}"}), "chain-u": frozenset({"{U}"})}

    def test_connect_pulls_matching_create_from_another_chain(self) -> None:
        windows = EvidenceWindowAttacher().attach([_window("chain-s", 0, 60), _window("chain-u", 0, 60)], [_timed(1, self.create), _timed(2, self.connect), _timed(3, self.thread)], self.members)
        self.assertEqual(windows[0].event_group.pipe_evidence, (self.create, self.connect))
        self.assertEqual(windows[0].event_group.remote_thread_evidence, (self.thread,))
        self.assertEqual(windows[1].event_group.pipe_evidence, ())  # creator's chain has no connect

    def test_window_is_the_only_temporal_scope(self) -> None:
        windows = EvidenceWindowAttacher().attach([_window("chain-s", 0, 60)], [_timed(-5, self.create), _timed(2, self.connect), _timed(60, self.thread)], self.members)
        self.assertEqual(windows[0].event_group.pipe_evidence, (self.connect,))
        self.assertEqual(windows[0].event_group.remote_thread_evidence, ())

    def test_windows_without_evidence_are_returned_unchanged(self) -> None:
        window = _window("chain-u", 0, 60)
        self.assertIs(EvidenceWindowAttacher().attach([window], [_timed(2, self.connect)], self.members)[0], window)


def _event(event_id: str, seconds: float, guid: str, parent: str | None = None, image: str | None = None, integrity: str | None = None) -> CanonicalEvent:
    return CanonicalEvent(_iso(seconds), event_id, "1", guid, parent, None, integrity, None, None, image, None)


class PipelineEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        resolver = ContextResolver(("Untrusted", "Low", "Medium", "High", "System"), ("fodhelper.exe",), ("ms-settings",))
        generator = CompositeObservationGenerator((
            ResolvedSignalObservationGenerator("token_impersonation", resolver, "token_impersonation"),
            ResolvedSignalObservationGenerator("remote_thread_injection", resolver, "remote_thread_injection"),
        ))
        model = EvidenceModel(Decimal(0), (EvidenceTerm("token_impersonation", Decimal("6")), EvidenceTerm("remote_thread_injection", Decimal("7"))))
        self.config = PipelineConfiguration(SlidingWindowParameters(_T0, _T0 + timedelta(seconds=120), 60, 60), model, Decimal("0.5"), generator)
        self.events = [
            _event("e1", 0, "{U}", image="C:\\a\\evil.exe", integrity="Medium"),
            _event("e2", 1, "{SVC}", image="C:\\Windows\\System32\\services.exe", integrity="System"),
            _event("e3", 2, "{S}", parent="{SVC}", image="C:\\Windows\\System32\\cmd.exe", integrity="System"),
        ]
        self.channels = _builder().build([
            _record("p1", 3, "17", "{U}", user="labuser", pipe="\\x", image="C:\\a\\evil.exe"),
            _record("p2", 4, "18", "{S}", user="SYSTEM", pipe="\\x", image="C:\\Windows\\System32\\cmd.exe"),
        ])

    def test_without_evidence_output_is_identical_to_before(self) -> None:
        self.assertEqual(CpesPipeline().run(self.events, self.config), CpesPipeline().run(self.events, self.config, evidence=()))

    def test_token_impersonation_fires_only_with_evidence(self) -> None:
        without = CpesPipeline().run(self.events, self.config)
        self.assertFalse(any(decision.is_detected for decision in without.threshold_decisions))
        with_evidence = CpesPipeline().run(self.events, self.config, evidence=self.channels.items)
        detected = [d for d in with_evidence.threshold_decisions if d.is_detected]
        self.assertEqual(len(detected), 1)
        contribution = detected[0].cpes_score_result.evidence_contributions[0]
        self.assertEqual((contribution.signal_id, contribution.source_references[0].process_guid), ("token_impersonation", "{S}"))
        self.assertEqual(detected[0].cpes_score_result.lineage_chain_id, "{SVC}")


if __name__ == "__main__":
    unittest.main()


class ServiceInstallChannelTests(unittest.TestCase):
    _V2 = Path(__file__).resolve().parents[2] / "configs" / "elastic-sysmon-evidence-mapping-v2.yaml"

    def test_v2_mapping_reads_both_install_fields(self) -> None:
        mapper = EvidenceRecordMapper(load_evidence_mapping(self._V2))
        system = mapper.map_document({"@timestamp": _iso(1), "winlog": {"record_id": 7, "event_data": {"ImagePath": '"C:\T\Svc.exe" -k x'}}, "event": {"code": "7045"}})
        security = mapper.map_document({"@timestamp": _iso(2), "winlog": {"record_id": 8, "event_data": {"ServiceFileName": "C:\T\Svc.exe"}}, "event": {"code": "4697"}})
        self.assertEqual(system.service_image_path, '"C:\T\Svc.exe" -k x')
        self.assertEqual(security.service_file_name, "C:\T\Svc.exe")

    def test_builds_install_evidence_and_attaches_it_by_time(self) -> None:
        builder = EvidenceChannelBuilder(pipe_create_codes=("17",), pipe_connect_codes=("18",), remote_thread_codes=("8",),
                                         system_user_names=("SYSTEM",), service_install_codes=("7045", "4697"))
        records = [
            EvidenceRecord(_iso(5), "a", "7045", None, None, None, None, None, None, service_image_path='"C:\T\Svc.exe" -k x'),
            EvidenceRecord(_iso(6), "b", "4697", None, None, None, None, None, None, service_file_name="C:\T\Other.exe"),
            EvidenceRecord(_iso(7), "c", "4697", None, None, None, None, None, None),
        ]
        channels = builder.build(records)
        self.assertEqual([i.evidence.image_basename for i in channels.service_installs], ["svc.exe", "other.exe"])
        self.assertEqual(dict(channels.skipped), {"service_install_missing_image": 1})
        group = EventGroup("chain", (), False, False, False)
        windows = (DetectionWindow(_T0, _T0 + timedelta(seconds=6), group), DetectionWindow(_T0 + timedelta(seconds=6), _T0 + timedelta(seconds=12), group))
        attached = EvidenceWindowAttacher().attach(windows, channels.items, {})
        self.assertEqual([len(w.event_group.service_install_evidence) for w in attached], [1, 1])
