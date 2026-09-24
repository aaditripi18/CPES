"""Tests for resolver-based observation generators."""

from datetime import datetime, timezone
import unittest

from cpes.context import ContextEvent, ContextResolver
from cpes.orchestration.resolved_observations import ResolvedSignalObservationGenerator
from cpes.windowing.models import EventGroup


ORDER = ("Untrusted", "Low", "Medium", "High", "System")


def _event(event_id, guid, when, **kw):
    return ContextEvent(event_id, guid, datetime(2026, 9, 1, 8, 0, when, tzinfo=timezone.utc), **kw)


def _group(events):
    return EventGroup("chain-1", tuple(events), False, False, False)


class ResolvedSignalObservationGeneratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.resolver = ContextResolver(
            integrity_order=ORDER,
            auto_elevating_images=("fodhelper.exe",),
            hijack_registry_tokens=("ms-settings",),
        )
        self.gen510 = ResolvedSignalObservationGenerator("510", self.resolver, "autoelevation_lolbin")
        self.gen520 = ResolvedSignalObservationGenerator("520", self.resolver, "service_dropped_binary")

    def test_fires_when_mechanism_reassociated(self) -> None:
        events = [
            _event("w", "guid-ps", 1, registry_object="HKCU\\...\\ms-settings\\shell\\open\\command"),
            _event("a", "guid-fod", 2, integrity_level="High",
                   image_path="C:\\Windows\\System32\\fodhelper.exe"),
        ]
        (obs,) = self.gen510.generate(_group(events))
        self.assertEqual(obs.signal_id, "510")
        self.assertTrue(obs.is_present)
        self.assertEqual(obs.source_references[0].process_guid, "guid-fod")

    def test_absent_without_registry_evidence(self) -> None:
        events = [
            _event("a", "guid-fod", 2, integrity_level="High",
                   image_path="C:\\Windows\\System32\\fodhelper.exe"),
        ]
        (obs,) = self.gen510.generate(_group(events))
        self.assertFalse(obs.is_present)

    def test_service_signal_independent_of_uac(self) -> None:
        events = [
            _event("s", "guid-svc", 3, integrity_level="System",
                   image_path="C:\\ProgramData\\dropped\\evil.exe"),
        ]
        (obs510,) = self.gen510.generate(_group(events))
        (obs520,) = self.gen520.generate(_group(events))
        self.assertFalse(obs510.is_present)
        self.assertTrue(obs520.is_present)

    def test_validation(self) -> None:
        with self.assertRaises(ValueError):
            ResolvedSignalObservationGenerator("", self.resolver, "autoelevation_lolbin")
        with self.assertRaises(ValueError):
            ResolvedSignalObservationGenerator("510", object(), "autoelevation_lolbin")


if __name__ == "__main__":
    unittest.main()
