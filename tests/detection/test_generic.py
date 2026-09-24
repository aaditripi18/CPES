"""Tests for the generic unexplained-privilege-gain escalation test."""

from datetime import datetime, timezone
import unittest

from cpes.context import ContextEvent, ContextResolver
from cpes.context.models import IntegrityTransition
from cpes.detection import GenericEscalationObservationGenerator
from cpes.windowing.models import EventGroup


ORDER = ("Untrusted", "Low", "Medium", "High", "System")


def _event(event_id, guid, **kw):
    return ContextEvent(event_id, guid, datetime(2026, 9, 1, 8, 0, 0, tzinfo=timezone.utc), **kw)


def _resolver():
    return ContextResolver(
        integrity_order=ORDER,
        auto_elevating_images=("fodhelper.exe",),
        hijack_registry_tokens=("ms-settings",),
    )


class GenericEscalationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.gen = GenericEscalationObservationGenerator("gen", ORDER, _resolver())

    def _group(self, events, transitions):
        return EventGroup("chain", tuple(events), False, False, False, tuple(transitions))

    def test_fires_on_unexplained_elevation(self) -> None:
        # a Medium->High elevation with an ordinary user parent, no specific mechanism,
        # no consent mediator -> unexplained privilege gain.
        events = [
            _event("p", "guid-parent", integrity_level="Medium", image_path="C:\\X\\launcher.exe"),
            _event("c", "guid-child", integrity_level="High", image_path="C:\\X\\wsreset.exe"),
        ]
        tr = [IntegrityTransition("guid-parent", "guid-child", "Medium", "High")]
        (obs,) = self.gen.generate(self._group(events, tr))
        self.assertTrue(obs.is_present)
        self.assertEqual(obs.source_references[0].process_guid, "guid-child")

    def test_silent_on_consent_mediated_elevation(self) -> None:
        # a legitimate interactive UAC elevation goes through consent.exe -> not flagged.
        events = [
            _event("p", "guid-consent", integrity_level="System", image_path="C:\\Windows\\System32\\consent.exe"),
            _event("c", "guid-child", integrity_level="High", image_path="C:\\Windows\\System32\\mmc.exe"),
        ]
        tr = [IntegrityTransition("guid-consent", "guid-child", "System", "High")]
        (obs,) = self.gen.generate(self._group(events, tr))
        self.assertFalse(obs.is_present)

    def test_silent_when_specific_mechanism_explains_it(self) -> None:
        # if a specific mechanism (fodhelper + hijack write) resolves the elevation,
        # the generic test does NOT double-count it.
        events = [
            _event("w", "guid-actor", registry_object="HKCU\\...\\ms-settings\\shell\\open\\command"),
            _event("p", "guid-parent", integrity_level="Medium", image_path="C:\\X\\cmd.exe"),
            _event("c", "guid-fod", integrity_level="High", image_path="C:\\Windows\\System32\\fodhelper.exe"),
        ]
        tr = [IntegrityTransition("guid-parent", "guid-fod", "Medium", "High")]
        (obs,) = self.gen.generate(self._group(events, tr))
        self.assertFalse(obs.is_present)  # explained by the autoelevation mechanism

    def test_silent_without_elevation(self) -> None:
        events = [_event("c", "guid-child", integrity_level="Medium")]
        tr = [IntegrityTransition("guid-parent", "guid-child", "Medium", "Medium")]
        (obs,) = self.gen.generate(self._group(events, tr))
        self.assertFalse(obs.is_present)

    def test_validation(self) -> None:
        with self.assertRaises(ValueError):
            GenericEscalationObservationGenerator("", ORDER, _resolver())
        with self.assertRaises(ValueError):
            GenericEscalationObservationGenerator("gen", ORDER, object())


if __name__ == "__main__":
    unittest.main()
