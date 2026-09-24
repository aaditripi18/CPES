"""Tests for the first real privilege-escalation observation generators."""

from __future__ import annotations

from datetime import datetime, timezone
import unittest

from cpes.context.models import ContextEvent, IntegrityTransition
from cpes.orchestration import (
    CommandLineIndicatorObservationGenerator,
    CompositeObservationGenerator,
    IntegrityElevationObservationGenerator,
)
from cpes.windowing import EventGroup

_ORDER = ("Untrusted", "Low", "Medium", "High", "System")
_TS = datetime(2026, 7, 20, tzinfo=timezone.utc)


def _event(event_id: str, process_guid: str, command_line: str | None = None) -> ContextEvent:
    return ContextEvent(event_id, process_guid, _TS, command_line=command_line)


def _group(events=(), transitions=()) -> EventGroup:
    return EventGroup("chain", tuple(events), False, False, False, tuple(transitions))


class IntegrityElevationTests(unittest.TestCase):
    def test_fires_on_elevation(self) -> None:
        group = _group(transitions=(IntegrityTransition("parent", "child", "Medium", "High"),))
        observations = IntegrityElevationObservationGenerator("s.integ", _ORDER).generate(group)
        self.assertEqual(len(observations), 1)
        self.assertTrue(observations[0].is_present)
        self.assertEqual(observations[0].source_references[0].process_guid, "child")

    def test_silent_on_deescalation(self) -> None:
        group = _group(transitions=(IntegrityTransition("parent", "child", "High", "Medium"),))
        observations = IntegrityElevationObservationGenerator("s.integ", _ORDER).generate(group)
        self.assertFalse(observations[0].is_present)
        self.assertEqual(observations[0].source_references, ())

    def test_silent_when_no_transitions(self) -> None:
        observations = IntegrityElevationObservationGenerator("s.integ", _ORDER).generate(_group())
        self.assertFalse(observations[0].is_present)

    def test_unknown_level_is_skipped_not_crashed(self) -> None:
        group = _group(transitions=(IntegrityTransition("p", "c", "Medium", "AppContainer"),))
        observations = IntegrityElevationObservationGenerator("s.integ", _ORDER).generate(group)
        self.assertFalse(observations[0].is_present)

    def test_system_elevation_from_medium(self) -> None:
        group = _group(transitions=(IntegrityTransition("p", "c", "Medium", "System"),))
        observations = IntegrityElevationObservationGenerator("s.integ", _ORDER).generate(group)
        self.assertTrue(observations[0].is_present)

    def test_deterministic(self) -> None:
        group = _group(
            transitions=(
                IntegrityTransition("p1", "c1", "Medium", "High"),
                IntegrityTransition("p2", "c2", "Low", "System"),
            )
        )
        generator = IntegrityElevationObservationGenerator("s.integ", _ORDER)
        self.assertEqual(generator.generate(group), generator.generate(group))

    def test_rejects_blank_signal_id(self) -> None:
        with self.assertRaises(ValueError):
            IntegrityElevationObservationGenerator("  ", _ORDER)

    def test_rejects_duplicate_order_levels(self) -> None:
        with self.assertRaises(ValueError):
            IntegrityElevationObservationGenerator("s.integ", ("Medium", "Medium"))

    def test_rejects_empty_order(self) -> None:
        with self.assertRaises(ValueError):
            IntegrityElevationObservationGenerator("s.integ", ())


class CommandLineIndicatorTests(unittest.TestCase):
    def test_fires_on_indicator_case_insensitive(self) -> None:
        group = _group(events=(_event("e1", "p", "C:/Windows/System32/FODHELPER.exe"),))
        observations = CommandLineIndicatorObservationGenerator("s.cmd", ("fodhelper.exe",)).generate(group)
        self.assertTrue(observations[0].is_present)
        self.assertEqual(observations[0].source_references[0].event_id, "e1")

    def test_silent_without_indicator(self) -> None:
        group = _group(events=(_event("e1", "p", "notepad.exe"),))
        observations = CommandLineIndicatorObservationGenerator("s.cmd", ("fodhelper.exe",)).generate(group)
        self.assertFalse(observations[0].is_present)

    def test_silent_when_command_line_absent(self) -> None:
        group = _group(events=(_event("e1", "p", None),))
        observations = CommandLineIndicatorObservationGenerator("s.cmd", ("fodhelper.exe",)).generate(group)
        self.assertFalse(observations[0].is_present)

    def test_matches_any_of_several_indicators(self) -> None:
        group = _group(events=(_event("e1", "p", "run sdclt.exe now"),))
        generator = CommandLineIndicatorObservationGenerator("s.cmd", ("fodhelper.exe", "sdclt.exe"))
        self.assertTrue(generator.generate(group)[0].is_present)

    def test_rejects_blank_signal_id(self) -> None:
        with self.assertRaises(ValueError):
            CommandLineIndicatorObservationGenerator("", ("x",))

    def test_rejects_empty_indicators(self) -> None:
        with self.assertRaises(ValueError):
            CommandLineIndicatorObservationGenerator("s.cmd", ())

    def test_rejects_blank_indicator(self) -> None:
        with self.assertRaises(ValueError):
            CommandLineIndicatorObservationGenerator("s.cmd", ("  ",))


class CompositeTests(unittest.TestCase):
    def test_concatenates_distinct_signals(self) -> None:
        group = _group(
            events=(_event("e1", "c", "fodhelper.exe"),),
            transitions=(IntegrityTransition("p", "c", "Medium", "High"),),
        )
        composite = CompositeObservationGenerator(
            (
                IntegrityElevationObservationGenerator("s.integ", _ORDER),
                CommandLineIndicatorObservationGenerator("s.cmd", ("fodhelper.exe",)),
            )
        )
        observations = composite.generate(group)
        self.assertEqual({o.signal_id for o in observations}, {"s.integ", "s.cmd"})
        self.assertTrue(all(o.is_present for o in observations))

    def test_rejects_duplicate_signal_ids(self) -> None:
        composite = CompositeObservationGenerator(
            (
                CommandLineIndicatorObservationGenerator("dup", ("a",)),
                CommandLineIndicatorObservationGenerator("dup", ("b",)),
            )
        )
        with self.assertRaises(ValueError):
            composite.generate(_group())

    def test_rejects_empty_generators(self) -> None:
        with self.assertRaises(ValueError):
            CompositeObservationGenerator(())


if __name__ == "__main__":
    unittest.main()
