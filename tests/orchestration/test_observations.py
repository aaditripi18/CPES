from __future__ import annotations
import unittest
from datetime import datetime, timezone
from cpes.context import ContextEvent
from cpes.orchestration import EventFieldPresenceObservationGenerator, EventFieldPresenceRule
from cpes.windowing import EventGroup

class ObservationTests(unittest.TestCase):
    def test_generates_factual_field_observations(self) -> None:
        group = EventGroup("root", (ContextEvent("e1", "root", datetime(2026, 1, 1, tzinfo=timezone.utc), command_line="whoami"),), False, False, False)
        observations = EventFieldPresenceObservationGenerator((EventFieldPresenceRule("command", "command_line"),)).generate(group)
        self.assertTrue(observations[0].is_present)
        self.assertEqual(observations[0].source_references[0].event_id, "e1")
