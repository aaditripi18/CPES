from __future__ import annotations

import unittest

from cpes.adapters.mapping import CanonicalEventMapper
from cpes.replay import ReplayDriver

from tests.adapters.test_mapping import mapping_configuration


class ReplayDriverTests(unittest.TestCase):
    def test_replay_matches_live_canonical_input_deterministically(self) -> None:
        mapper = CanonicalEventMapper(mapping_configuration())
        documents = (
            {"@timestamp": "2026-01-01T00:00:02.000Z", "event": {"id": "two"}},
            {"@timestamp": "2026-01-01T00:00:01.000Z", "event": {"id": "one"}},
        )
        live_input = tuple(
            sorted(
                (mapper.map_document(document) for document in documents),
                key=lambda event: (event.source_timestamp, event.source_event_id),
            )
        )
        driver = ReplayDriver()

        first_run = driver.replay(reversed(live_input))
        second_run = driver.replay(reversed(live_input))

        self.assertEqual(first_run, live_input)
        self.assertEqual(second_run, live_input)
        self.assertEqual(first_run, second_run)
