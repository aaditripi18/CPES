"""Tests for bounded C8 event-group assembly."""

from datetime import datetime, timezone
import unittest

from cpes.context import ContextBuilder, ContextEvent
from cpes.lineage import LineageBuilder, ProcessNode
from cpes.windowing import SlidingWindowParameters, WindowManager


class WindowManagerTests(unittest.TestCase):
    def test_assembles_deterministic_bounded_event_groups(self) -> None:
        lineage_chain = LineageBuilder().build([ProcessNode("guid-root", None, is_incomplete=True)])[0]
        lineage_context = ContextBuilder().build(
            lineage_chain,
            [
                ContextEvent("event-late", "guid-root", datetime(2026, 7, 18, 4, 31, tzinfo=timezone.utc)),
                ContextEvent("event-early", "guid-root", datetime(2026, 7, 18, 4, 30, tzinfo=timezone.utc)),
            ],
        )
        parameters = SlidingWindowParameters(
            start_at=datetime(2026, 7, 18, 4, 30, tzinfo=timezone.utc),
            horizon_end_at=datetime(2026, 7, 18, 4, 34, tzinfo=timezone.utc),
            span_seconds=120,
            advance_seconds=60,
        )

        windows = WindowManager().assemble(lineage_context, parameters)

        self.assertEqual(len(windows), 3)
        self.assertEqual([event.event_id for event in windows[0].event_group.events], ["event-early", "event-late"])
        self.assertTrue(windows[0].event_group.is_incomplete)
        self.assertEqual([event.event_id for event in windows[2].event_group.events], [])

    def test_scopes_integrity_transitions_to_window_processes(self) -> None:
        # parent (Medium) -> child (High) both created inside the window.
        nodes = [
            ProcessNode("guid-parent", None),
            ProcessNode("guid-child", "guid-parent"),
        ]
        lineage_chain = LineageBuilder().build(nodes)[0]
        lineage_context = ContextBuilder().build(
            lineage_chain,
            [
                ContextEvent("event-parent", "guid-parent", datetime(2026, 7, 18, 4, 30, tzinfo=timezone.utc), integrity_level="Medium"),
                ContextEvent("event-child", "guid-child", datetime(2026, 7, 18, 4, 30, 30, tzinfo=timezone.utc), integrity_level="High"),
            ],
        )
        parameters = SlidingWindowParameters(
            start_at=datetime(2026, 7, 18, 4, 30, tzinfo=timezone.utc),
            horizon_end_at=datetime(2026, 7, 18, 4, 32, tzinfo=timezone.utc),
            span_seconds=120,
            advance_seconds=120,
        )

        windows = WindowManager().assemble(lineage_context, parameters)

        self.assertEqual(len(windows), 1)
        transitions = windows[0].event_group.integrity_transitions
        self.assertEqual(len(transitions), 1)
        self.assertEqual(transitions[0].parent_process_guid, "guid-parent")
        self.assertEqual(transitions[0].child_process_guid, "guid-child")
        self.assertEqual(transitions[0].parent_integrity_level, "Medium")
        self.assertEqual(transitions[0].child_integrity_level, "High")

    def test_excludes_transition_when_one_endpoint_outside_window(self) -> None:
        nodes = [
            ProcessNode("guid-parent", None),
            ProcessNode("guid-child", "guid-parent"),
        ]
        lineage_chain = LineageBuilder().build(nodes)[0]
        lineage_context = ContextBuilder().build(
            lineage_chain,
            [
                ContextEvent("event-parent", "guid-parent", datetime(2026, 7, 18, 4, 30, tzinfo=timezone.utc), integrity_level="Medium"),
                ContextEvent("event-child", "guid-child", datetime(2026, 7, 18, 4, 40, tzinfo=timezone.utc), integrity_level="High"),
            ],
        )
        # A 60s window starting at the parent's time contains only the parent.
        parameters = SlidingWindowParameters(
            start_at=datetime(2026, 7, 18, 4, 30, tzinfo=timezone.utc),
            horizon_end_at=datetime(2026, 7, 18, 4, 31, tzinfo=timezone.utc),
            span_seconds=60,
            advance_seconds=60,
        )

        windows = WindowManager().assemble(lineage_context, parameters)

        self.assertEqual(len(windows), 1)
        self.assertEqual(windows[0].event_group.integrity_transitions, ())

    def test_rejects_nonpositive_supplied_window_parameters(self) -> None:
        lineage_chain = LineageBuilder().build([ProcessNode("guid-root", None)])[0]
        lineage_context = ContextBuilder().build(lineage_chain, [])
        parameters = SlidingWindowParameters(
            start_at=datetime(2026, 7, 18, 4, 30, tzinfo=timezone.utc),
            horizon_end_at=datetime(2026, 7, 18, 4, 31, tzinfo=timezone.utc),
            span_seconds=0,
            advance_seconds=60,
        )

        with self.assertRaises(ValueError):
            WindowManager().assemble(lineage_context, parameters)
