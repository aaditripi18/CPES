"""Tests for factual C7 context extraction."""

from datetime import datetime, timezone
import unittest

from cpes.context import ContextBuilder, ContextEvent
from cpes.lineage import LineageBuilder, ProcessNode


class ContextBuilderTests(unittest.TestCase):
    def test_extracts_all_active_context_categories(self) -> None:
        lineage_chain = LineageBuilder().build(
            [
                ProcessNode("guid-parent", None),
                ProcessNode("guid-child", "guid-parent", is_incomplete=True),
            ]
        )[0]
        events = [
            ContextEvent(
                "event-parent",
                "guid-parent",
                datetime(2026, 7, 18, 4, 30, tzinfo=timezone.utc),
                integrity_level="Medium",
                privilege_identity="user",
                command_line="parent-command",
                image_path="parent-image",
            ),
            ContextEvent(
                "event-child",
                "guid-child",
                datetime(2026, 7, 18, 4, 31, tzinfo=timezone.utc),
                integrity_level="High",
                privilege_identity="administrator",
                command_line="child-command",
                registry_object="registry-object",
                module_path="child-module",
            ),
        ]

        lineage_context = ContextBuilder().build(lineage_chain, reversed(events))

        self.assertEqual(len(lineage_context.parent_child_relationships), 1)
        self.assertEqual(len(lineage_context.lineage_relationships), 2)
        self.assertEqual(len(lineage_context.integrity_transitions), 1)
        self.assertEqual(len(lineage_context.privilege_inheritance), 1)
        self.assertEqual(len(lineage_context.command_line_context), 2)
        self.assertEqual(len(lineage_context.registry_context), 1)
        self.assertEqual(len(lineage_context.image_module_context), 2)
        self.assertEqual(len(lineage_context.temporal_context), 1)
        self.assertTrue(lineage_context.is_incomplete)

    def test_output_order_is_deterministic(self) -> None:
        lineage_chain = LineageBuilder().build([ProcessNode("guid-root", None)])[0]
        events = [
            ContextEvent("event-later", "guid-root", datetime(2026, 7, 18, 4, 31, tzinfo=timezone.utc)),
            ContextEvent("event-earlier", "guid-root", datetime(2026, 7, 18, 4, 30, tzinfo=timezone.utc)),
        ]

        first = ContextBuilder().build(lineage_chain, events)
        second = ContextBuilder().build(lineage_chain, reversed(events))

        self.assertEqual(first, second)
