"""Deterministic tests for ProcessGUID-based structural lineage."""

import unittest

from cpes.lineage import LineageBuilder, ProcessNode


class LineageBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.builder = LineageBuilder()

    def test_builds_parent_child_relationships_by_process_guid(self) -> None:
        chains = self.builder.build(
            [
                ProcessNode("guid-parent", None, process_id=100),
                ProcessNode("guid-child", "guid-parent", process_id=200),
            ]
        )

        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0].root_process_guid, "guid-parent")
        self.assertEqual(chains[0].children_by_process_guid, (("guid-child", ()), ("guid-parent", ("guid-child",))))

    def test_pid_reuse_does_not_merge_distinct_process_guids(self) -> None:
        chains = self.builder.build(
            [
                ProcessNode("guid-first", None, process_id=500),
                ProcessNode("guid-second", None, process_id=500),
            ]
        )

        self.assertEqual(len(chains), 2)
        self.assertEqual({chain.root_process_guid for chain in chains}, {"guid-first", "guid-second"})

    def test_missing_parent_remains_truncated_and_fragmented(self) -> None:
        chain = self.builder.build(
            [
                ProcessNode("guid-child", "guid-missing"),
                ProcessNode("guid-grandchild", "guid-child"),
            ]
        )[0]

        self.assertTrue(chain.is_truncated)
        self.assertTrue(chain.is_fragmented)
        self.assertEqual(chain.unresolved_parent_process_guids, ("guid-missing",))
        self.assertEqual(chain.children_by_process_guid, (("guid-child", ("guid-grandchild",)), ("guid-grandchild", ())))

    def test_incomplete_status_is_preserved(self) -> None:
        chain = self.builder.build([ProcessNode("guid-root", None, is_incomplete=True)])[0]

        self.assertTrue(chain.is_incomplete)

    def test_output_is_deterministic_regardless_of_input_order(self) -> None:
        nodes = [
            ProcessNode("guid-parent", None),
            ProcessNode("guid-child", "guid-parent"),
        ]

        self.assertEqual(self.builder.build(nodes), self.builder.build(reversed(nodes)))

    def test_parent_cycles_are_rejected_without_repair(self) -> None:
        with self.assertRaises(ValueError):
            self.builder.build(
                [
                    ProcessNode("guid-first", "guid-second"),
                    ProcessNode("guid-second", "guid-first"),
                ]
            )
