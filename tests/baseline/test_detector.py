"""Tests for the C12 single-event baseline detector."""

from __future__ import annotations

import unittest

from cpes.baseline import SingleEventBaselineDetector
from cpes.context.models import IntegrityTransition
from cpes.windowing import EventGroup

_ORDER = ("Untrusted", "Low", "Medium", "High", "System")


def _group(transitions=(), *, truncated=False, incomplete=False, fragmented=False) -> EventGroup:
    return EventGroup("chain", (), truncated, incomplete, fragmented, tuple(transitions))


class SingleEventBaselineDetectorTests(unittest.TestCase):
    def test_flags_on_single_elevation(self) -> None:
        group = _group((IntegrityTransition("parent", "child", "Medium", "High"),))
        decision = SingleEventBaselineDetector(_ORDER).evaluate(group)
        self.assertTrue(decision.is_detected)
        self.assertEqual(decision.triggering_process_guids, ("child",))
        self.assertEqual(decision.lineage_chain_id, "chain")

    def test_silent_on_deescalation(self) -> None:
        group = _group((IntegrityTransition("parent", "child", "High", "Medium"),))
        decision = SingleEventBaselineDetector(_ORDER).evaluate(group)
        self.assertFalse(decision.is_detected)
        self.assertEqual(decision.triggering_process_guids, ())

    def test_silent_without_transitions(self) -> None:
        decision = SingleEventBaselineDetector(_ORDER).evaluate(_group())
        self.assertFalse(decision.is_detected)

    def test_unknown_levels_ignored(self) -> None:
        group = _group((IntegrityTransition("p", "c", "Medium", "AppContainer"),))
        decision = SingleEventBaselineDetector(_ORDER).evaluate(group)
        self.assertFalse(decision.is_detected)

    def test_flags_on_any_of_multiple_transitions(self) -> None:
        group = _group(
            (
                IntegrityTransition("p1", "c1", "High", "Medium"),  # de-escalation
                IntegrityTransition("p2", "c2", "Medium", "System"),  # elevation
            )
        )
        decision = SingleEventBaselineDetector(_ORDER).evaluate(group)
        self.assertTrue(decision.is_detected)
        self.assertEqual(decision.triggering_process_guids, ("c2",))

    def test_carries_structural_flags(self) -> None:
        group = _group(
            (IntegrityTransition("p", "c", "Medium", "High"),),
            truncated=True,
            incomplete=True,
            fragmented=True,
        )
        decision = SingleEventBaselineDetector(_ORDER).evaluate(group)
        self.assertTrue(decision.is_truncated)
        self.assertTrue(decision.is_incomplete)
        self.assertTrue(decision.is_fragmented)

    def test_deterministic(self) -> None:
        group = _group(
            (
                IntegrityTransition("p1", "c1", "Medium", "High"),
                IntegrityTransition("p2", "c2", "Low", "System"),
            )
        )
        detector = SingleEventBaselineDetector(_ORDER)
        self.assertEqual(detector.evaluate(group), detector.evaluate(group))

    def test_rejects_empty_order(self) -> None:
        with self.assertRaises(ValueError):
            SingleEventBaselineDetector(())

    def test_rejects_duplicate_order_levels(self) -> None:
        with self.assertRaises(ValueError):
            SingleEventBaselineDetector(("Medium", "Medium"))

    def test_rejects_blank_order_level(self) -> None:
        with self.assertRaises(ValueError):
            SingleEventBaselineDetector(("Medium", "  "))


if __name__ == "__main__":
    unittest.main()
