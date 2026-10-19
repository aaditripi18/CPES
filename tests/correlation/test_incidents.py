"""Incident correlation follows its three written rules and nothing else."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from cpes.correlation import Alert, correlate

T0 = datetime(2026, 7, 20, 10, 0, tzinfo=timezone.utc)
# shell -> cmd -> reg ; shell -> cmd2 ; unrelated
PARENTS = {"cmd": "shell", "reg": "cmd", "cmd2": "shell", "fod": "cmd", "payload": "fod", "deep": "payload", "other": None, "svc": "services"}


def alert(identifier, seconds, guid, source="sigma", related=(), level="high"):
    return Alert(identifier, source, T0 + timedelta(seconds=seconds), guid, identifier, level=level, related_guids=related)


class IncidentTests(unittest.TestCase):
    def test_lineage_within_two_generations_and_time_gap(self) -> None:
        incidents = correlate([alert("a", 0, "shell"), alert("b", 10, "reg"), alert("c", 20, "other")], PARENTS)
        self.assertEqual([[x.id for x in i.alerts] for i in incidents], [["a", "b"], ["c"]])

    def test_siblings_and_three_generations_are_not_linked(self) -> None:
        self.assertEqual(len(correlate([alert("a", 0, "cmd"), alert("b", 5, "cmd2")], PARENTS)), 2)
        self.assertEqual(len(correlate([alert("a", 0, "cmd"), alert("b", 5, "deep")], PARENTS)), 2)

    def test_gap_limits_lineage_links_but_not_same_process(self) -> None:
        self.assertEqual(len(correlate([alert("a", 0, "shell"), alert("b", 400, "cmd")], PARENTS, gap_seconds=300)), 2)
        self.assertEqual(len(correlate([alert("a", 0, "reg"), alert("b", 4000, "reg")], PARENTS)), 1)

    def test_resolver_actor_link_crosses_trees_and_marks_the_outcome(self) -> None:
        incidents = correlate([alert("hijack", 0, "reg"), alert("elevated", 900, "svc", source="cpes", related=("reg",))], PARENTS)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].outcome_processes, ("svc",))
        self.assertEqual(incidents[0].sources, ("cpes", "sigma"))

    def test_level_is_the_highest_member(self) -> None:
        incidents = correlate([alert("a", 0, "reg", level="medium"), alert("b", 1, "reg", level="critical")], PARENTS)
        self.assertEqual(incidents[0].level, "critical")


if __name__ == "__main__":
    unittest.main()
