from __future__ import annotations
import unittest
from cpes.adapters import CanonicalEvent
from cpes.orchestration import CanonicalEventTranslator


def event(event_id: str, process_guid: str, parent_guid: str | None) -> CanonicalEvent:
    return CanonicalEvent("2026-07-20T00:00:00Z", event_id, "1", process_guid, parent_guid, 1, "Medium", None, None, "C:/x.exe", None)


def create_event(event_id: str, ts: str, process_guid: str, parent_guid: str | None, process_id) -> CanonicalEvent:
    # EID 1: carries ProcessGuid, ParentProcessGuid, ProcessId, integrity, command line, image.
    return CanonicalEvent(ts, event_id, "1", process_guid, parent_guid, process_id, "Medium", "c.exe", None, "C:/c.exe", None)


def registry_event(event_id: str, ts: str, process_guid: str, process_id) -> CanonicalEvent:
    # EID 13: ProcessGuid + ProcessId + TargetObject, but NO ParentProcessGuid.
    return CanonicalEvent(ts, event_id, "13", process_guid, None, process_id, None, None, "HKCU/x", None, None)


def imageload_event(event_id: str, ts: str, process_guid: str, process_id) -> CanonicalEvent:
    # EID 7: ProcessGuid + ProcessId + ImageLoaded, but NO ParentProcessGuid.
    return CanonicalEvent(ts, event_id, "7", process_guid, None, process_id, None, None, None, "C:/c.exe", "C:/lib.dll")


def processaccess_event(event_id: str, ts: str, process_guid: str, process_id) -> CanonicalEvent:
    # EID 10: ProcessGuid + ProcessId, but NO ParentProcessGuid.
    return CanonicalEvent(ts, event_id, "10", process_guid, None, process_id, None, None, None, "C:/c.exe", None)


def _node_by_guid(translated):
    return {node.process_guid: node for node in translated.process_nodes}


class TranslationTests(unittest.TestCase):
    def test_translates_canonical_events_deterministically(self) -> None:
        translated = CanonicalEventTranslator().translate((event("child", "child", "root"), event("root", "root", None)))
        self.assertEqual([node.process_guid for node in translated.process_nodes], ["child", "root"])
        self.assertEqual([item.event_id for item in translated.context_events], ["child", "root"])

    def test_create_then_registry_keeps_known_parent(self) -> None:
        translated = CanonicalEventTranslator().translate((
            create_event("e1", "2026-07-20T00:00:00Z", "proc", "parent", 100),
            registry_event("e2", "2026-07-20T00:00:01Z", "proc", 100),
        ))
        nodes = _node_by_guid(translated)
        self.assertEqual(len(translated.process_nodes), 1)
        self.assertEqual(nodes["proc"].parent_process_guid, "parent")
        self.assertEqual(nodes["proc"].process_id, 100)
        # Both events still produce distinct context observations.
        self.assertEqual(len(translated.context_events), 2)

    def test_create_then_imageload_keeps_known_parent(self) -> None:
        translated = CanonicalEventTranslator().translate((
            create_event("e1", "2026-07-20T00:00:00Z", "proc", "parent", 100),
            imageload_event("e2", "2026-07-20T00:00:01Z", "proc", 100),
        ))
        nodes = _node_by_guid(translated)
        self.assertEqual(len(translated.process_nodes), 1)
        self.assertEqual(nodes["proc"].parent_process_guid, "parent")

    def test_create_then_processaccess_keeps_known_parent(self) -> None:
        translated = CanonicalEventTranslator().translate((
            create_event("e1", "2026-07-20T00:00:00Z", "proc", "parent", 100),
            processaccess_event("e2", "2026-07-20T00:00:01Z", "proc", 100),
        ))
        nodes = _node_by_guid(translated)
        self.assertEqual(len(translated.process_nodes), 1)
        self.assertEqual(nodes["proc"].parent_process_guid, "parent")

    def test_many_events_one_process_collapse_to_single_node(self) -> None:
        translated = CanonicalEventTranslator().translate((
            create_event("e1", "2026-07-20T00:00:00Z", "proc", "parent", 100),
            registry_event("e2", "2026-07-20T00:00:01Z", "proc", 100),
            imageload_event("e3", "2026-07-20T00:00:02Z", "proc", 100),
            processaccess_event("e4", "2026-07-20T00:00:03Z", "proc", 100),
        ))
        self.assertEqual(len(translated.process_nodes), 1)
        self.assertEqual(len(translated.context_events), 4)
        self.assertEqual(translated.process_nodes[0].parent_process_guid, "parent")

    def test_unknown_parent_is_filled_by_later_known_parent(self) -> None:
        # A non-create event arrives before the create event; None must not win.
        translated = CanonicalEventTranslator().translate((
            registry_event("e1", "2026-07-20T00:00:00Z", "proc", 100),
            create_event("e2", "2026-07-20T00:00:01Z", "proc", "parent", 100),
        ))
        self.assertEqual(len(translated.process_nodes), 1)
        self.assertEqual(translated.process_nodes[0].parent_process_guid, "parent")

    def test_unknown_parent_stays_unknown_when_never_supplied(self) -> None:
        translated = CanonicalEventTranslator().translate((
            registry_event("e1", "2026-07-20T00:00:00Z", "proc", 100),
            imageload_event("e2", "2026-07-20T00:00:01Z", "proc", 100),
        ))
        self.assertEqual(len(translated.process_nodes), 1)
        self.assertIsNone(translated.process_nodes[0].parent_process_guid)

    def test_rejects_truly_conflicting_parents(self) -> None:
        # Two DIFFERENT non-None parents for the same ProcessGuid is a real conflict.
        with self.assertRaises(ValueError):
            CanonicalEventTranslator().translate((
                create_event("e1", "2026-07-20T00:00:00Z", "proc", "parent-a", 100),
                create_event("e2", "2026-07-20T00:00:01Z", "proc", "parent-b", 100),
            ))

    def test_rejects_conflicting_process_ids(self) -> None:
        with self.assertRaises(ValueError):
            CanonicalEventTranslator().translate((
                create_event("e1", "2026-07-20T00:00:00Z", "proc", "parent", 100),
                registry_event("e2", "2026-07-20T00:00:01Z", "proc", 999),
            ))


if __name__ == "__main__":
    unittest.main()
