"""Own-image signature suppressor (S1): positive evidence only, service anchor only."""

from __future__ import annotations

from datetime import datetime, timezone
import unittest

from cpes.context import ContextEvent, ContextResolver
from cpes.context.signatures import ImageLoad, validly_signed_processes
from cpes.windowing.models import EventGroup

ORDER = ("Untrusted", "Low", "Medium", "High", "System")
DEFENDER = "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2008.9-0\\MsMpEng.exe"
DROPPED = "C:\\AtomicRedTeam\\atomics\\T1543.003\\bin\\AtomicService.exe"


def _group(*events):
    return EventGroup("chain-1", tuple(events), False, False, False)


def _system(guid, image):
    return ContextEvent(guid + "-e", guid, datetime(2026, 9, 1, 8, 0, 3, tzinfo=timezone.utc), integrity_level="System", image_path=image)


def _resolver(signed=frozenset()):
    return ContextResolver(ORDER, ("fodhelper.exe",), ("ms-settings",), validly_signed_process_guids=signed)


class SignedProcessesTests(unittest.TestCase):
    def test_only_valid_signature_on_the_own_image_counts(self) -> None:
        loads = [
            ImageLoad("g-def", DEFENDER, DEFENDER.upper(), "true", "Valid"),          # own image, case-insensitive
            ImageLoad("g-dll", DROPPED, "C:\\Windows\\System32\\ntdll.dll", "true", "Valid"),  # a signed DLL is not the image
            ImageLoad("g-uns", DROPPED, DROPPED, "false", "Unavailable"),
            ImageLoad("g-bad", DROPPED, DROPPED, "true", "Expired"),
            ImageLoad(None, DEFENDER, DEFENDER, "true", "Valid"),
        ]
        self.assertEqual(validly_signed_processes(loads), frozenset({"g-def"}))

    def test_discriminators_are_required(self) -> None:
        with self.assertRaises(ValueError):
            validly_signed_processes([], signed_values=())


class ResolverSuppressionTests(unittest.TestCase):
    def _service(self, resolver, guid, image):
        return [r for r in resolver.resolve(_group(_system(guid, image))) if r.anchor_kind == "service_dropped_binary"]

    def test_default_is_location_only(self) -> None:
        self.assertEqual(len(self._service(_resolver(), "g-def", DEFENDER)), 1)

    def test_validly_signed_process_is_skipped(self) -> None:
        self.assertEqual(self._service(_resolver(frozenset({"g-def"})), "g-def", DEFENDER), [])

    def test_unlisted_process_still_resolves(self) -> None:
        self.assertEqual(len(self._service(_resolver(frozenset({"g-def"})), "g-svc", DROPPED)), 1)


if __name__ == "__main__":
    unittest.main()
