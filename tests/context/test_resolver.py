"""Tests for cross-channel context re-association (ContextResolver)."""

from datetime import datetime, timezone
import unittest

from cpes.context import (
    ContextEvent,
    ContextResolver,
    PipeEvidence,
    RemoteThreadEvidence,
)
from cpes.windowing.models import EventGroup


ORDER = ("Untrusted", "Low", "Medium", "High", "System")


def _event(event_id, guid, when, **kw):
    return ContextEvent(event_id, guid, datetime(2026, 9, 1, 8, 0, when, tzinfo=timezone.utc), **kw)


def _group(events, chain_id="chain-1"):
    return EventGroup(chain_id, tuple(events), False, False, False)


class ContextResolverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.resolver = ContextResolver(
            integrity_order=ORDER,
            auto_elevating_images=("fodhelper.exe", "sdclt.exe", "computerdefaults.exe"),
            hijack_registry_tokens=("ms-settings", "mscfile", "\\shell\\open\\command"),
        )

    def test_uac_reassociates_lolbin_with_hijack_write(self) -> None:
        events = [
            _event("w", "guid-ps", 1, registry_object="HKCU\\...\\ms-settings\\shell\\open\\command",
                   image_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            _event("a", "guid-fod", 2, integrity_level="High",
                   image_path="C:\\Windows\\System32\\fodhelper.exe"),
        ]
        resolved = self.resolver.resolve(_group(events))
        uac = [r for r in resolved if r.anchor_kind == "autoelevation_lolbin"]
        self.assertEqual(len(uac), 1)
        self.assertEqual(uac[0].anchor_process_guid, "guid-fod")
        self.assertEqual(uac[0].actor_process_guid, "guid-ps")
        self.assertIn("w", uac[0].evidence_event_ids)
        self.assertTrue(uac[0].resolution_path)

    def test_lolbin_without_hijack_write_does_not_resolve(self) -> None:
        # A LOLBin at High with NO hijack write present must NOT resolve as UAC
        # (this is the whole point: mechanism-conditioned, not image-only).
        events = [
            _event("a", "guid-fod", 2, integrity_level="High",
                   image_path="C:\\Windows\\System32\\fodhelper.exe"),
        ]
        resolved = self.resolver.resolve(_group(events))
        self.assertEqual([r for r in resolved if r.anchor_kind == "autoelevation_lolbin"], [])

    def test_service_dropped_binary_is_structural(self) -> None:
        events = [
            _event("s", "guid-svc", 3, integrity_level="System",
                   image_path="C:\\AtomicRedTeam\\atomics\\T1543.003\\bin\\AtomicService.exe"),
        ]
        resolved = self.resolver.resolve(_group(events))
        svc = [r for r in resolved if r.anchor_kind == "service_dropped_binary"]
        self.assertEqual(len(svc), 1)
        self.assertEqual(svc[0].anchor_process_guid, "guid-svc")

    def test_legitimate_system_binary_in_windows_does_not_resolve(self) -> None:
        events = [
            _event("s", "guid-legit", 3, integrity_level="System",
                   image_path="C:\\Windows\\servicing\\TrustedInstaller.exe"),
        ]
        resolved = self.resolver.resolve(_group(events))
        self.assertEqual([r for r in resolved if r.anchor_kind == "service_dropped_binary"], [])

    def test_svchost_system_service_does_not_resolve(self) -> None:
        events = [
            _event("s", "guid-svchost", 3, integrity_level="System",
                   image_path="C:\\Windows\\System32\\svchost.exe"),
        ]
        resolved = self.resolver.resolve(_group(events))
        self.assertEqual(resolved, ())

    def test_token_impersonation_reassociates_pipe_create_and_connect(self) -> None:
        group = _group([_event("x", "guid-noise", 1, image_path="C:\\Windows\\System32\\conhost.exe")])
        pipes = (
            PipeEvidence("p1", "guid-ps", "\\TestSVC", "create", user_is_system=False, image_basename="powershell.exe"),
            PipeEvidence("p2", "guid-sys", "\\TestSVC", "connect", user_is_system=True, image_basename="cmd.exe"),
        )
        resolved = self.resolver.resolve(group, pipe_evidence=pipes)
        tok = [r for r in resolved if r.anchor_kind == "token_impersonation"]
        self.assertEqual(len(tok), 1)
        self.assertEqual(tok[0].anchor_process_guid, "guid-sys")
        self.assertEqual(tok[0].actor_process_guid, "guid-ps")

    def test_benign_system_service_pipe_does_not_resolve_as_token(self) -> None:
        # VBox-style: pipe created by a user tray app, connected by a SYSTEM *service*
        # binary (not an interactive shell) -> must NOT resolve as impersonation.
        group = _group([_event("x", "guid-noise", 1)])
        pipes = (
            PipeEvidence("p1", "guid-tray", "\\VBoxTrayIPC", "create", user_is_system=False, image_basename="vboxtray.exe"),
            PipeEvidence("p2", "guid-svc", "\\VBoxTrayIPC", "connect", user_is_system=True, image_basename="vboxservice.exe"),
        )
        resolved = self.resolver.resolve(group, pipe_evidence=pipes)
        self.assertEqual([r for r in resolved if r.anchor_kind == "token_impersonation"], [])

    def test_injection_reassociates_remote_thread(self) -> None:
        group = _group([_event("x", "guid-noise", 1)])
        threads = (RemoteThreadEvidence("t1", "guid-mav", "guid-victim", "mavinject.exe"),)
        resolved = self.resolver.resolve(group, remote_thread_evidence=threads)
        inj = [r for r in resolved if r.anchor_kind == "remote_thread_injection"]
        self.assertEqual(len(inj), 1)
        self.assertEqual(inj[0].anchor_process_guid, "guid-mav")

    def test_validation_rejects_empty_config(self) -> None:
        with self.assertRaises(ValueError):
            ContextResolver(ORDER, (), ("ms-settings",))
        with self.assertRaises(ValueError):
            ContextResolver(ORDER, ("fodhelper.exe",), ())


if __name__ == "__main__":
    unittest.main()
