"""Opt-in resolver variants: research-v3 replication and structural-v3 service fixes."""

from datetime import datetime, timezone
import unittest

from cpes.context import ContextEvent, ContextResolver, PipeEvidence, RemoteThreadEvidence
from cpes.context.models import ServiceInstallEvidence
from cpes.windowing.models import EventGroup

ORDER = ("Untrusted", "Low", "Medium", "High", "System")
AUTO = ("fodhelper.exe", "sdclt.exe")
HIJACK = ("ms-settings", "\\shell\\open\\command")


def _at(second):
    return datetime(2026, 10, 24, 8, 0, second, tzinfo=timezone.utc)


def _event(event_id, guid, second, **kw):
    return ContextEvent(event_id, guid, _at(second), **kw)


def _group(events):
    return EventGroup("chain-1", tuple(events), False, False, False)


def _kinds(resolved, kind):
    return [r.anchor_process_guid for r in resolved if r.anchor_kind == kind]


SERVICE = dict(integrity_level="System", image_path="C:\\Temp\\AtomicService.exe", parent_image_path="C:\\Windows\\System32\\services.exe")
VENDOR = dict(integrity_level="System", image_path="C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MpCmdRun.exe",
              parent_image_path="C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe")


class DefaultsUnchangedTests(unittest.TestCase):
    def test_default_resolver_flags_vendor_service_and_needs_hijack_write(self) -> None:
        resolver = ContextResolver(ORDER, AUTO, HIJACK)
        resolved = resolver.resolve(_group([
            _event("v", "vendor", 1, **VENDOR),
            _event("f", "fod", 2, integrity_level="High", image_path="C:\\Windows\\System32\\fodhelper.exe"),
        ]))
        self.assertEqual(_kinds(resolved, "service_dropped_binary"), ["vendor"])
        self.assertEqual(_kinds(resolved, "autoelevation_lolbin"), [])


class StructuralV3Tests(unittest.TestCase):
    def test_parent_check_drops_vendor_service(self) -> None:
        resolver = ContextResolver(ORDER, AUTO, HIJACK, service_parent_images=("services.exe",))
        resolved = resolver.resolve(_group([_event("v", "vendor", 1, **VENDOR), _event("s", "svc", 2, **SERVICE)]))
        self.assertEqual(_kinds(resolved, "service_dropped_binary"), ["svc"])

    def test_install_record_must_name_the_binary_and_precede_it(self) -> None:
        resolver = ContextResolver(ORDER, AUTO, HIJACK, require_service_install=True)
        group = _group([_event("s", "svc", 5, **SERVICE)])
        before = (ServiceInstallEvidence("i", _at(3), "atomicservice.exe"),)
        after = (ServiceInstallEvidence("i", _at(7), "atomicservice.exe"),)
        other = (ServiceInstallEvidence("i", _at(3), "other.exe"),)
        self.assertEqual(_kinds(resolver.resolve(group, service_install_evidence=before), "service_dropped_binary"), ["svc"])
        self.assertEqual(_kinds(resolver.resolve(group, service_install_evidence=after), "service_dropped_binary"), [])
        self.assertEqual(_kinds(resolver.resolve(group, service_install_evidence=other), "service_dropped_binary"), [])


class ResearchV3Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.resolver = ContextResolver(
            ORDER, AUTO, HIJACK, uac_requires_hijack_write=False, service_parent_images=("services.exe",),
            service_image_tokens=("atomicservice",), injection_images=("mavinject.exe",),
            remote_thread_source_images=("mavinject.exe",), token_first_creator_only=True,
        )

    def test_uac_without_registry_write(self) -> None:
        resolved = self.resolver.resolve(_group([_event("f", "fod", 2, integrity_level="High", image_path="C:\\Windows\\System32\\fodhelper.exe")]))
        self.assertEqual(_kinds(resolved, "autoelevation_lolbin"), ["fod"])
        self.assertIsNone(resolved[0].actor_process_guid)

    def test_service_name_rule_fires_at_any_integrity(self) -> None:
        resolved = self.resolver.resolve(_group([_event("s", "svc", 1, integrity_level="Medium", image_path="C:\\Temp\\AtomicService.exe")]))
        self.assertEqual(_kinds(resolved, "service_dropped_binary"), ["svc"])
        self.assertIn("NAME RULE", resolved[0].resolution_path[0])

    def test_injection_name_rule_and_listed_thread_sources_only(self) -> None:
        events = [_event("m", "mav", 1, integrity_level="High", image_path="C:\\Windows\\System32\\mavinject.exe")]
        threads = (RemoteThreadEvidence("t1", "csrss", "victim", "csrss.exe"),)
        resolved = self.resolver.resolve(_group(events), remote_thread_evidence=threads)
        self.assertEqual(_kinds(resolved, "remote_thread_injection"), ["mav"])

    def test_token_uses_first_creator_only(self) -> None:
        shell = _event("c", "shell", 3, integrity_level="System", image_path="C:\\Windows\\System32\\cmd.exe")
        pipes = (
            PipeEvidence("p1", "svc", "\\pipe\\x", "create", True, "svchost.exe"),
            PipeEvidence("p2", "user", "\\pipe\\x", "create", False, "powershell.exe"),
            PipeEvidence("p3", "shell", "\\pipe\\x", "connect", True, "cmd.exe"),
        )
        self.assertEqual(_kinds(self.resolver.resolve(_group([shell]), pipe_evidence=pipes), "token_impersonation"), [])
        default = ContextResolver(ORDER, AUTO, HIJACK)
        self.assertEqual(_kinds(default.resolve(_group([shell]), pipe_evidence=pipes), "token_impersonation"), ["shell"])


if __name__ == "__main__":
    unittest.main()
