"""Strict translation from C5 canonical events to C6/C7 domain inputs."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from collections.abc import Iterable
from cpes.adapters.models import CanonicalEvent
from cpes.context.models import ContextEvent
from cpes.lineage.models import ProcessNode

@dataclass(frozen=True)
class TranslatedEvents:
    canonical_events: tuple[CanonicalEvent, ...]
    process_nodes: tuple[ProcessNode, ...]
    context_events: tuple[ContextEvent, ...]

class CanonicalEventTranslator:
    def translate(self, events: Iterable[CanonicalEvent]) -> TranslatedEvents:
        canonical_events = tuple(sorted(events, key=lambda event: (event.source_timestamp, event.source_event_id)))
        nodes: dict[str, ProcessNode] = {}
        context_events: list[ContextEvent] = []
        for event in canonical_events:
            occurred_at = self._timestamp(event.source_timestamp)
            process_guid = self._optional_string(event.process_guid, "process_guid")
            if process_guid is None:
                continue
            context_events.append(ContextEvent(event.source_event_id, process_guid, occurred_at, self._optional_string(event.integrity_level, "integrity_level"), None, self._optional_string(event.command_line, "command_line"), self._optional_string(event.registry_object, "registry_object"), self._optional_string(event.image_path, "image_path"), self._optional_string(event.module_path, "module_path")))
            incoming = ProcessNode(process_guid, self._optional_string(event.parent_process_guid, "parent_process_guid"), event.process_id)
            existing = nodes.get(process_guid)
            nodes[process_guid] = incoming if existing is None else self._merge_node(existing, incoming)
        return TranslatedEvents(canonical_events, tuple(nodes[key] for key in sorted(nodes)), tuple(sorted(context_events, key=lambda event: (event.occurred_at, event.event_id))))

    @classmethod
    def _merge_node(cls, existing: ProcessNode, incoming: ProcessNode) -> ProcessNode:
        """Reconcile repeated assertions for one ProcessGUID across events.

        Real Sysmon telemetry supplies ``ParentProcessGuid`` only on process
        creation (EID 1); registry, image-load, and process-access events repeat
        the ``ProcessGuid`` without a parent. A missing (``None``) field carries
        no assertion, so a known value always supersedes an unknown one; two
        differing known values are a genuine structural contradiction.
        """

        return ProcessNode(
            process_guid=existing.process_guid,
            parent_process_guid=cls._reconcile(
                "parent_process_guid", existing.parent_process_guid, incoming.parent_process_guid
            ),
            process_id=cls._reconcile("process_id", existing.process_id, incoming.process_id),
            is_incomplete=existing.is_incomplete or incoming.is_incomplete,
        )

    @staticmethod
    def _reconcile(field: str, existing_value: object, incoming_value: object) -> object:
        if existing_value is None:
            return incoming_value
        if incoming_value is None:
            return existing_value
        if existing_value != incoming_value:
            raise ValueError(f"conflicting {field} assertions for one ProcessGUID are not allowed.")
        return existing_value

    @staticmethod
    def _timestamp(value: str) -> datetime:
        if not isinstance(value, str) or not value.strip(): raise ValueError("source_timestamp must be a nonblank ISO 8601 string.")
        try: parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error: raise ValueError("source_timestamp must be ISO 8601.") from error
        if parsed.tzinfo is None: raise ValueError("source_timestamp must include an offset.")
        return parsed

    @staticmethod
    def _optional_string(value: object, field: str) -> str | None:
        if value is None: return None
        if not isinstance(value, str) or not value.strip(): raise ValueError(f"{field} must be a nonblank string when supplied.")
        return value
