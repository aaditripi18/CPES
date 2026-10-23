"""Backend-neutral descriptive context models."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class ContextEvent:
    """A supplied event attribute set associated with one process identity."""

    event_id: str
    process_guid: str
    occurred_at: datetime
    integrity_level: str | None = None
    privilege_identity: str | None = None
    command_line: str | None = None
    registry_object: str | None = None
    image_path: str | None = None
    module_path: str | None = None
    parent_image_path: str | None = None


@dataclass(frozen=True)
class ParentChildRelationship:
    parent_process_guid: str
    child_process_guid: str


@dataclass(frozen=True)
class LineageRelationship:
    process_guid: str
    ancestor_process_guids: tuple[str, ...]
    depth: int


@dataclass(frozen=True)
class IntegrityTransition:
    parent_process_guid: str
    child_process_guid: str
    parent_integrity_level: str
    child_integrity_level: str


@dataclass(frozen=True)
class PrivilegeInheritance:
    parent_process_guid: str
    child_process_guid: str
    parent_privilege_identity: str
    child_privilege_identity: str


@dataclass(frozen=True)
class CommandLineContext:
    event_id: str
    process_guid: str
    command_line: str


@dataclass(frozen=True)
class RegistryContext:
    event_id: str
    process_guid: str
    registry_object: str


@dataclass(frozen=True)
class ImageModuleContext:
    event_id: str
    process_guid: str
    image_path: str | None
    module_path: str | None


@dataclass(frozen=True)
class TemporalContext:
    earlier_event_id: str
    later_event_id: str
    elapsed_seconds: float


@dataclass(frozen=True)
class PipeEvidence:
    """A named-pipe create/connect observation (Sysmon EID 17/18).

    Carried alongside the window so the resolver can re-associate a token
    impersonation (a user-created pipe connected by a SYSTEM interactive shell)
    without embedding pipe attributes in the per-process ``ContextEvent``.
    """

    event_id: str
    process_guid: str
    pipe_name: str
    action: str  # "create" | "connect"
    user_is_system: bool
    image_basename: str


@dataclass(frozen=True)
class RemoteThreadEvidence:
    """A remote-thread creation observation (Sysmon EID 8): source -> target."""

    event_id: str
    source_process_guid: str
    target_process_guid: str
    source_image_basename: str


@dataclass(frozen=True)
class ServiceInstallEvidence:
    """A service-install record (System 7045 / Security 4697): which executable was registered, and when."""

    event_id: str
    occurred_at: datetime
    image_basename: str


@dataclass(frozen=True)
class LineageContext:
    """Descriptive context for one structural process-lineage chain."""

    lineage_chain_id: str
    events: tuple[ContextEvent, ...]
    parent_child_relationships: tuple[ParentChildRelationship, ...]
    lineage_relationships: tuple[LineageRelationship, ...]
    integrity_transitions: tuple[IntegrityTransition, ...]
    privilege_inheritance: tuple[PrivilegeInheritance, ...]
    command_line_context: tuple[CommandLineContext, ...]
    registry_context: tuple[RegistryContext, ...]
    image_module_context: tuple[ImageModuleContext, ...]
    temporal_context: tuple[TemporalContext, ...]
    is_truncated: bool
    is_incomplete: bool
    is_fragmented: bool
