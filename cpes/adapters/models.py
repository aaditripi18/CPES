"""Backend-neutral canonical event and declarative mapping models for C5."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class FieldMapping:
    """One direct source-field to canonical-field declaration."""

    source_field: str
    destination_field: str
    optional: bool


@dataclass(frozen=True)
class MappingConfiguration:
    """Versioned direct-field mapping used by the retrieval adapter."""

    version: str
    fields: tuple[FieldMapping, ...]


@dataclass(frozen=True)
class CanonicalEvent:
    """One backend-neutral event with source values preserved as supplied."""

    source_timestamp: str
    source_event_id: str
    event_code: Any | None
    process_guid: Any | None
    parent_process_guid: Any | None
    process_id: Any | None
    integrity_level: Any | None
    command_line: Any | None
    registry_object: Any | None
    image_path: Any | None
    module_path: Any | None
    # Optional (mapping v2): mappings written before it may omit it.
    parent_image_path: Any | None = None

