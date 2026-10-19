"""Direct declarative mapping of cross-channel evidence fields (C5, additive).

``CanonicalEvent`` carries the per-process fields the lineage and context stages
need. Named-pipe (Sysmon EID 17/18) and remote-thread (EID 8) evidence needs a
few more raw fields. Rather than widen the frozen canonical event, a second
mapping copies those fields into an ``EvidenceRecord``. Values are copied as
supplied: no transformation, normalisation or inference.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .mapping import parse_mapping_configuration
from .models import MappingConfiguration


@dataclass(frozen=True)
class EvidenceRecord:
    """Raw evidence-relevant fields of one source document, copied verbatim."""

    source_timestamp: str
    source_event_id: str
    event_code: Any | None
    process_guid: Any | None
    image_path: Any | None
    user_name: Any | None
    pipe_name: Any | None
    pipe_event_type: Any | None
    target_process_guid: Any | None


_DESTINATIONS = frozenset(EvidenceRecord.__dataclass_fields__)
_REQUIRED = frozenset({"source_timestamp", "source_event_id"})


class EvidenceRecordMapper:
    """Map documents to evidence records using declared source paths only."""

    def __init__(self, mapping_configuration: MappingConfiguration) -> None:
        destinations = [field.destination_field for field in mapping_configuration.fields]
        if len(destinations) != len(set(destinations)):
            raise ValueError("evidence mapping destinations must be unique.")
        if set(destinations) != _DESTINATIONS:
            raise ValueError("evidence mapping must declare exactly the evidence destinations.")
        if any(field.optional for field in mapping_configuration.fields if field.destination_field in _REQUIRED):
            raise ValueError("ordering fields must be required evidence mapping fields.")
        self._configuration = mapping_configuration

    def map_document(self, document: Mapping[str, Any]) -> EvidenceRecord:
        values: dict[str, Any] = {}
        for field in self._configuration.fields:
            found, value = _lookup(document, field.source_field)
            if not found:
                if not field.optional:
                    raise ValueError(f"required source field is missing: {field.source_field}")
                value = None
            values[field.destination_field] = value
        return EvidenceRecord(**values)

    def map_documents(self, documents: Iterable[Mapping[str, Any]]) -> tuple[EvidenceRecord, ...]:
        return tuple(self.map_document(document) for document in documents)


def load_evidence_mapping(path: Path) -> MappingConfiguration:
    return parse_mapping_configuration(path.read_text(encoding="utf-8").splitlines())


def _lookup(document: Mapping[str, Any], source_field: str) -> tuple[bool, Any]:
    value: Any = document
    for segment in source_field.split("."):
        if not isinstance(value, Mapping) or segment not in value:
            return False, None
        value = value[segment]
    return True, value
