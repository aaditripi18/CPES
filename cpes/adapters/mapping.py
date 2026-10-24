"""Direct declarative-field mapping with no derived event values."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from .models import CanonicalEvent, FieldMapping, MappingConfiguration


_CANONICAL_DESTINATIONS = frozenset(CanonicalEvent.__dataclass_fields__)
_REQUIRED_DESTINATIONS = frozenset({"source_timestamp", "source_event_id"})
# Destinations added after v1 mappings existed; a mapping may leave them out.
_OMITTABLE_DESTINATIONS = frozenset({"parent_image_path"})


class CanonicalEventMapper:
    """Map supplied source documents using direct, declared source paths only."""

    def __init__(self, mapping_configuration: MappingConfiguration) -> None:
        self._mapping_configuration = mapping_configuration
        self._validate_configuration(mapping_configuration)

    def map_document(self, document: Mapping[str, Any]) -> CanonicalEvent:
        """Map one source document without transforming, enriching, or inferring values."""

        values: dict[str, Any] = {}
        for field_mapping in self._mapping_configuration.fields:
            found, value = self._lookup(document, field_mapping.source_field)
            if not found:
                if not field_mapping.optional:
                    raise ValueError(
                        "required source field is missing: "
                        f"{field_mapping.source_field}"
                    )
                value = None
            values[field_mapping.destination_field] = value
        return CanonicalEvent(**values)

    @staticmethod
    def _lookup(document: Mapping[str, Any], source_field: str) -> tuple[bool, Any]:
        value: Any = document
        for segment in source_field.split("."):
            if not isinstance(value, Mapping) or segment not in value:
                return False, None
            value = value[segment]
        return True, value

    @staticmethod
    def _validate_configuration(mapping_configuration: MappingConfiguration) -> None:
        destinations = [field.destination_field for field in mapping_configuration.fields]
        if len(destinations) != len(set(destinations)):
            raise ValueError("mapping destinations must be unique.")
        unknown_destinations = set(destinations) - _CANONICAL_DESTINATIONS
        if unknown_destinations:
            raise ValueError("mapping contains an unknown canonical destination.")
        missing_destinations = _CANONICAL_DESTINATIONS - _OMITTABLE_DESTINATIONS - set(destinations)
        if missing_destinations:
            raise ValueError("mapping must declare every canonical destination.")
        optional_required = [
            field.destination_field
            for field in mapping_configuration.fields
            if field.destination_field in _REQUIRED_DESTINATIONS and field.optional
        ]
        if optional_required:
            raise ValueError("ordering fields must be required mapping fields.")


def parse_mapping_configuration(lines: Iterable[str]) -> MappingConfiguration:
    """Parse the constrained declarative YAML form used by M7's mapping file."""

    version: str | None = None
    fields: list[FieldMapping] = []
    current: dict[str, str] | None = None
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or line == "fields:":
            continue
        if line.startswith("version:"):
            version = _scalar_value(line, "version")
            continue
        if line.startswith("- "):
            if current is not None:
                fields.append(_field_mapping(current))
            current = {}
            line = line[2:].strip()
        if current is None:
            raise ValueError("mapping field declaration expected.")
        key, value = _key_value(line)
        current[key] = value
    if current is not None:
        fields.append(_field_mapping(current))
    if version is None:
        raise ValueError("mapping version is required.")
    return MappingConfiguration(version=version, fields=tuple(fields))


def load_mapping_configuration(path: Path) -> MappingConfiguration:
    """Load the constrained declarative mapping configuration from its file."""

    return parse_mapping_configuration(path.read_text(encoding="utf-8").splitlines())


def _field_mapping(values: Mapping[str, str]) -> FieldMapping:
    if set(values) != {"source_field", "destination_field", "optional"}:
        raise ValueError("each mapping field requires source_field, destination_field, optional.")
    optional_value = values["optional"]
    if optional_value not in {"true", "false"}:
        raise ValueError("optional must be true or false.")
    return FieldMapping(
        source_field=values["source_field"],
        destination_field=values["destination_field"],
        optional=optional_value == "true",
    )


def _scalar_value(line: str, expected_key: str) -> str:
    key, value = _key_value(line)
    if key != expected_key:
        raise ValueError(f"expected {expected_key}.")
    return value


def _key_value(line: str) -> tuple[str, str]:
    if ":" not in line:
        raise ValueError("mapping declaration must contain a colon.")
    key, value = line.split(":", maxsplit=1)
    return key.strip(), value.strip().strip('"').strip("'")
