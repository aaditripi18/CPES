from __future__ import annotations

import unittest

from cpes.adapters.mapping import CanonicalEventMapper, parse_mapping_configuration
from cpes.adapters.models import FieldMapping, MappingConfiguration


def mapping_configuration() -> MappingConfiguration:
    return MappingConfiguration(
        version="test-v1",
        fields=(
            FieldMapping("@timestamp", "source_timestamp", False),
            FieldMapping("event.id", "source_event_id", False),
            FieldMapping("event.code", "event_code", True),
            FieldMapping("data.process_guid", "process_guid", True),
            FieldMapping("data.parent_process_guid", "parent_process_guid", True),
            FieldMapping("data.process_id", "process_id", True),
            FieldMapping("data.integrity_level", "integrity_level", True),
            FieldMapping("data.command_line", "command_line", True),
            FieldMapping("data.registry_object", "registry_object", True),
            FieldMapping("data.image_path", "image_path", True),
            FieldMapping("data.module_path", "module_path", True),
        ),
    )


class CanonicalEventMapperTests(unittest.TestCase):
    def test_maps_declared_values_without_changes(self) -> None:
        document = {
            "@timestamp": "2026-01-01T00:00:00.000Z",
            "event": {"id": "immutable-1", "code": "1"},
            "data": {"process_id": 44, "command_line": "whoami"},
        }

        event = CanonicalEventMapper(mapping_configuration()).map_document(document)

        self.assertEqual(event.source_timestamp, document["@timestamp"])
        self.assertEqual(event.source_event_id, document["event"]["id"])
        self.assertEqual(event.process_id, 44)
        self.assertEqual(event.command_line, "whoami")
        self.assertIsNone(event.process_guid)

    def test_rejects_missing_required_ordering_field(self) -> None:
        with self.assertRaisesRegex(ValueError, "required source field"):
            CanonicalEventMapper(mapping_configuration()).map_document(
                {"@timestamp": "2026-01-01T00:00:00.000Z"}
            )

    def test_parses_constrained_declarative_yaml(self) -> None:
        configuration = parse_mapping_configuration(
            (
                "version: mapping-v1",
                "fields:",
                "  - source_field: source.timestamp",
                "    destination_field: source_timestamp",
                "    optional: false",
                "  - source_field: source.id",
                "    destination_field: source_event_id",
                "    optional: false",
                "  - source_field: source.code",
                "    destination_field: event_code",
                "    optional: true",
                "  - source_field: source.process_guid",
                "    destination_field: process_guid",
                "    optional: true",
                "  - source_field: source.parent_process_guid",
                "    destination_field: parent_process_guid",
                "    optional: true",
                "  - source_field: source.process_id",
                "    destination_field: process_id",
                "    optional: true",
                "  - source_field: source.integrity_level",
                "    destination_field: integrity_level",
                "    optional: true",
                "  - source_field: source.command_line",
                "    destination_field: command_line",
                "    optional: true",
                "  - source_field: source.registry_object",
                "    destination_field: registry_object",
                "    optional: true",
                "  - source_field: source.image_path",
                "    destination_field: image_path",
                "    optional: true",
                "  - source_field: source.module_path",
                "    destination_field: module_path",
                "    optional: true",
            )
        )

        self.assertEqual(configuration.version, "mapping-v1")
        self.assertEqual(len(configuration.fields), 11)
