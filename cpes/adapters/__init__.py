"""C5 retrieval adapter interfaces and the quarantined Elastic implementation."""

from .contracts import CanonicalEventStream
from .elastic import ElasticRetrievalAdapter
from .evidence import EvidenceRecord, EvidenceRecordMapper, load_evidence_mapping
from .mapping import (
    CanonicalEventMapper,
    load_mapping_configuration,
    parse_mapping_configuration,
)
from .models import CanonicalEvent, FieldMapping, MappingConfiguration

__all__ = [
    "CanonicalEvent",
    "CanonicalEventMapper",
    "CanonicalEventStream",
    "ElasticRetrievalAdapter",
    "EvidenceRecord",
    "EvidenceRecordMapper",
    "FieldMapping",
    "MappingConfiguration",
    "load_evidence_mapping",
    "load_mapping_configuration",
    "parse_mapping_configuration",
]
