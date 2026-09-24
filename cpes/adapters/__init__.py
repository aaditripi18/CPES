"""C5 retrieval adapter interfaces and the quarantined Elastic implementation."""

from .contracts import CanonicalEventStream
from .elastic import ElasticRetrievalAdapter
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
    "FieldMapping",
    "MappingConfiguration",
    "load_mapping_configuration",
    "parse_mapping_configuration",
]
