"""The sole Elasticsearch-aware CPES component (C5)."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from elasticsearch import Elasticsearch

from .mapping import CanonicalEventMapper
from .models import CanonicalEvent


class ElasticRetrievalAdapter:
    """Retrieve Elastic documents and expose ordered canonical events only."""

    def __init__(self, client: Elasticsearch, mapper: CanonicalEventMapper) -> None:
        self._client = client
        self._mapper = mapper

    def retrieve(self, *, index: str, query: Mapping[str, Any]) -> tuple[CanonicalEvent, ...]:
        """Read source documents and order their direct canonical representations."""

        response = self._client.search(index=index, query=dict(query))
        documents = self._source_documents(response)
        return self.canonical_events(documents)

    def canonical_events(
        self, documents: Iterable[Mapping[str, Any]]
    ) -> tuple[CanonicalEvent, ...]:
        """Map supplied documents and apply the approved deterministic ordering."""

        events = tuple(self._mapper.map_document(document) for document in documents)
        return tuple(sorted(events, key=lambda event: (event.source_timestamp, event.source_event_id)))

    @staticmethod
    def _source_documents(response: Any) -> tuple[Mapping[str, Any], ...]:
        hits = response.get("hits", {}).get("hits", [])
        documents: list[Mapping[str, Any]] = []
        for hit in hits:
            source = hit.get("_source")
            if not isinstance(source, Mapping):
                raise ValueError("each Elasticsearch hit must contain an object _source.")
            documents.append(source)
        return tuple(documents)
