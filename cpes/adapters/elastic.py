"""The sole Elasticsearch-aware CPES component (C5)."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
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


class ElasticPollingSource:
    """Fetch newly indexed documents from a live index, for streaming scoring.

    Shippers deliver in batches, so a document can be indexed after a later one.
    Each poll therefore re-reads the last ``lateness_seconds`` before the newest
    timestamp seen and drops documents already returned (by ``_id``). The caller
    should only close windows older than ``safe_watermark()``, which lags the newest
    timestamp by the same lateness, so late documents still reach their window.
    """

    def __init__(self, client: Elasticsearch, *, index: str, timestamp_field: str = "@timestamp", lateness_seconds: float = 30.0, page_size: int = 1000, query: Mapping[str, Any] | None = None) -> None:
        if lateness_seconds < 0 or page_size <= 0:
            raise ValueError("lateness_seconds must be >= 0 and page_size > 0.")
        self._client = client
        self._index = index
        self._field = timestamp_field
        self._lateness = lateness_seconds
        self._page = page_size
        self._query = dict(query) if query else None
        self._newest: str | None = None
        self._seen: dict[str, str] = {}  # _id -> timestamp, pruned to the lateness horizon

    @staticmethod
    def _parse(stamp: str) -> datetime:
        return datetime.fromisoformat(stamp.replace("Z", "+00:00"))

    def safe_watermark(self) -> datetime | None:
        """Time up to which windows may be closed, or None before any data."""

        if self._newest is None:
            return None
        return self._parse(self._newest) - timedelta(seconds=self._lateness)

    def poll(self) -> tuple[Mapping[str, Any], ...]:
        must: list[dict[str, Any]] = [self._query] if self._query else []
        horizon = self.safe_watermark()
        if horizon is not None:
            must.append({"range": {self._field: {"gte": horizon.isoformat()}}})
        query = {"bool": {"must": must}} if must else {"match_all": {}}
        fresh: list[Mapping[str, Any]] = []
        search_after = None
        while True:
            kwargs: dict[str, Any] = {"index": self._index, "query": query, "size": self._page, "sort": [{self._field: "asc"}, {"_doc": "asc"}]}
            if search_after is not None:
                kwargs["search_after"] = search_after
            hits = self._client.search(**kwargs).get("hits", {}).get("hits", [])
            if not hits:
                break
            for hit in hits:
                source = hit.get("_source")
                if not isinstance(source, Mapping):
                    raise ValueError("each Elasticsearch hit must contain an object _source.")
                if hit.get("_id") in self._seen:
                    continue
                stamp = source.get(self._field)
                self._seen[hit.get("_id")] = stamp
                fresh.append(source)
                if isinstance(stamp, str) and (self._newest is None or self._parse(stamp) > self._parse(self._newest)):
                    self._newest = stamp
            search_after = hits[-1].get("sort")
            if len(hits) < self._page or search_after is None:
                break
        horizon = self.safe_watermark()
        if horizon is not None:  # forget ids older than anything a future poll can return
            self._seen = {key: stamp for key, stamp in self._seen.items() if not isinstance(stamp, str) or self._parse(stamp) >= horizon}
        return tuple(fresh)
