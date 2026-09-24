from __future__ import annotations

import unittest

from cpes.adapters.elastic import ElasticRetrievalAdapter
from cpes.adapters.mapping import CanonicalEventMapper

from .test_mapping import mapping_configuration


class FakeElasticClient:
    def __init__(self, response: dict[str, object]) -> None:
        self.response = response
        self.request: dict[str, object] | None = None

    def search(self, **kwargs: object) -> dict[str, object]:
        self.request = kwargs
        return self.response


class ElasticRetrievalAdapterTests(unittest.TestCase):
    def test_retrieves_and_orders_canonical_events(self) -> None:
        client = FakeElasticClient(
            {
                "hits": {
                    "hits": [
                        {
                            "_source": {
                                "@timestamp": "2026-01-01T00:00:01.000Z",
                                "event": {"id": "b"},
                            }
                        },
                        {
                            "_source": {
                                "@timestamp": "2026-01-01T00:00:01.000Z",
                                "event": {"id": "a"},
                            }
                        },
                    ]
                }
            }
        )
        adapter = ElasticRetrievalAdapter(client, CanonicalEventMapper(mapping_configuration()))

        events = adapter.retrieve(index="cpes-telemetry-raw-v1", query={"match_all": {}})

        self.assertEqual([event.source_event_id for event in events], ["a", "b"])
        self.assertEqual(
            client.request,
            {"index": "cpes-telemetry-raw-v1", "query": {"match_all": {}}},
        )
