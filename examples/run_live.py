"""Stage 3 live runner — retrieve real Sysmon telemetry from Elasticsearch and
reconstruct process-lineage chains.

Goal of this run: prove the C5 retrieval adapter + reconciled field mapping +
lineage builder work on the machine's ACTUAL telemetry. CPES scoring is
intentionally not run here — evidence weights come from the corpus (a later
stage), so this run validates retrieval and lineage only.

Configuration comes from environment variables so no secret is stored in code:
    CPES_ES_PASSWORD   (required)  password for the elastic user
    CPES_ES_URL        default https://localhost:9200
    CPES_ES_USER       default elastic
    CPES_ES_INDEX      default cpes-telemetry-raw-v1
"""

from __future__ import annotations

import os
from pathlib import Path

from elasticsearch import Elasticsearch

from cpes.adapters.elastic import ElasticRetrievalAdapter
from cpes.adapters.mapping import CanonicalEventMapper, load_mapping_configuration
from cpes.lineage import LineageBuilder
from cpes.orchestration import CanonicalEventTranslator

_REPO_ROOT = Path(__file__).resolve().parent.parent
_MAPPING_PATH = _REPO_ROOT / "configs" / "elastic-sysmon-field-mapping-v1.yaml"


def main() -> None:
    password = os.environ.get("CPES_ES_PASSWORD")
    if not password:
        raise SystemExit(
            "Set CPES_ES_PASSWORD first, e.g.  $env:CPES_ES_PASSWORD = \"<elastic password>\""
        )
    url = os.environ.get("CPES_ES_URL", "https://localhost:9200")
    user = os.environ.get("CPES_ES_USER", "elastic")
    index = os.environ.get("CPES_ES_INDEX", "cpes-telemetry-raw-v1")

    # Local lab cluster uses a self-signed certificate; skip cert verification.
    client = Elasticsearch(
        url, basic_auth=(user, password), verify_certs=False, ssl_show_warn=False
    )
    version = client.info()["version"]["number"]
    print(f"Connected to Elasticsearch {version} at {url}")

    mapper = CanonicalEventMapper(load_mapping_configuration(_MAPPING_PATH))
    # Adapter constructed to prove wiring; we call the mapper via canonical_events
    # so we can request more than the default hit size.
    adapter = ElasticRetrievalAdapter(client, mapper)

    # Sysmon ProcessCreate (EID 1) — the events that carry process lineage.
    query = {
        "bool": {
            "must": [
                {"term": {"event.code": "1"}},
                {"term": {"winlog.provider_name": "Microsoft-Windows-Sysmon"}},
            ]
        }
    }
    response = client.search(index=index, query=query, size=2000, sort=[{"@timestamp": "asc"}])
    documents = [hit["_source"] for hit in response["hits"]["hits"]]
    print(f"Retrieved {len(documents)} Sysmon EID 1 document(s) from {index}")
    if not documents:
        raise SystemExit("No EID 1 documents returned — check the index name and that Sysmon is flowing.")

    events = adapter.canonical_events(documents)
    translated = CanonicalEventTranslator().translate(events)
    chains = LineageBuilder().build(translated.process_nodes)

    image_by_guid: dict[str, str | None] = {}
    integrity_by_guid: dict[str, str] = {}
    for context_event in translated.context_events:
        image_by_guid.setdefault(context_event.process_guid, context_event.image_path)
        if context_event.integrity_level is not None:
            integrity_by_guid.setdefault(context_event.process_guid, context_event.integrity_level)

    print(
        f"Reconstructed {len(chains)} lineage chain(s) "
        f"from {len(translated.process_nodes)} unique process(es)"
    )
    print(f"Integrity levels observed: {sorted(set(integrity_by_guid.values()))}")

    def short_name(guid: str) -> str:
        image = image_by_guid.get(guid) or "?"
        return image.split("\\")[-1]

    multi_process_chains = sorted(
        (chain for chain in chains if len(chain.process_guids) > 1),
        key=lambda chain: len(chain.process_guids),
        reverse=True,
    )
    print(f"\nLargest reconstructed chains (parent -> child), showing up to 5:")
    for chain in multi_process_chains[:5]:
        children_by_guid = dict(chain.children_by_process_guid)
        truncated = " [truncated: parent outside window]" if chain.is_truncated else ""
        print(f"\n  chain root {short_name(chain.root_process_guid)} "
              f"({len(chain.process_guids)} processes){truncated}")

        def walk(guid: str, depth: int) -> None:
            integrity = integrity_by_guid.get(guid, "-")
            print("      " + "  " * depth + f"{short_name(guid)}  [{integrity}]")
            for child in children_by_guid.get(guid, ()):
                walk(child, depth + 1)

        walk(chain.root_process_guid, 0)

    if not multi_process_chains:
        print("  (No multi-process chains in this window — parents were created before it. "
              "This still confirms retrieval + mapping; run again after generating activity.)")

    print("\nStage 3 check complete: real telemetry retrieved and lineage reconstructed.")


if __name__ == "__main__":
    main()
