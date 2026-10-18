"""Incremental (live) scoring over an arriving event stream (additive to C5–C10).

The Elasticsearch poller for live telemetry lives in ``cpes.adapters.elastic``
(the only Elasticsearch-aware component); this package is backend-neutral.
"""

from .scorer import ClosedWindow, StreamingScorer
from .sources import ReplaySource

__all__ = ["ClosedWindow", "ReplaySource", "StreamingScorer"]
