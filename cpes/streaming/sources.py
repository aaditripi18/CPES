"""Event sources for streaming: replay of recorded documents in event-time order."""

from __future__ import annotations

import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any


@dataclass(frozen=True)
class Batch:
    """Documents whose timestamps fall in [start, watermark)."""

    start: datetime
    watermark: datetime
    documents: tuple[dict[str, Any], ...]


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class ReplaySource:
    """Replay recorded documents as if they were arriving live.

    ``timestamp_of`` extracts the source timestamp string from a document (the
    same field the C5 mapping uses). Batches advance by ``tick_seconds`` of event
    time; with ``speed`` set, the replay sleeps so that ``speed`` seconds of event
    time pass per second of wall time (``speed=None`` replays as fast as possible).
    """

    def __init__(self, documents: Iterable[dict[str, Any]], *, timestamp_of, tick_seconds: float, speed: float | None = None, sleep=time.sleep) -> None:
        if tick_seconds <= 0:
            raise ValueError("tick_seconds must be positive.")
        if speed is not None and speed <= 0:
            raise ValueError("speed must be positive.")
        timed = []
        for document in documents:
            value = timestamp_of(document)
            if isinstance(value, str) and value.strip():
                timed.append((_ts(value), document))
        timed.sort(key=lambda item: item[0])
        self._timed = timed
        self._tick = timedelta(seconds=tick_seconds)
        self._speed = speed
        self._sleep = sleep

    @property
    def start(self) -> datetime | None:
        return self._timed[0][0] if self._timed else None

    @property
    def end(self) -> datetime | None:
        return self._timed[-1][0] if self._timed else None

    def __len__(self) -> int:
        return len(self._timed)

    def batches(self) -> Iterator[Batch]:
        if not self._timed:
            return
        position = 0
        cursor = self._timed[0][0]
        while position < len(self._timed):
            watermark = cursor + self._tick
            chunk = []
            while position < len(self._timed) and self._timed[position][0] < watermark:
                chunk.append(self._timed[position][1])
                position += 1
            if self._speed:
                self._sleep(self._tick.total_seconds() / self._speed)
            yield Batch(cursor, watermark, tuple(chunk))
            cursor = watermark
