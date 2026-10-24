"""Build timestamped cross-channel evidence from mapped evidence records.

Turns ``EvidenceRecord``s into the ``PipeEvidence`` / ``RemoteThreadEvidence``
objects ``ContextResolver`` already understands. Every discriminator (which
event codes mean create / connect / remote thread, which user names count as
SYSTEM) is supplied by the caller. A record missing a field the evidence type
needs is skipped and counted in ``skipped``; nothing is guessed.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime

from cpes.adapters.evidence import EvidenceRecord
from cpes.context.models import PipeEvidence, RemoteThreadEvidence, ServiceInstallEvidence


@dataclass(frozen=True)
class TimedEvidence:
    """One evidence object and the source timestamp it was observed at."""

    occurred_at: datetime
    evidence: PipeEvidence | RemoteThreadEvidence | ServiceInstallEvidence


@dataclass(frozen=True)
class EvidenceChannels:
    items: tuple[TimedEvidence, ...]
    skipped: tuple[tuple[str, int], ...] = field(default=())

    @property
    def pipes(self) -> tuple[TimedEvidence, ...]:
        return tuple(item for item in self.items if isinstance(item.evidence, PipeEvidence))

    @property
    def remote_threads(self) -> tuple[TimedEvidence, ...]:
        return tuple(item for item in self.items if isinstance(item.evidence, RemoteThreadEvidence))

    @property
    def service_installs(self) -> tuple[TimedEvidence, ...]:
        return tuple(item for item in self.items if isinstance(item.evidence, ServiceInstallEvidence))


def _basename(path: str | None) -> str:
    # Same rule as cpes.context.resolver._basename.
    return (path or "").replace("/", "\\").split("\\")[-1].lower()


def _nonblank(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def service_command_image(command: str | None) -> str:
    """Executable basename of a service ImagePath / ServiceFileName: quotes and arguments stripped."""

    text = (command or "").strip()
    if text.startswith('"'):
        text = text[1:].split('"', 1)[0]
    else:
        end = text.lower().find(".exe")
        text = text[: end + 4] if end >= 0 else text.split(" ", 1)[0]
    return _basename(text)


class EvidenceChannelBuilder:
    def __init__(
        self,
        *,
        pipe_create_codes: tuple[str, ...],
        pipe_connect_codes: tuple[str, ...],
        remote_thread_codes: tuple[str, ...],
        system_user_names: tuple[str, ...],
        service_install_codes: tuple[str, ...] = (),
    ) -> None:
        codes = (pipe_create_codes, pipe_connect_codes, remote_thread_codes)
        if any(not group for group in codes):
            raise ValueError("pipe create, pipe connect and remote-thread codes are required.")
        flat = [code for group in (*codes, service_install_codes) for code in group]
        if len(flat) != len(set(flat)):
            raise ValueError("an event code may belong to one evidence type only.")
        if not system_user_names or any(not name.strip() for name in system_user_names):
            raise ValueError("system_user_names must be nonblank.")
        self._create = frozenset(pipe_create_codes)
        self._connect = frozenset(pipe_connect_codes)
        self._thread = frozenset(remote_thread_codes)
        self._install = frozenset(service_install_codes)
        self._system = frozenset(name.lower() for name in system_user_names)

    def build(self, records: Iterable[EvidenceRecord]) -> EvidenceChannels:
        items: list[TimedEvidence] = []
        skipped: Counter = Counter()
        for record in records:
            code = str(record.event_code)
            if code not in self._create | self._connect | self._thread | self._install:
                continue
            occurred_at = self._timestamp(record.source_timestamp)
            if code in self._install:
                image = service_command_image(_nonblank(record.service_image_path) or _nonblank(record.service_file_name))
                if not image:
                    skipped["service_install_missing_image"] += 1
                    continue
                items.append(TimedEvidence(occurred_at, ServiceInstallEvidence(str(record.source_event_id), occurred_at, image)))
                continue
            process_guid = _nonblank(record.process_guid)
            if code in self._thread:
                target = _nonblank(record.target_process_guid)
                if process_guid is None or target is None:
                    skipped["remote_thread_missing_guid"] += 1
                    continue
                items.append(TimedEvidence(occurred_at, RemoteThreadEvidence(str(record.source_event_id), process_guid, target, _basename(_nonblank(record.image_path)))))
                continue
            pipe = _nonblank(record.pipe_name)
            user = _nonblank(record.user_name)
            if process_guid is None or pipe is None or user is None:
                skipped["pipe_missing_field"] += 1
                continue
            items.append(TimedEvidence(occurred_at, PipeEvidence(
                event_id=str(record.source_event_id),
                process_guid=process_guid,
                pipe_name=pipe,
                action="create" if code in self._create else "connect",
                user_is_system=user.lower() in self._system,
                image_basename=_basename(_nonblank(record.image_path)),
            )))
        ordered = tuple(sorted(items, key=lambda item: (item.occurred_at, item.evidence.event_id)))
        return EvidenceChannels(ordered, tuple(sorted(skipped.items())))

    @staticmethod
    def _timestamp(value: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (AttributeError, ValueError) as error:
            raise ValueError("evidence source_timestamp must be ISO 8601.") from error
        if parsed.tzinfo is None:
            raise ValueError("evidence source_timestamp must include an offset.")
        return parsed
