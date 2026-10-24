"""Attach cross-channel evidence to assembled detection windows (C8, additive).

Assignment rules (see docs/design/evidence-channels-and-package-evaluation.md):

* remote-thread evidence → windows of the chain containing its source process,
  when its time lies in [start, end);
* pipe *connect* evidence → windows of the chain containing the connecting
  process, when its time lies in the window;
* pipe *create* evidence with the same pipe name as an attached connect, from
  any chain, when its time lies in the same window;
* service-install evidence (not tied to a process) → every window whose time
  range contains it.

The window is the only temporal scope; nothing outside it is associated.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import replace

from cpes.context.models import PipeEvidence, RemoteThreadEvidence, ServiceInstallEvidence

from .models import DetectionWindow


class EvidenceWindowAttacher:
    def attach(
        self,
        windows: Iterable[DetectionWindow],
        evidence: Iterable,  # TimedEvidence from cpes.orchestration.evidence
        chain_members: Mapping[str, frozenset[str]],
    ) -> tuple[DetectionWindow, ...]:
        items = tuple(evidence)
        threads = [item for item in items if isinstance(item.evidence, RemoteThreadEvidence)]
        connects = [item for item in items if isinstance(item.evidence, PipeEvidence) and item.evidence.action == "connect"]
        creates = [item for item in items if isinstance(item.evidence, PipeEvidence) and item.evidence.action == "create"]
        installs = [item for item in items if isinstance(item.evidence, ServiceInstallEvidence)]
        out: list[DetectionWindow] = []
        for window in windows:
            members = chain_members.get(window.event_group.lineage_chain_id, frozenset())
            inside = lambda item: window.start_at <= item.occurred_at < window.end_at  # noqa: E731
            window_threads = tuple(t.evidence for t in threads if t.evidence.source_process_guid in members and inside(t))
            window_connects = [c for c in connects if c.evidence.process_guid in members and inside(c)]
            pipe_names = {c.evidence.pipe_name for c in window_connects}
            window_creates = [c for c in creates if c.evidence.pipe_name in pipe_names and inside(c)]
            pipes = tuple(item.evidence for item in sorted(window_creates + window_connects, key=lambda item: (item.occurred_at, item.evidence.event_id)))
            window_installs = tuple(i.evidence for i in installs if inside(i))
            if not window_threads and not pipes and not window_installs:
                out.append(window)
                continue
            out.append(replace(window, event_group=replace(window.event_group, pipe_evidence=pipes, remote_thread_evidence=window_threads, service_install_evidence=window_installs)))
        return tuple(out)
