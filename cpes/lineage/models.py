"""Backend-neutral structural models for ProcessGUID-based lineage."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProcessNode:
    """One process identity and its asserted structural parent relationship."""

    process_guid: str
    parent_process_guid: str | None
    process_id: int | None = None
    is_incomplete: bool = False


@dataclass(frozen=True)
class ProcessLineageChain:
    """A structural lineage tree or reconstructable connected fragment."""

    lineage_chain_id: str
    root_process_guid: str
    process_guids: tuple[str, ...]
    parent_by_process_guid: tuple[tuple[str, str | None], ...]
    children_by_process_guid: tuple[tuple[str, tuple[str, ...]], ...]
    unresolved_parent_process_guids: tuple[str, ...]
    is_truncated: bool
    is_incomplete: bool
    is_fragmented: bool
