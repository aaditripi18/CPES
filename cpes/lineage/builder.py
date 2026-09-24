"""Purely structural ProcessGUID-keyed lineage reconstruction."""

from __future__ import annotations

from collections.abc import Iterable

from .models import ProcessLineageChain, ProcessNode


class LineageBuilder:
    """Build deterministic lineage trees without inferring missing ancestry."""

    def build(self, process_nodes: Iterable[ProcessNode]) -> tuple[ProcessLineageChain, ...]:
        """Build reconstructable structural chains from supplied process nodes.

        ``process_guid`` is the only identity key. Missing parents remain
        unresolved and create a truncated, fragmented structural result; they
        are never created or guessed.
        """

        nodes_by_guid = self._index_nodes(process_nodes)
        self._reject_cycles(nodes_by_guid)
        children_by_guid = self._children_by_guid(nodes_by_guid)
        components = self._connected_components(nodes_by_guid, children_by_guid)
        chains = tuple(
            self._build_chain(component, nodes_by_guid, children_by_guid)
            for component in components
        )
        return tuple(sorted(chains, key=lambda chain: chain.lineage_chain_id))

    @staticmethod
    def _index_nodes(process_nodes: Iterable[ProcessNode]) -> dict[str, ProcessNode]:
        nodes_by_guid: dict[str, ProcessNode] = {}
        for process_node in process_nodes:
            if not process_node.process_guid:
                raise ValueError("process_guid must not be blank.")
            if process_node.process_guid in nodes_by_guid:
                raise ValueError("duplicate process_guid values are not structural input.")
            nodes_by_guid[process_node.process_guid] = process_node
        return nodes_by_guid

    @staticmethod
    def _children_by_guid(
        nodes_by_guid: dict[str, ProcessNode],
    ) -> dict[str, tuple[str, ...]]:
        mutable_children = {process_guid: [] for process_guid in nodes_by_guid}
        for process_node in nodes_by_guid.values():
            parent_guid = process_node.parent_process_guid
            if parent_guid in nodes_by_guid:
                mutable_children[parent_guid].append(process_node.process_guid)
        return {
            process_guid: tuple(sorted(children))
            for process_guid, children in mutable_children.items()
        }

    @staticmethod
    def _reject_cycles(nodes_by_guid: dict[str, ProcessNode]) -> None:
        for process_guid in nodes_by_guid:
            seen: set[str] = set()
            current_guid: str | None = process_guid
            while current_guid in nodes_by_guid:
                if current_guid in seen:
                    raise ValueError("lineage input contains a parent cycle.")
                seen.add(current_guid)
                current_guid = nodes_by_guid[current_guid].parent_process_guid

    @staticmethod
    def _connected_components(
        nodes_by_guid: dict[str, ProcessNode],
        children_by_guid: dict[str, tuple[str, ...]],
    ) -> tuple[tuple[str, ...], ...]:
        remaining = set(nodes_by_guid)
        components: list[tuple[str, ...]] = []
        while remaining:
            start_guid = min(remaining)
            pending = [start_guid]
            component: set[str] = set()
            while pending:
                current_guid = pending.pop()
                if current_guid in component:
                    continue
                component.add(current_guid)
                process_node = nodes_by_guid[current_guid]
                if process_node.parent_process_guid in nodes_by_guid:
                    pending.append(process_node.parent_process_guid)
                pending.extend(children_by_guid[current_guid])
            remaining.difference_update(component)
            components.append(tuple(sorted(component)))
        return tuple(sorted(components, key=lambda component: component[0]))

    @staticmethod
    def _build_chain(
        component: tuple[str, ...],
        nodes_by_guid: dict[str, ProcessNode],
        children_by_guid: dict[str, tuple[str, ...]],
    ) -> ProcessLineageChain:
        unresolved_parent_process_guids = tuple(
            sorted(
                {
                    process_node.parent_process_guid
                    for process_guid in component
                    if (
                        (process_node := nodes_by_guid[process_guid]).parent_process_guid
                        and process_node.parent_process_guid not in nodes_by_guid
                    )
                }
            )
        )
        anchors = tuple(
            process_guid
            for process_guid in component
            if (
                nodes_by_guid[process_guid].parent_process_guid is None
                or nodes_by_guid[process_guid].parent_process_guid not in nodes_by_guid
            )
        )
        root_process_guid = min(anchors) if anchors else component[0]
        parent_by_process_guid = tuple(
            (process_guid, nodes_by_guid[process_guid].parent_process_guid)
            for process_guid in component
        )
        child_relationships = tuple(
            (process_guid, tuple(child for child in children_by_guid[process_guid] if child in component))
            for process_guid in component
        )
        is_truncated = bool(unresolved_parent_process_guids)
        return ProcessLineageChain(
            lineage_chain_id=root_process_guid,
            root_process_guid=root_process_guid,
            process_guids=component,
            parent_by_process_guid=parent_by_process_guid,
            children_by_process_guid=child_relationships,
            unresolved_parent_process_guids=unresolved_parent_process_guids,
            is_truncated=is_truncated,
            is_incomplete=any(nodes_by_guid[process_guid].is_incomplete for process_guid in component),
            is_fragmented=is_truncated,
        )
