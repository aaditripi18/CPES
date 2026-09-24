"""Purely descriptive context derivation for supplied lineage structures."""

from __future__ import annotations

from collections.abc import Iterable

from cpes.lineage.models import ProcessLineageChain

from .models import (
    CommandLineContext,
    ContextEvent,
    ImageModuleContext,
    IntegrityTransition,
    LineageContext,
    LineageRelationship,
    ParentChildRelationship,
    PrivilegeInheritance,
    RegistryContext,
    TemporalContext,
)


class ContextBuilder:
    """Derive factual context without assigning any evaluative meaning."""

    def build(
        self,
        lineage_chain: ProcessLineageChain,
        context_events: Iterable[ContextEvent],
    ) -> LineageContext:
        """Build descriptive context from supplied events and structure."""

        lineage_process_guids = frozenset(lineage_chain.process_guids)
        events = tuple(
            sorted(
                (
                    event
                    for event in context_events
                    if event.process_guid in lineage_process_guids
                ),
                key=lambda event: (event.occurred_at, event.event_id),
            )
        )
        parent_by_process_guid = dict(lineage_chain.parent_by_process_guid)
        children_by_process_guid = dict(lineage_chain.children_by_process_guid)
        relationships = tuple(
            ParentChildRelationship(parent_process_guid, process_guid)
            for process_guid, parent_process_guid in lineage_chain.parent_by_process_guid
            if parent_process_guid in lineage_process_guids
        )
        lineage_relationships = self._lineage_relationships(
            lineage_chain.root_process_guid, children_by_process_guid
        )
        first_event_by_process_guid = self._first_event_by_process_guid(events)

        return LineageContext(
            lineage_chain_id=lineage_chain.lineage_chain_id,
            events=events,
            parent_child_relationships=relationships,
            lineage_relationships=lineage_relationships,
            integrity_transitions=self._integrity_transitions(
                relationships, first_event_by_process_guid
            ),
            privilege_inheritance=self._privilege_inheritance(
                relationships, first_event_by_process_guid
            ),
            command_line_context=tuple(
                CommandLineContext(event.event_id, event.process_guid, event.command_line)
                for event in events
                if event.command_line is not None
            ),
            registry_context=tuple(
                RegistryContext(event.event_id, event.process_guid, event.registry_object)
                for event in events
                if event.registry_object is not None
            ),
            image_module_context=tuple(
                ImageModuleContext(
                    event.event_id, event.process_guid, event.image_path, event.module_path
                )
                for event in events
                if event.image_path is not None or event.module_path is not None
            ),
            temporal_context=self._temporal_context(events),
            is_truncated=lineage_chain.is_truncated,
            is_incomplete=lineage_chain.is_incomplete,
            is_fragmented=lineage_chain.is_fragmented,
        )

    @staticmethod
    def _first_event_by_process_guid(
        events: tuple[ContextEvent, ...],
    ) -> dict[str, ContextEvent]:
        first_event_by_process_guid: dict[str, ContextEvent] = {}
        for event in events:
            first_event_by_process_guid.setdefault(event.process_guid, event)
        return first_event_by_process_guid

    @staticmethod
    def _lineage_relationships(
        root_process_guid: str,
        children_by_process_guid: dict[str, tuple[str, ...]],
    ) -> tuple[LineageRelationship, ...]:
        pending = [(root_process_guid, (), 0)]
        relationships: list[LineageRelationship] = []
        while pending:
            process_guid, ancestors, depth = pending.pop(0)
            relationships.append(LineageRelationship(process_guid, ancestors, depth))
            pending.extend(
                (child_process_guid, ancestors + (process_guid,), depth + 1)
                for child_process_guid in children_by_process_guid.get(process_guid, ())
            )
        return tuple(relationships)

    @staticmethod
    def _integrity_transitions(
        relationships: tuple[ParentChildRelationship, ...],
        events_by_process_guid: dict[str, ContextEvent],
    ) -> tuple[IntegrityTransition, ...]:
        return tuple(
            IntegrityTransition(
                relationship.parent_process_guid,
                relationship.child_process_guid,
                parent_event.integrity_level,
                child_event.integrity_level,
            )
            for relationship in relationships
            if (
                (parent_event := events_by_process_guid.get(relationship.parent_process_guid))
                and (child_event := events_by_process_guid.get(relationship.child_process_guid))
                and parent_event.integrity_level is not None
                and child_event.integrity_level is not None
                and parent_event.integrity_level != child_event.integrity_level
            )
        )

    @staticmethod
    def _privilege_inheritance(
        relationships: tuple[ParentChildRelationship, ...],
        events_by_process_guid: dict[str, ContextEvent],
    ) -> tuple[PrivilegeInheritance, ...]:
        return tuple(
            PrivilegeInheritance(
                relationship.parent_process_guid,
                relationship.child_process_guid,
                parent_event.privilege_identity,
                child_event.privilege_identity,
            )
            for relationship in relationships
            if (
                (parent_event := events_by_process_guid.get(relationship.parent_process_guid))
                and (child_event := events_by_process_guid.get(relationship.child_process_guid))
                and parent_event.privilege_identity is not None
                and child_event.privilege_identity is not None
            )
        )

    @staticmethod
    def _temporal_context(events: tuple[ContextEvent, ...]) -> tuple[TemporalContext, ...]:
        return tuple(
            TemporalContext(
                earlier_event.event_id,
                later_event.event_id,
                (later_event.occurred_at - earlier_event.occurred_at).total_seconds(),
            )
            for earlier_event, later_event in zip(events, events[1:])
        )
