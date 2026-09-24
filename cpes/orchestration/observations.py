"""Pluggable, factual event-group to observation strategies."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Protocol
from cpes.scoring.models import SignalObservation, SourceReference
from cpes.windowing.models import EventGroup

class ObservationGenerator(Protocol):
    def generate(self, event_group: EventGroup) -> tuple[SignalObservation, ...]: ...

@dataclass(frozen=True)
class EventFieldPresenceRule:
    signal_id: str
    field_name: str

class EventFieldPresenceObservationGenerator:
    """Generate only caller-declared factual field-presence observations."""
    _ALLOWED_FIELDS = frozenset({"integrity_level", "command_line", "registry_object", "image_path", "module_path"})
    def __init__(self, rules: tuple[EventFieldPresenceRule, ...]) -> None:
        if not rules or len({rule.signal_id for rule in rules}) != len(rules): raise ValueError("unique observation rules are required.")
        if any(not rule.signal_id or rule.field_name not in self._ALLOWED_FIELDS for rule in rules): raise ValueError("rules must name an allowed factual event field.")
        self._rules = rules
    def generate(self, event_group: EventGroup) -> tuple[SignalObservation, ...]:
        return tuple(SignalObservation(rule.signal_id, bool(references := tuple(SourceReference(event.process_guid, event.event_id) for event in event_group.events if getattr(event, rule.field_name) is not None)), references) for rule in self._rules)


class IntegrityElevationObservationGenerator:
    """Observe a privilege-escalation integrity elevation across the lineage.

    Fires when the window contains a parent->child integrity transition whose
    child integrity level is strictly higher than its parent's, per a
    caller-supplied integrity ordering (e.g. Untrusted < Low < Medium < High <
    System). This is the flagship context-aware signal (Bible §8.2/§8.4): it is
    a relationship across the process lineage, not a per-event field. The signal
    is binary; its evidential weight is derived from the corpus in M8 and applied
    additively in C9, so no threshold or weight is embedded here.
    """

    def __init__(self, signal_id: str, integrity_order: tuple[str, ...]) -> None:
        if not signal_id or not signal_id.strip():
            raise ValueError("signal_id must be a nonblank identifier.")
        if not integrity_order or len(set(integrity_order)) != len(integrity_order):
            raise ValueError("integrity_order must be a nonempty tuple of unique levels.")
        if any(not level or not level.strip() for level in integrity_order):
            raise ValueError("integrity_order levels must be nonblank.")
        self._signal_id = signal_id
        self._rank = {level: index for index, level in enumerate(integrity_order)}

    def generate(self, event_group: EventGroup) -> tuple[SignalObservation, ...]:
        references = tuple(
            SourceReference(transition.child_process_guid)
            for transition in event_group.integrity_transitions
            if transition.parent_integrity_level in self._rank
            and transition.child_integrity_level in self._rank
            and self._rank[transition.child_integrity_level] > self._rank[transition.parent_integrity_level]
        )
        return (SignalObservation(self._signal_id, bool(references), references),)


class CommandLineIndicatorObservationGenerator:
    """Observe an auto-elevation invocation indicator in command-line context.

    Fires when any windowed event's command line contains a caller-supplied
    indicator token (case-insensitive substring), e.g. a known auto-elevating
    system binary. Sanctioned by Bible §8.4 as a command-line *signal* (not a
    signature): the presence is observed here, while how discriminative it is
    remains a corpus-derived weight applied downstream.
    """

    def __init__(self, signal_id: str, indicators: tuple[str, ...]) -> None:
        if not signal_id or not signal_id.strip():
            raise ValueError("signal_id must be a nonblank identifier.")
        if not indicators:
            raise ValueError("at least one indicator is required.")
        if any(not indicator or not indicator.strip() for indicator in indicators):
            raise ValueError("indicators must be nonblank.")
        self._signal_id = signal_id
        self._indicators = tuple(indicator.lower() for indicator in indicators)

    def generate(self, event_group: EventGroup) -> tuple[SignalObservation, ...]:
        references = tuple(
            SourceReference(event.process_guid, event.event_id)
            for event in event_group.events
            if event.command_line is not None
            and any(indicator in event.command_line.lower() for indicator in self._indicators)
        )
        return (SignalObservation(self._signal_id, bool(references), references),)


class CompositeObservationGenerator:
    """Run several observation generators and concatenate their observations.

    Itself an ``ObservationGenerator`` (so the pipeline seam is unchanged), it
    lets one pipeline run many signals. It fails closed on duplicate signal
    identifiers so a misconfiguration surfaces here rather than inside the
    scorer, which requires unique signal identifiers.
    """

    def __init__(self, generators: tuple[ObservationGenerator, ...]) -> None:
        if not generators:
            raise ValueError("at least one observation generator is required.")
        self._generators = generators

    def generate(self, event_group: EventGroup) -> tuple[SignalObservation, ...]:
        observations = tuple(
            observation
            for generator in self._generators
            for observation in generator.generate(event_group)
        )
        signal_ids = [observation.signal_id for observation in observations]
        if len(signal_ids) != len(set(signal_ids)):
            raise ValueError("composite generators must emit unique signal_id values.")
        return observations
