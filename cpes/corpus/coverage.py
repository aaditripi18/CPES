"""Validation for manually recorded M3 coverage observations.

This module validates the shape of an observation entered by a reviewer. It
does not inspect telemetry, derive coverage, or alter the recorded status.
"""

from collections.abc import Mapping


_REQUIRED_FIELDS = frozenset(
    {
        "observation_id",
        "technique_id",
        "event_id",
        "coverage_status",
        "observation_timestamp",
        "evidence_reference",
        "reviewer",
    }
)
_MANUAL_STATUSES = frozenset({"passed", "incomplete", "missing", "not-applicable"})


def validate_coverage_observation(observation: Mapping[str, str]) -> None:
    """Validate a manually supplied observation without interpreting it.

    A status of ``incomplete`` or ``missing`` must include the reviewer's
    recorded reason. The value itself is preserved and never repaired.
    """

    _require_fields(observation, _REQUIRED_FIELDS)
    _require_nonblank_fields(observation, _REQUIRED_FIELDS)

    status = observation["coverage_status"]
    if status not in _MANUAL_STATUSES:
        raise ValueError("coverage_status must be a manually recorded M3 status.")
    if status in {"incomplete", "missing"}:
        _require_nonblank_fields(observation, {"incomplete_reason"})


def _require_fields(record: Mapping[str, str], fields: frozenset[str]) -> None:
    missing_fields = sorted(fields.difference(record))
    if missing_fields:
        raise ValueError(f"Missing required fields: {', '.join(missing_fields)}.")


def _require_nonblank_fields(record: Mapping[str, str], fields: frozenset[str]) -> None:
    blank_fields = sorted(field for field in fields if not record.get(field, "").strip())
    if blank_fields:
        raise ValueError(f"Blank required fields: {', '.join(blank_fields)}.")
