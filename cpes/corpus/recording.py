"""Deterministic execution-bracket metadata generation for M2.

This module deliberately operates only on manually supplied execution metadata.
It does not read, parse, process, or analyze telemetry.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json


_UTC_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_RUN_TYPES = frozenset({"attack", "benign"})


@dataclass(frozen=True)
class ExecutionBracket:
    """A manually recorded, bounded laboratory activity interval."""

    run_id: str
    run_type: str
    technique_id: str | None
    atomic_test_id: str | None
    variant: str
    started_at: str
    ended_at: str
    operator: str
    cleanup_status: str
    evidence_reference: str

    def as_dict(self) -> dict[str, str | None]:
        """Return a stable, serialization-ready metadata representation."""

        return asdict(self)


def create_execution_bracket(
    *,
    run_type: str,
    technique_id: str | None,
    atomic_test_id: str | None,
    variant: str,
    started_at: str,
    ended_at: str,
    operator: str,
    cleanup_status: str,
    evidence_reference: str,
) -> ExecutionBracket:
    """Create deterministic metadata for one manually bracketed activity.

    All timestamps are supplied by the operator and normalized to UTC. The
    identifier is a stable digest of the normalized metadata, so identical
    inputs always produce the same bracket record.
    """

    normalized_run_type = _required_value("run_type", run_type).lower()
    if normalized_run_type not in _RUN_TYPES:
        raise ValueError("run_type must be 'attack' or 'benign'.")

    normalized_technique_id = _optional_value(technique_id)
    normalized_atomic_test_id = _optional_value(atomic_test_id)
    if normalized_run_type == "attack":
        if normalized_technique_id is None:
            raise ValueError("attack brackets require a technique_id.")
        if normalized_atomic_test_id is None:
            raise ValueError("attack brackets require an atomic_test_id.")

    normalized_started_at = _normalize_timestamp(started_at)
    normalized_ended_at = _normalize_timestamp(ended_at)
    if normalized_ended_at < normalized_started_at:
        raise ValueError("ended_at must not precede started_at.")

    record_without_id = {
        "run_type": normalized_run_type,
        "technique_id": normalized_technique_id,
        "atomic_test_id": normalized_atomic_test_id,
        "variant": _required_value("variant", variant),
        "started_at": normalized_started_at,
        "ended_at": normalized_ended_at,
        "operator": _required_value("operator", operator),
        "cleanup_status": _required_value("cleanup_status", cleanup_status),
        "evidence_reference": _required_value(
            "evidence_reference", evidence_reference
        ),
    }
    canonical_record = json.dumps(
        record_without_id, sort_keys=True, separators=(",", ":")
    )
    run_id = f"m2-{sha256(canonical_record.encode('utf-8')).hexdigest()[:16]}"

    return ExecutionBracket(run_id=run_id, **record_without_id)


def _required_value(name: str, value: str) -> str:
    normalized_value = value.strip()
    if not normalized_value:
        raise ValueError(f"{name} must not be blank.")
    return normalized_value


def _optional_value(value: str | None) -> str | None:
    if value is None:
        return None
    normalized_value = value.strip()
    return normalized_value or None


def _normalize_timestamp(value: str) -> str:
    try:
        parsed_value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("timestamps must be ISO 8601 values with an offset.") from error

    if parsed_value.tzinfo is None:
        raise ValueError("timestamps must include a UTC offset.")
    return parsed_value.astimezone(timezone.utc).strftime(_UTC_TIMESTAMP_FORMAT)
