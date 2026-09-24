"""Validation for manually completed M3 audit records.

The functions validate record completeness only. They do not infer labels,
evaluate evidence, or change the manually recorded outcome.
"""

from collections.abc import Mapping


_LABEL_AUDIT_FIELDS = frozenset(
    {
        "audit_id",
        "run_id",
        "recorded_label",
        "audit_outcome",
        "evidence_reference",
        "reviewer",
        "reviewed_at",
    }
)
_BENIGN_REVIEW_FIELDS = frozenset(
    {
        "review_id",
        "category",
        "observed_status",
        "evidence_reference",
        "reviewer",
        "reviewed_at",
    }
)


def validate_label_audit_record(record: Mapping[str, str]) -> None:
    """Validate that a manual label-audit record contains its evidence trail."""

    _require_complete(record, _LABEL_AUDIT_FIELDS)


def validate_benign_review_record(record: Mapping[str, str]) -> None:
    """Validate that a manual hard-negative review record is complete."""

    _require_complete(record, _BENIGN_REVIEW_FIELDS)


def _require_complete(record: Mapping[str, str], fields: frozenset[str]) -> None:
    missing_fields = sorted(fields.difference(record))
    if missing_fields:
        raise ValueError(f"Missing required fields: {', '.join(missing_fields)}.")
    blank_fields = sorted(field for field in fields if not record.get(field, "").strip())
    if blank_fields:
        raise ValueError(f"Blank required fields: {', '.join(blank_fields)}.")
