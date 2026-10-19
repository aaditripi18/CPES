"""Processes whose own image the telemetry recorded as validly signed (C7, additive).

Sysmon image-load records (EID 7) carry ``Signed`` and ``SignatureStatus`` for
every module a process loads, including, when the configuration logs it, the
process's own executable. ``ContextResolver`` can use the resulting set to skip
the service-location anchor for vendor binaries (pre-registered as S1 in
docs/design/service-signature-suppressor.md).

Only positive evidence counts: a process with no own-image record, or with an
unsigned or invalid signature, is never in the set. What counts as "signed" and
"valid" is supplied by the caller; values are compared case-insensitively.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class ImageLoad:
    """The fields of one image-load record needed for the own-image signature test."""

    process_guid: str | None
    image_path: str | None
    loaded_path: str | None
    signed: str | None
    signature_status: str | None


def _norm(value: object) -> str:
    return value.strip().lower() if isinstance(value, str) else ""


def validly_signed_processes(
    image_loads: Iterable[ImageLoad],
    *,
    signed_values: tuple[str, ...] = ("true",),
    valid_statuses: tuple[str, ...] = ("valid",),
) -> frozenset[str]:
    if not signed_values or not valid_statuses:
        raise ValueError("signed_values and valid_statuses must be nonempty.")
    signed = frozenset(_norm(value) for value in signed_values)
    valid = frozenset(_norm(value) for value in valid_statuses)
    out: set[str] = set()
    for load in image_loads:
        guid = load.process_guid.strip() if isinstance(load.process_guid, str) else ""
        image = _norm(load.image_path)
        if not guid or not image or image != _norm(load.loaded_path):
            continue
        if _norm(load.signed) in signed and _norm(load.signature_status) in valid:
            out.add(guid)
    return frozenset(out)
