"""Backend-neutral descriptive runtime context construction (C7)."""

from .builder import ContextBuilder
from .models import ContextEvent, LineageContext
from .resolver import (
    ContextResolver,
    PipeEvidence,
    RemoteThreadEvidence,
    ResolvedContext,
)

__all__ = [
    "ContextBuilder",
    "ContextEvent",
    "LineageContext",
    "ContextResolver",
    "ResolvedContext",
    "PipeEvidence",
    "RemoteThreadEvidence",
]
