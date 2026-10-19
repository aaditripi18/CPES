"""Backend-neutral deterministic detection-window management (C8)."""

from .evidence import EvidenceWindowAttacher
from .manager import WindowManager
from .models import DetectionWindow, EventGroup, SlidingWindowParameters

__all__ = ["DetectionWindow", "EvidenceWindowAttacher", "EventGroup", "SlidingWindowParameters", "WindowManager"]
