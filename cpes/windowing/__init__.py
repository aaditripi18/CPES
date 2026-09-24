"""Backend-neutral deterministic detection-window management (C8)."""

from .manager import WindowManager
from .models import DetectionWindow, EventGroup, SlidingWindowParameters

__all__ = ["DetectionWindow", "EventGroup", "SlidingWindowParameters", "WindowManager"]
