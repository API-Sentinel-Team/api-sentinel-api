"""
WebSocket event types for the API Security Engine dashboard.
Ensures consistency between Backend push and Frontend consumption.

The enum lives in ``sentinel_core.modules.events`` so non-API services can publish the
same event types; this alias keeps API-side imports stable.
"""

from sentinel_core.modules.events import EventType as WSEventType

__all__ = ["WSEventType"]
