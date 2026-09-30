"""Relay dashboard events published by any service to this replica's WebSockets."""
from __future__ import annotations

import asyncio
import logging

from sentinel_core.config import settings
from sentinel_core.modules.events import DASHBOARD_EVENTS_CHANNEL, decode_event
from server.api.websocket.manager import ws_manager

logger = logging.getLogger(__name__)


class DashboardEventRelay:
    """Subscribes to the dashboard events channel for the API process lifetime."""

    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._client = None

    async def start(self) -> None:
        if not settings.REDIS_URL or self._task is not None:
            return
        import redis.asyncio as redis_asyncio

        self._client = redis_asyncio.from_url(settings.REDIS_URL, decode_responses=True)
        self._task = asyncio.create_task(self._run(), name="dashboard-event-relay")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _run(self) -> None:
        backoff = 1.0
        while True:
            try:
                pubsub = self._client.pubsub()
                await pubsub.subscribe(DASHBOARD_EVENTS_CHANNEL)
                backoff = 1.0
                async for item in pubsub.listen():
                    if item.get("type") != "message":
                        continue
                    try:
                        message, account_id = decode_event(item["data"])
                    except (ValueError, KeyError, TypeError):
                        logger.warning("dashboard_event_malformed")
                        continue
                    await ws_manager.broadcast(message, account_id=account_id)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("dashboard_event_relay_error", extra={"error": str(exc)})
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30.0)


dashboard_event_relay = DashboardEventRelay()
