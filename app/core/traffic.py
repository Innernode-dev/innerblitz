import asyncio
import aiohttp
import logging
import time
from typing import Dict, Any, Tuple
from app.config import settings
from app.database import crud

logger = logging.getLogger("innerblitz.traffic")

class TrafficCollector:
    def __init__(self):
        self._running = False
        self._task: asyncio.Task = None
        self._last_stats = {}
        self._last_time = time.monotonic()
        self._session: aiohttp.ClientSession = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=4))
        return self._session

    async def _fetch_stats(self, endpoint: str, secret: str) -> Dict[str, Any]:
        url = f"http://127.0.0.1:{settings.HYSTERIA_TRAFFIC_STATS_PORT}{endpoint}"
        headers = {"Authorization": secret}
        try:
            session = await self._get_session()
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data if isinstance(data, dict) else {}
        except Exception:
            pass
        return {}

    async def collect_once(self) -> Tuple[float, float, int]:
        """Fetch traffic increments, update DB, and calculate current rates."""
        now = time.monotonic()
        dt = max(1.0, now - self._last_time) if self._last_time > 0 else 4.0
        self._last_time = now

        secret = await crud.get_setting("traffic_secret", "")
        traffic_data = await self._fetch_stats("/traffic?clear=1", secret)
        online_data = await self._fetch_stats("/online", secret)

        total_tx = 0
        total_rx = 0
        active_users = sum(
            1 for v in online_data.values()
            if (isinstance(v, int) and v > 0) or (isinstance(v, list) and len(v) > 0)
        ) if isinstance(online_data, dict) else 0

        if traffic_data and isinstance(traffic_data, dict):
            for username, stats in traffic_data.items():
                if isinstance(stats, dict):
                    tx = stats.get("tx", 0)
                    rx = stats.get("rx", 0)
                    total_tx += tx
                    total_rx += rx
                    if tx > 0 or rx > 0:
                        await crud.add_user_traffic(username, tx, rx)

        # Convert to KBps using actual elapsed monotonic interval
        # Server rx (receive from client) = Client upload
        # Server tx (transmit to client) = Client download
        rate_up_kbps = round((total_rx / 1024) / dt, 2)
        rate_down_kbps = round((total_tx / 1024) / dt, 2)

        # Record metric in DB for live chart
        await crud.record_traffic_metric(rate_up_kbps, rate_down_kbps, active_users)
        return rate_up_kbps, rate_down_kbps, active_users

    async def start_loop(self, interval_seconds: int = 5):
        """Background loop updating traffic every N seconds."""
        self._running = True
        self._last_time = time.monotonic()
        logger.info("Traffic collector daemon started.")
        try:
            while self._running:
                try:
                    await self.collect_once()
                except Exception as e:
                    logger.error(f"Traffic collector error: {e}")
                await asyncio.sleep(interval_seconds)
        finally:
            await self.close()

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    def stop(self):
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()

traffic_collector = TrafficCollector()
