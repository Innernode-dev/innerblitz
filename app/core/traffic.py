import asyncio
import aiohttp
import logging
from typing import Dict, Any, Tuple
from app.config import settings
from app.database import crud

logger = logging.getLogger("innerblitz.traffic")

class TrafficCollector:
    def __init__(self):
        self._running = False
        self._task: asyncio.Task = None
        self._last_stats = {}
        self._last_time = 0

    async def _fetch_stats(self, endpoint: str) -> Dict[str, Any]:
        secret = await crud.get_setting("traffic_secret", "")
        url = f"http://127.0.0.1:{settings.HYSTERIA_TRAFFIC_STATS_PORT}{endpoint}"
        headers = {"Authorization": secret}
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=4)) as session:
                async with session.get(url, headers=headers) as resp:
                    if resp.status == 200:
                        return await resp.json()
        except Exception:
            pass
        return {}

    async def collect_once(self) -> Tuple[float, float, int]:
        """Fetch traffic increments, update DB, and calculate current rates."""
        traffic_data = await self._fetch_stats("/traffic?clear=1")
        online_data = await self._fetch_stats("/online")

        total_tx = 0
        total_rx = 0
        active_users = len(online_data) if isinstance(online_data, dict) else 0

        if traffic_data and isinstance(traffic_data, dict):
            for username, stats in traffic_data.items():
                if isinstance(stats, dict):
                    tx = stats.get("tx", 0)
                    rx = stats.get("rx", 0)
                    total_tx += tx
                    total_rx += rx
                    if tx > 0 or rx > 0:
                        await crud.add_user_traffic(username, tx, rx)

        # Convert to KBps (assuming ~5 sec interval)
        rate_up_kbps = round((total_tx / 1024) / 5, 2)
        rate_down_kbps = round((total_rx / 1024) / 5, 2)

        # Record metric in DB for live chart
        await crud.record_traffic_metric(rate_up_kbps, rate_down_kbps, active_users)
        return rate_up_kbps, rate_down_kbps, active_users

    async def start_loop(self, interval_seconds: int = 5):
        """Background loop updating traffic every N seconds."""
        self._running = True
        logger.info("Traffic collector daemon started.")
        while self._running:
            try:
                await self.collect_once()
            except Exception as e:
                logger.error(f"Traffic collector error: {e}")
            await asyncio.sleep(interval_seconds)

    def stop(self):
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()

traffic_collector = TrafficCollector()
