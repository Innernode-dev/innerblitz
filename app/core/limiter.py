import asyncio
import aiohttp
import logging
from typing import List, Dict, Any
from app.config import settings
from app.database import crud

logger = logging.getLogger("innerblitz.limiter")

async def kick_users_api(usernames: List[str]) -> bool:
    """Send kick request to Hysteria 2 API for specified usernames."""
    if not usernames:
        return True
    secret = await crud.get_setting("traffic_secret", "")
    url = f"http://127.0.0.1:{settings.HYSTERIA_TRAFFIC_STATS_PORT}/kick"
    headers = {"Authorization": secret, "Content-Type": "application/json"}
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=4)) as session:
            async with session.post(url, json=usernames, headers=headers) as resp:
                return resp.status == 200
    except Exception as e:
        logger.error(f"Failed to kick users {usernames}: {e}")
        return False

class LimiterDaemon:
    def __init__(self):
        self._running = False
        self._task: asyncio.Task = None

    async def check_and_enforce(self):
        """Check all users for quota, expiration, and IP limits, kicking offenders."""
        users = await crud.get_all_users()
        to_kick = []

        # 1. Quota & expiration enforcement
        for u in users:
            if u.get("unlimited_user", False):
                continue
            if u.get("blocked", False) or u.get("is_expired", False) or u.get("is_limit_reached", False):
                to_kick.append(u["username"])

        # 2. Online IP limit enforcement
        secret = await crud.get_setting("traffic_secret", "")
        online_url = f"http://127.0.0.1:{settings.HYSTERIA_TRAFFIC_STATS_PORT}/online"
        headers = {"Authorization": secret}
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=4)) as session:
                async with session.get(online_url, headers=headers) as resp:
                    if resp.status == 200:
                        online_data = await resp.json()
                        if isinstance(online_data, dict):
                            for u in users:
                                if u.get("unlimited_user", False):
                                    continue
                                max_ips = u.get("max_ips", 0)
                                if max_ips > 0:
                                    conns = online_data.get(u["username"], [])
                                    # conns can be list of remote addresses
                                    if isinstance(conns, list):
                                        unique_ips = {addr.split(":")[0] for addr in conns if ":" in addr}
                                        if len(unique_ips) > max_ips:
                                            logger.warning(f"User {u['username']} exceeded IP limit ({len(unique_ips)} > {max_ips}). Kicking.")
                                            to_kick.append(u["username"])
        except Exception:
            pass

        if to_kick:
            unique_kicks = list(set(to_kick))
            logger.info(f"Limiter kicking {len(unique_kicks)} users: {unique_kicks}")
            await kick_users_api(unique_kicks)

    async def start_loop(self, interval_seconds: int = 15):
        self._running = True
        logger.info("Quota & IP limiter daemon started.")
        while self._running:
            try:
                await self.check_and_enforce()
            except Exception as e:
                logger.error(f"Limiter loop error: {e}")
            await asyncio.sleep(interval_seconds)

    def stop(self):
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()

limiter_daemon = LimiterDaemon()
