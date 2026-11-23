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

def _extract_remote_ip(addr: str) -> str:
    """Extract IPv4 or IPv6 host cleanly from 'ip:port' or '[ipv6]:port'."""
    s = str(addr or "").strip()
    if s.startswith("[") and "]" in s:
        return s[1 : s.index("]")]
    if ":" in s:
        return s.rsplit(":", 1)[0]
    return s


def _count_online_devices(conns: Any) -> int:
    """
    Parse Hysteria 2 /online entry:
    - Real Hysteria 2 API returns an integer count of active client connections/devices.
    - Also supports list of remote 'ip:port' strings (including IPv6).
    """
    if isinstance(conns, bool):
        return int(conns)
    if isinstance(conns, int):
        return max(0, conns)
    if isinstance(conns, list):
        unique_ips = {_extract_remote_ip(addr) for addr in conns if addr}
        return len(unique_ips)
    return 0


class LimiterDaemon:
    def __init__(self):
        self._running = False
        self._task: asyncio.Task = None

    async def check_and_enforce(self):
        """Check all users for quota, expiration, and IP/device limits, kicking offenders."""
        users = await crud.get_all_users()
        candidates_to_kick = []

        # 1. Quota & expiration enforcement
        for u in users:
            is_disabled = u.get("blocked", False) or not u.get("enable", True)
            if is_disabled:
                candidates_to_kick.append(u["username"])
                continue
            if u.get("unlimited_user", False):
                continue
            if u.get("is_expired", False) or u.get("is_limit_reached", False) or u.get("is_quota_exceeded", False):
                candidates_to_kick.append(u["username"])

        # 2. Fetch live /online map from Hysteria 2 core for device/IP limits and filtering
        online_data = None
        secret = await crud.get_setting("traffic_secret", "")
        online_url = f"http://127.0.0.1:{settings.HYSTERIA_TRAFFIC_STATS_PORT}/online"
        headers = {"Authorization": secret}
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=4)) as session:
                async with session.get(online_url, headers=headers) as resp:
                    if resp.status == 200:
                        parsed = await resp.json()
                        if isinstance(parsed, dict):
                            online_data = parsed
        except Exception:
            pass

        to_kick = []
        if online_data is not None:
            # Only kick disabled/expired/over-quota users that are actually connected right now
            for uname in candidates_to_kick:
                if _count_online_devices(online_data.get(uname, 0)) > 0:
                    to_kick.append(uname)

            # Enforce max_ips / simultaneous device limit (works with both int and list formats)
            for u in users:
                if u.get("unlimited_user", False):
                    continue
                max_ips = u.get("max_ips", 0) or 0
                if max_ips > 0:
                    active_count = _count_online_devices(online_data.get(u["username"], 0))
                    if active_count > max_ips:
                        logger.warning(f"User {u['username']} exceeded IP/device limit ({active_count} > {max_ips}). Kicking.")
                        to_kick.append(u["username"])
        else:
            # Fallback when /online is unreachable: attempt kick for all unauthorized accounts
            to_kick = candidates_to_kick

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
