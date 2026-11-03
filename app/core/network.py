import asyncio
import ipaddress
import logging
import socket
import urllib.request
from typing import Optional

logger = logging.getLogger("innerblitz.network")

# Known fast, reliable public IPv4 discovery endpoints
IP_DISCOVERY_URLS = [
    "https://api.ipify.org",
    "https://icanhazip.com",
    "https://ifconfig.me/ip",
    "https://ip.sb",
    "https://checkip.amazonaws.com",
]

_CACHED_PUBLIC_IP: Optional[str] = None
_LAST_CHECK_TIME: float = 0.0
_CACHE_TTL_SECONDS: float = 900.0  # 15 minutes


def is_valid_public_ipv4(ip_str: Optional[str]) -> bool:
    """Validate that string is a non-private, non-loopback IPv4 address."""
    if not ip_str:
        return False
    try:
        ip = ipaddress.IPv4Address(ip_str.strip())
        return not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        )
    except (ValueError, AttributeError):
        return False


def is_local_or_unusable_host(host_str: Optional[str]) -> bool:
    """Check if host string is empty, localhost, loopback, or private LAN address."""
    if not host_str:
        return True
    clean = host_str.strip().lower()
    if clean in ("127.0.0.1", "localhost", "0.0.0.0", "::1", "", "none", "null"):
        return True
    try:
        ip = ipaddress.ip_address(clean)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        )
    except ValueError:
        # Domain name
        if clean.endswith(".local") or clean.endswith(".localhost"):
            return True
        return False


async def fetch_ip_from_url(url: str, timeout: float = 2.5) -> Optional[str]:
    """Fetch raw IP from a single discovery endpoint with short timeout."""
    loop = asyncio.get_running_loop()

    def _do():
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "curl/7.88.1"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="ignore").strip()

    try:
        res = await loop.run_in_executor(None, _do)
        if res and is_valid_public_ipv4(res):
            return res
    except Exception:
        pass
    return None


async def detect_public_ip(timeout: float = 3.0) -> Optional[str]:
    """
    Detect the public IPv4 address of this machine asynchronously.
    Executes parallel queries against reliable discovery endpoints and returns the first response.
    """
    global _CACHED_PUBLIC_IP, _LAST_CHECK_TIME

    tasks = [asyncio.create_task(fetch_ip_from_url(url, timeout=timeout)) for url in IP_DISCOVERY_URLS]
    for completed in asyncio.as_completed(tasks):
        try:
            ip = await completed
            if ip and is_valid_public_ipv4(ip):
                _CACHED_PUBLIC_IP = ip
                try:
                    _LAST_CHECK_TIME = asyncio.get_event_loop().time()
                except RuntimeError:
                    _LAST_CHECK_TIME = 0.0
                for t in tasks:
                    if not t.done():
                        t.cancel()
                return ip
        except Exception:
            continue

    # Fallback to local routing socket probe
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        s.connect(("1.1.1.1", 80))
        local_route_ip = s.getsockname()[0]
        s.close()
        if is_valid_public_ipv4(local_route_ip):
            _CACHED_PUBLIC_IP = local_route_ip
            return local_route_ip
    except Exception:
        pass

    return None


def get_cached_public_ip() -> Optional[str]:
    """Return memory-cached public IP if available."""
    return _CACHED_PUBLIC_IP


async def get_server_public_ip(force_refresh: bool = False, fallback: str = "127.0.0.1") -> str:
    """
    Retrieve server public IP:
    1. Checks DB setting 'server_ip' (if valid public IPv4 and not force_refresh).
    2. If missing/local, detects from internet endpoints and persists to DB.
    3. Falls back to fallback string if completely offline.
    """
    global _CACHED_PUBLIC_IP
    from app.database import crud

    if not force_refresh:
        try:
            db_ip = await crud.get_setting("server_ip", "")
            if db_ip and is_valid_public_ipv4(db_ip):
                _CACHED_PUBLIC_IP = db_ip
                return db_ip
        except Exception:
            pass

        if _CACHED_PUBLIC_IP and is_valid_public_ipv4(_CACHED_PUBLIC_IP):
            return _CACHED_PUBLIC_IP

    detected = await detect_public_ip()
    if detected:
        _CACHED_PUBLIC_IP = detected
        try:
            await crud.set_setting("server_ip", detected)
            logger.info(f"[Network] Detected server public IP: {detected}")
        except Exception as e:
            logger.warning(f"[Network] Failed to save detected server_ip: {e}")
        return detected

    try:
        existing = await crud.get_setting("server_ip", fallback)
        return existing or fallback
    except Exception:
        return fallback


async def sync_server_ip_on_startup() -> str:
    """
    Lifespan startup hook:
    Verifies server_ip setting in database. If empty or a local/private address,
    automatically detects the public IP and saves it to the database so all
    subscription links, Hysteria URIs, and telemetry show the real public server IP.
    """
    from app.database import crud

    try:
        current_ip = await crud.get_setting("server_ip", "")
        if is_local_or_unusable_host(current_ip):
            detected = await detect_public_ip()
            if detected:
                await crud.set_setting("server_ip", detected)
                logger.info(f"[Network] Auto-detected and stored server public IP: {detected}")

                ssl_mode = await crud.get_setting("panel_ssl_mode", "http")
                if ssl_mode == "self_signed_ip":
                    try:
                        from app.core.cert import generate_panel_cert, generate_self_signed_cert
                        sni = await crud.get_setting("sni", "")
                        generate_panel_cert(detected, valid_days=6)
                        _, _, pin = generate_self_signed_cert(detected, sni=sni)
                        if pin:
                            await crud.set_setting("cert_sha256", pin)
                        logger.info(f"[Network] Self-signed IP certificate generated for {detected}")
                    except Exception as ce:
                        logger.warning(f"[Network] IP cert generation notice: {ce}")
                return detected
        return current_ip or "127.0.0.1"
    except Exception as e:
        logger.warning(f"[Network] Startup IP sync notice: {e}")
        return "127.0.0.1"
