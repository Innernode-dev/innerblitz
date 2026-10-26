"""
InnerBlitz WARP Core Module
Handles active WireGuard/SOCKS5 detection, connection adoption,
dual-path Cloudflare trace diagnostics, and automated lifecycle management.
"""

import asyncio
import collections
import datetime
import logging
import os
import shutil
import socket
import subprocess
import time
from enum import Enum
from pathlib import Path
from typing import Deque, Dict, List, Optional, Tuple, Any

import psutil
from app.config import settings
from app.database import crud

logger = logging.getLogger("innerblitz.warp")

WARP_CACHE_TTL = 15.0  # seconds
_detection_cache: Dict[str, Any] = {"timestamp": 0.0, "data": None}


class WarpMode(str, Enum):
    NONE = "none"
    WIREGUARD = "wireguard"
    SOCKS5 = "socks5"


class WarpStatusLevel(str, Enum):
    ACTIVE = "active"      # Egress confirmed working, warp=on/plus
    STANDBY = "standby"    # Interface or socket is up, but trace is unreachable or off
    OFFLINE = "offline"    # No interface or socket detected


class WarpInstallStatus(str, Enum):
    IDLE = "idle"
    INSTALLING = "installing"
    SUCCESS = "success"
    FAILED = "failed"


def parse_cloudflare_trace(text: str) -> Dict[str, str]:
    """
    Parses cloudflare.com/cdn-cgi/trace plaintext key-value format.
    Guards against HTML challenge pages, HTTP error payloads, and malformed output.
    """
    text_lower = text.lower() if text else ""
    if (
        not text
        or "<!doctype" in text_lower
        or "<html" in text_lower
        or "<head" in text_lower
        or "<body" in text_lower
        or "<title" in text_lower
    ):
        raise ValueError("Invalid trace response: received HTML instead of plaintext")

    result: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        k, v = line.split("=", 1)
        result[k.strip()] = v.strip()
    return result


async def check_socks5_alive(
    host: str = "127.0.0.1", port: int = 40000, timeout: float = 1.5
) -> Tuple[bool, Optional[float]]:
    """
    Executes a non-blocking RFC 1928 Method Negotiation handshake.
    Sends b'\\x05\\x01\\x00' (VER=5, NMETHODS=1, METHOD=0 No Auth).
    Expects b'\\x05\\x00' (VER=5, METHOD=0 Accepted).
    Returns (is_alive: bool, latency_ms: Optional[float]).
    """
    start = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        try:
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            resp = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
            latency_ms = (time.perf_counter() - start) * 1000.0
            if len(resp) == 2 and resp[0] == 0x05 and resp[1] == 0x00:
                return True, round(latency_ms, 2)
            return False, None
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
        return False, None


def check_wireguard_interface(candidate_names: Optional[List[str]] = None) -> Optional[str]:
    """
    Detects if any active WireGuard WARP interface is present and administratively UP.
    Checks psutil, Linux /sys/class/net, and ip link.
    """
    if candidate_names is None:
        candidate_names = ["warp", "wgcf", "warp0", "wg-warp"]

    # 1. psutil in-process network interface check
    try:
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        for iface in candidate_names:
            if iface in stats:
                if stats[iface].isup:
                    return iface
            elif iface in addrs and addrs[iface]:
                return iface
    except Exception:
        pass

    # 2. Linux sysfs check (/sys/class/net/<iface>)
    for iface in candidate_names:
        sys_path = Path(f"/sys/class/net/{iface}")
        if sys_path.exists():
            try:
                oper = (sys_path / "operstate").read_text(encoding="utf-8").strip().lower()
                flags = int((sys_path / "flags").read_text(encoding="utf-8").strip(), 0)
                if oper in ("up", "unknown") and (flags & 1):  # IFF_UP = 0x1
                    return iface
            except Exception:
                pass  # Do not return down or unreadable interface as UP

    # 3. ip link command check (if iproute2 is available)
    ip_bin = shutil.which("ip")
    if ip_bin:
        for iface in candidate_names:
            try:
                res = subprocess.run(
                    [ip_bin, "link", "show", iface],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                if res.returncode == 0 and ("UP" in res.stdout or "state UP" in res.stdout or "UNKNOWN" in res.stdout):
                    return iface
            except Exception:
                pass

    return None


async def query_cloudflare_trace(
    proxy_url: Optional[str] = None,
    interface: Optional[str] = None,
    timeout: float = 4.0
) -> Dict[str, Any]:
    """
    Queries Cloudflare trace with automatic fallback to https://1.1.1.1/cdn-cgi/trace.
    Supports SOCKS5 proxy (via aiohttp-socks or curl) and network interface binding.
    """
    urls = [
        "https://cloudflare.com/cdn-cgi/trace",
        "https://1.1.1.1/cdn-cgi/trace"
    ]

    for url in urls:
        start = time.perf_counter()
        try:
            # 1. Proxied request via SOCKS5
            if proxy_url:
                text = None
                try:
                    import aiohttp
                    from aiohttp_socks import ProxyConnector
                    connector = ProxyConnector.from_url(proxy_url)
                    async with aiohttp.ClientSession(connector=connector) as session:
                        async with session.get(
                            url,
                            timeout=aiohttp.ClientTimeout(total=timeout),
                            headers={"User-Agent": "InnerBlitz/2.0"}
                        ) as resp:
                            if resp.status == 200:
                                text = await resp.text()
                except Exception as ex:
                    logger.debug(f"aiohttp-socks attempt failed ({ex}), trying curl fallback")

                if text is None:
                    # Fallback to curl if available
                    curl_bin = shutil.which("curl") or shutil.which("curl.exe")
                    if curl_bin:
                        proxy_arg = proxy_url.replace("socks5://", "socks5h://")
                        cmd = [curl_bin, "-s4", "-m", str(int(timeout)), "-x", proxy_arg, url]
                        try:
                            proc = await asyncio.create_subprocess_exec(
                                *cmd,
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.PIPE
                            )
                            out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 1.0)
                            if proc.returncode == 0 and out:
                                text = out.decode("utf-8", errors="replace")
                        except Exception as e:
                            logger.debug(f"curl proxy fallback failed: {e}")

                if text:
                    parsed = parse_cloudflare_trace(text)
                    parsed["latency_ms"] = round((time.perf_counter() - start) * 1000.0, 2)
                    parsed["reachable"] = True
                    return parsed

            # 2. Bound interface request (for WireGuard interface)
            elif interface:
                curl_bin = shutil.which("curl") or shutil.which("curl.exe")
                if curl_bin:
                    cmd = [curl_bin, "-s4", "-m", str(int(timeout)), "--interface", interface, url]
                    try:
                        proc = await asyncio.create_subprocess_exec(
                            *cmd,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 1.0)
                        if proc.returncode == 0 and out:
                            parsed = parse_cloudflare_trace(out.decode("utf-8", errors="replace"))
                            parsed["latency_ms"] = round((time.perf_counter() - start) * 1000.0, 2)
                            parsed["reachable"] = True
                            return parsed
                    except Exception as e:
                        logger.debug(f"curl interface probe failed: {e}")

            # 3. Direct request (Direct server egress)
            else:
                text = None
                try:
                    import aiohttp
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            url,
                            timeout=aiohttp.ClientTimeout(total=timeout),
                            headers={"User-Agent": "InnerBlitz/2.0"}
                        ) as resp:
                            if resp.status == 200:
                                text = await resp.text()
                except Exception as ex:
                    logger.debug(f"aiohttp direct trace query failed ({ex}), trying urllib fallback")

                if text is None:
                    # Fallback to urllib in worker thread
                    import urllib.request
                    loop = asyncio.get_running_loop()

                    def _fetch(u: str) -> str:
                        req = urllib.request.Request(u, headers={"User-Agent": "InnerBlitz/2.0"})
                        with urllib.request.urlopen(req, timeout=timeout) as resp:
                            return resp.read().decode("utf-8", errors="replace")

                    try:
                        text = await loop.run_in_executor(None, _fetch, url)
                    except Exception as ex:
                        logger.debug(f"urllib direct query failed: {ex}")

                if text:
                    parsed = parse_cloudflare_trace(text)
                    parsed["latency_ms"] = round((time.perf_counter() - start) * 1000.0, 2)
                    parsed["reachable"] = True
                    return parsed

        except Exception as e:
            logger.debug(f"Trace query to {url} encountered exception: {e}")
            continue

    return {
        "reachable": False,
        "ip": None,
        "warp": "off",
        "colo": None,
        "loc": None,
        "latency_ms": None,
        "error": "Cloudflare trace endpoint unreachable"
    }


async def detect_warp(force_refresh: bool = False, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Main detection entrypoint.
    Checks WireGuard interfaces and SOCKS5 socket (127.0.0.1:40000).
    Prioritizes native WireGuard interface over local SOCKS5 if both are active.
    Returns standard interface contract dict.
    """
    now = time.time()
    if not force_refresh and _detection_cache["data"] and (now - _detection_cache["timestamp"] < WARP_CACHE_TTL):
        return _detection_cache["data"]

    # 1. Determine target port from DB settings or default 40000
    configured_port = 40000
    try:
        p_val = await crud.get_setting("warp_port", "40000")
        if p_val and p_val.isdigit():
            configured_port = int(p_val)
    except Exception:
        pass

    # 2. Check WireGuard network interface first (priority resolution)
    wg_iface = check_wireguard_interface()

    # 3. Check SOCKS5 socket
    socks5_ok, socks5_latency = await check_socks5_alive("127.0.0.1", configured_port, timeout=1.5)

    mode = WarpMode.NONE
    interface = None
    socks5_addr = None
    latency_ms = None

    if wg_iface:
        mode = WarpMode.WIREGUARD
        interface = wg_iface
    elif socks5_ok:
        mode = WarpMode.SOCKS5
        socks5_addr = f"127.0.0.1:{configured_port}"
        latency_ms = socks5_latency

    active = (mode != WarpMode.NONE)
    external_ip = None
    warp_status = "off"
    colo = None
    status_level = WarpStatusLevel.OFFLINE

    if active:
        # Run live trace diagnostics through the detected WARP path
        proxy_url = f"socks5://127.0.0.1:{configured_port}" if mode == WarpMode.SOCKS5 else None
        iface_target = interface if mode == WarpMode.WIREGUARD else None

        diag = await query_cloudflare_trace(proxy_url=proxy_url, interface=iface_target, timeout=timeout)
        if diag.get("reachable"):
            external_ip = diag.get("ip")
            raw_warp = diag.get("warp", "off")
            warp_status = raw_warp if raw_warp in ("on", "plus") else "off"
            latency_ms = diag.get("latency_ms") or latency_ms
            colo = diag.get("colo")
            status_level = (
                WarpStatusLevel.ACTIVE
                if warp_status in ("on", "plus")
                else WarpStatusLevel.STANDBY
            )
        else:
            status_level = WarpStatusLevel.STANDBY

    result = {
        "active": active,
        "mode": mode.value,
        "interface": interface,
        "socks5_addr": socks5_addr,
        "external_ip": external_ip,
        "warp_status": warp_status,
        "status_level": status_level.value,
        "latency_ms": latency_ms,
        "colo": colo,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

    _detection_cache["timestamp"] = now
    _detection_cache["data"] = result
    return result


async def query_warp_diagnostics(timeout: float = 5.0) -> Dict[str, Any]:
    """
    Executes concurrent dual-path diagnostics:
    Path A: Direct VPS Server Egress (raw internet connection).
    Path B: WARP Egress (via SOCKS5 proxy or WireGuard interface).
    Computes comparative metrics, IP masking confirmation, and latency overhead.
    """
    status_info = await detect_warp(force_refresh=True, timeout=timeout)

    proxy_url = status_info.get("socks5_addr")
    if proxy_url:
        proxy_url = f"socks5://{proxy_url}"
    interface = status_info.get("interface")

    # Run direct trace and WARP trace in parallel
    direct_task = asyncio.create_task(query_cloudflare_trace(proxy_url=None, interface=None, timeout=timeout))

    if status_info["active"]:
        warp_task = asyncio.create_task(query_cloudflare_trace(proxy_url=proxy_url, interface=interface, timeout=timeout))
        direct_diag, warp_diag = await asyncio.gather(direct_task, warp_task, return_exceptions=True)
    else:
        direct_diag = await direct_task
        warp_diag = {
            "reachable": False,
            "ip": None,
            "warp": "off",
            "colo": None,
            "loc": None,
            "latency_ms": None,
            "error": "WARP daemon/interface not running"
        }

    if isinstance(direct_diag, Exception):
        direct_diag = {"reachable": False, "error": str(direct_diag)}
    if isinstance(warp_diag, Exception):
        warp_diag = {"reachable": False, "error": str(warp_diag)}

    # Calculate summary metrics
    direct_ip = direct_diag.get("ip")
    warp_ip = warp_diag.get("ip")
    ip_masked = bool(direct_ip and warp_ip and direct_ip != warp_ip)

    latency_delta = None
    if direct_diag.get("latency_ms") is not None and warp_diag.get("latency_ms") is not None:
        latency_delta = round(warp_diag["latency_ms"] - direct_diag["latency_ms"], 2)

    return {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "warp_active": status_info["active"],
        "mode": status_info["mode"],
        "status_level": status_info["status_level"],
        "direct": direct_diag,
        "warp": warp_diag,
        "summary": {
            "ip_masked": ip_masked,
            "direct_ip": direct_ip,
            "warp_ip": warp_ip,
            "latency_delta_ms": latency_delta,
            "warp_status": warp_diag.get("warp", "off"),
            "colo": warp_diag.get("colo"),
            "loc": warp_diag.get("loc")
        }
    }


async def sync_warp_settings_from_detection(warp_info: dict) -> bool:
    """
    Adopts an active pre-existing WARP connection into SQLite settings.
    Ensures Hysteria 2 routing can reuse the connection without duplicate daemons.
    """
    if not warp_info.get("active"):
        return False

    updates = {
        "warp_mode": warp_info["mode"],
        "warp_detected": "1"
    }
    if warp_info.get("socks5_addr"):
        port = warp_info["socks5_addr"].split(":")[-1]
        updates["warp_port"] = port
    if warp_info.get("interface"):
        updates["warp_interface"] = warp_info["interface"]

    await crud.set_settings(updates)
    logger.info(f"[WARP Reuse] Successfully synced detected WARP settings: {updates}")
    return True


class WarpProcessManager:
    """
    Manages non-blocking bare-metal installation of Cloudflare WARP.
    Maintains in-memory ring buffer of logs and thread-safe execution status.
    """
    def __init__(self, max_log_lines: int = 2000):
        self.status: WarpInstallStatus = WarpInstallStatus.IDLE
        self.start_time: Optional[str] = None
        self.end_time: Optional[str] = None
        self.exit_code: Optional[int] = None
        self.error_message: Optional[str] = None
        self.mode: str = "auto"
        self.port: int = 40000
        self.clean: bool = False
        self._logs: Deque[str] = collections.deque(maxlen=max_log_lines)
        self._total_lines_produced: int = 0
        self._lock = asyncio.Lock()
        self._process: Optional[asyncio.subprocess.Process] = None
        self._task: Optional[asyncio.Task] = None

    def is_installing(self) -> bool:
        return self.status == WarpInstallStatus.INSTALLING

    async def start_install(self, mode: str = "auto", port: int = 40000, clean: bool = False) -> Tuple[bool, str]:
        """Initiate background installation task. Non-blocking."""
        async with self._lock:
            if self.is_installing() or (self._task is not None and not self._task.done()):
                return False, "Installation is already in progress or cleaning up."

            if mode not in ("auto", "socks5", "wgcf"):
                return False, f"Invalid mode '{mode}'. Choose 'auto', 'socks5', or 'wgcf'."
            if not (1024 <= port <= 65535):
                return False, f"Invalid port {port}. Must be between 1024 and 65535."

            # Reset state for fresh installation run
            self.status = WarpInstallStatus.INSTALLING
            self.start_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
            self.end_time = None
            self.exit_code = None
            self.error_message = None
            self.mode = mode
            self.port = port
            self.clean = clean
            self._logs.clear()
            self._total_lines_produced = 0
            self._append_log(f"[{self.start_time}] [INFO] Starting WARP 1-click installation (mode={mode}, port={port}, clean={clean})...")

            # Spawn background coroutine
            self._task = asyncio.create_task(self._run_installer_coroutine(mode, port, clean))
            return True, "Installation started in background."

    async def _run_installer_coroutine(self, mode: str, port: int, clean: bool = False):
        """Asynchronously executes scripts/install_warp.sh and streams stdout/stderr."""
        # Locate install_warp.sh script
        script_path = Path("/etc/hysteria/scripts/install_warp.sh")
        if not script_path.exists():
            # Fallback to local project repository directory
            script_path = Path(__file__).resolve().parent.parent.parent / "scripts" / "install_warp.sh"

        if not script_path.exists():
            self._append_log(f"[ERROR] Installer script not found at {script_path}")
            self._finish_failed("Installer script not found on disk.")
            return

        # Check for bash interpreter
        bash_bin = shutil.which("bash") or shutil.which("/bin/bash")
        if not bash_bin:
            # Fallback check for Windows Git Bash or WSL
            if os.name == "nt":
                bash_bin = shutil.which("bash.exe")

        if not bash_bin:
            self._append_log("[ERROR] Bash interpreter not found in system PATH. Cannot execute shell installer.")
            self._finish_failed("Bash interpreter not found on system.")
            return

        # Ensure executable permission on Linux/macOS
        try:
            os.chmod(script_path, 0o755)
        except Exception:
            pass

        cmd = [bash_bin, str(script_path), f"--mode={mode}", f"--port={port}"]
        if clean:
            cmd.append("--clean")
        env = os.environ.copy()
        env["DEBIAN_FRONTEND"] = "noninteractive"
        env["PYTHONUNBUFFERED"] = "1"

        try:
            self._process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,  # Sequential chronological merge
                env=env
            )

            # Stream output line by line with combined 300s timeout guard
            async def _stream_and_wait():
                while True:
                    line_bytes = await self._process.stdout.readline()
                    if not line_bytes:
                        break
                    line_str = line_bytes.decode("utf-8", errors="replace").rstrip("\r\n")
                    self._append_log(line_str)
                return await self._process.wait()

            exit_code = await asyncio.wait_for(_stream_and_wait(), timeout=300.0)
            self.exit_code = exit_code
            self.end_time = datetime.datetime.now(datetime.timezone.utc).isoformat()

            if exit_code == 0:
                self.status = WarpInstallStatus.SUCCESS
                self._append_log("[SUCCESS] Installation completed successfully.")
                await self._on_install_success(mode, port)
            else:
                self.status = WarpInstallStatus.FAILED
                if not self.error_message:
                    self.error_message = f"Installer exited with non-zero status code: {exit_code}"
                self._append_log(f"[ERROR] {self.error_message}")

        except asyncio.CancelledError:
            self._append_log("[WARN] Installation coroutine cancelled.")
            self._kill_process()
            if not self.error_message:
                self._finish_failed("Installation aborted by administrator.")
        except asyncio.TimeoutError:
            self._append_log("[ERROR] Installation timed out after 300 seconds. Terminating process...")
            self._kill_process()
            self._finish_failed("Installation process timed out after 300 seconds.")
        except Exception as e:
            logger.exception("Unexpected error during WARP installation")
            self._append_log(f"[ERROR] Internal execution exception: {e}")
            self._finish_failed(str(e))
        finally:
            curr = asyncio.current_task()
            if self._task is curr:
                self._process = None
                self._task = None

    def _append_log(self, message: str):
        if len(self._logs) == 0 and self._total_lines_produced > 0:
            self._total_lines_produced = 0
        self._logs.append(message)
        self._total_lines_produced += 1
        logger.info(f"[WARP Install] {message}")

    def _finish_failed(self, error: str):
        self.status = WarpInstallStatus.FAILED
        self.error_message = error
        self.end_time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    def _kill_process(self):
        if self._process:
            try:
                self._process.kill()
            except Exception:
                pass

    async def _on_install_success(self, mode: str, port: int):
        """Auto-configure settings and reload Hysteria 2 configuration."""
        try:
            await crud.set_settings({
                "warp_enabled": "1",
                "warp_mode": "socks5" if mode in ("auto", "socks5") else "wireguard",
                "warp_port": str(port),
                "warp_install_status": "success",
                "warp_last_installed": self.end_time or ""
            })
            from app.core.hysteria import apply_and_save_config, restart_hysteria
            await apply_and_save_config()
            restart_hysteria()
            self._append_log("[SUCCESS] Hysteria 2 configuration updated and service restarted with WARP outbound.")
        except Exception as e:
            self._append_log(f"[WARN] Failed to automatically apply Hysteria config: {e}")

    def get_logs(self, offset: int = 0, limit: int = 200) -> Dict[str, Any]:
        """Returns paginated/incremental log lines from memory buffer."""
        total = self._total_lines_produced
        window_start = max(0, total - len(self._logs))
        req_offset = min(max(offset, window_start), total)
        idx_in_deque = max(0, min(req_offset - window_start, len(self._logs)))
        sliced = list(self._logs)[idx_in_deque : idx_in_deque + limit]
        next_offset = min(req_offset + len(sliced), total)

        return {
            "status": self.status.value,
            "exit_code": self.exit_code,
            "error_message": self.error_message,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "total_lines": total,
            "offset": req_offset,
            "next_offset": next_offset,
            "has_more": next_offset < total,
            "logs": sliced
        }

    async def cancel_install(self) -> Tuple[bool, str]:
        """Aborts active installation if running."""
        async with self._lock:
            if not self.is_installing() and (self._task is None or self._task.done()):
                return False, "No installation currently in progress."
            self._append_log("[WARN] Abort requested by user.")
            self._kill_process()
            self._finish_failed("Installation aborted by administrator.")
            if self._task and not self._task.done():
                self._task.cancel()
            return True, "Installation cancelled."


warp_installer = WarpProcessManager()


async def run_warp_installer(mode: str = "auto", port: int = 40000, clean: bool = False) -> Tuple[bool, str]:
    """
    Executes automated installation on bare metal.
    Contract from PROJECT.md: Returns (success: bool, log_output: str).
    """
    ok, msg = await warp_installer.start_install(mode=mode, port=port, clean=clean)
    if not ok and not warp_installer.is_installing():
        return False, msg

    if warp_installer._task:
        try:
            await asyncio.wait_for(asyncio.shield(warp_installer._task), timeout=310.0)
        except Exception:
            pass

    logs = "\n".join(warp_installer._logs)
    success = (warp_installer.status == WarpInstallStatus.SUCCESS)
    return success, logs


# ==================== SYSTEMD SERVICE MANAGEMENT ====================

def get_warp_service_name() -> Optional[str]:
    """Identify which WARP systemd service unit is active."""
    from app.core.hysteria import run_systemctl
    for svc in ("warp-svc.service", "wg-quick@warp.service"):
        ok, out = run_systemctl("is-active", svc)
        if ok and "active" in out:
            return svc
    return None


def restart_warp_service() -> Tuple[bool, str]:
    """Restart detected WARP systemd unit safely."""
    from app.core.hysteria import run_systemctl
    svc = get_warp_service_name() or "warp-svc.service"
    return run_systemctl("restart", svc)


def repair_warp_service() -> Dict[str, Any]:
    """
    Automated self-healing diagnostics and recovery for WARP:
    1. Checks if warp-svc or wg-quick@warp is running.
    2. Runs systemctl daemon-reload and service restart.
    3. Verifies warp-cli registration and reconnects if in disconnected state.
    4. Gathers journalctl snippet on failure.
    """
    from app.core.hysteria import run_systemctl
    actions_taken: List[str] = []
    service = get_warp_service_name() or "warp-svc.service"

    # Step 1: Daemon reload
    try:
        res = subprocess.run(["systemctl", "daemon-reload"], capture_output=True, text=True, timeout=10)
        if res.returncode == 0:
            actions_taken.append("Executed systemctl daemon-reload")
        else:
            actions_taken.append(f"systemctl daemon-reload exited code {res.returncode}")
    except Exception as e:
        actions_taken.append(f"daemon-reload notice: {e}")

    # Step 2: Restart service
    ok, restart_out = run_systemctl("restart", service)
    actions_taken.append(f"Restarted {service}: success={ok}")

    # Step 3: Check warp-cli status if official client
    if service == "warp-svc.service":
        warp_cli = shutil.which("warp-cli")
        if warp_cli:
            try:
                status_res = subprocess.run(
                    [warp_cli, "--accept-tos", "status"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if "Disconnected" in status_res.stdout:
                    subprocess.run([warp_cli, "--accept-tos", "connect"], capture_output=True, timeout=5)
                    actions_taken.append("Reconnected warp-cli")
                elif "Registration Missing" in status_res.stdout:
                    subprocess.run(
                        [warp_cli, "--accept-tos", "registration", "new"],
                        capture_output=True,
                        timeout=5
                    )
                    actions_taken.append("Registered new warp-cli account")
            except Exception as e:
                actions_taken.append(f"warp-cli status check notice: {e}")

    # Step 4: Verify active status
    is_active_ok, is_active_out = run_systemctl("is-active", service)
    success = is_active_ok and "active" in is_active_out

    journal_snippet = None
    if not success:
        try:
            j_res = subprocess.run(
                ["journalctl", "-u", service, "-n", "30", "--no-pager"],
                capture_output=True,
                text=True,
                timeout=5
            )
            journal_snippet = j_res.stdout
        except Exception:
            pass

    return {
        "success": success,
        "service": service,
        "status": "active" if success else "failed",
        "actions_taken": actions_taken,
        "journal_snippet": journal_snippet
    }
