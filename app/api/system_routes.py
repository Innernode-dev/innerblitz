from fastapi import APIRouter, Depends
from pydantic import BaseModel
import psutil
import time
from datetime import datetime, timedelta

from app.api.auth_routes import get_current_admin
from app.database import crud
from app.core.hysteria import (
    is_hysteria_running, get_hysteria_version, get_hysteria_logs,
    clear_service_logs, configure_service_logging
)
from app.core.warp import detect_warp
from app.api.client_routes import _fetch_online_data

router = APIRouter(prefix="/api/system", dependencies=[Depends(get_current_admin)])

def _format_bytes(bytes_val: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024
    return f"{bytes_val:.1f} PB"

@router.get("/stats")
async def get_system_stats():
    """Real-time system telemetry and Hysteria status."""
    # CPU
    cpu_percent = psutil.cpu_percent(interval=None)

    # Memory
    vm = psutil.virtual_memory()
    mem_used = round((vm.total - vm.available) / (1024 ** 3), 2)
    mem_total = round(vm.total / (1024 ** 3), 2)
    mem_percent = vm.percent

    # Disk
    try:
        disk = psutil.disk_usage("/")
        disk_used = round(disk.used / (1024 ** 3), 2)
        disk_total = round(disk.total / (1024 ** 3), 2)
        disk_percent = disk.percent
    except Exception:
        disk_used, disk_total, disk_percent = 0, 0, 0

    # Uptime
    boot_time = datetime.fromtimestamp(psutil.boot_time())
    uptime_delta = datetime.now() - boot_time
    days = uptime_delta.days
    hours, remainder = divmod(uptime_delta.seconds, 3600)
    minutes, _ = divmod(remainder, 60)
    uptime_str = f"{days}d {hours}h {minutes}m"

    # Users counts
    all_users = await crud.get_all_users()
    total_users = len(all_users)
    active_users = sum(1 for u in all_users if not u.get("blocked") and not u.get("is_expired") and not u.get("is_limit_reached"))

    # Recent traffic speed points
    history = await crud.get_traffic_history(limit=25)

    return {
        "cpu_percent": cpu_percent,
        "mem_percent": mem_percent,
        "mem_used_gb": mem_used,
        "mem_total_gb": mem_total,
        "disk_percent": disk_percent,
        "disk_used_gb": disk_used,
        "disk_total_gb": disk_total,
        "uptime": uptime_str,
        "hysteria_running": is_hysteria_running(),
        "hysteria_version": get_hysteria_version(),
        "total_users": total_users,
        "active_users": active_users,
        "traffic_history": history
    }

@router.get("/dashboard")
async def get_dashboard_telemetry():
    """Consolidated single-request dashboard telemetry (server, clients, bandwidth, gateway)."""
    # 1. System / Server metrics
    cpu_percent = psutil.cpu_percent(interval=None)
    vm = psutil.virtual_memory()
    mem_used = round((vm.total - vm.available) / (1024 ** 3), 2)
    mem_total = round(vm.total / (1024 ** 3), 2)
    mem_percent = vm.percent

    try:
        disk = psutil.disk_usage("/")
        disk_used = round(disk.used / (1024 ** 3), 2)
        disk_total = round(disk.total / (1024 ** 3), 2)
        disk_percent = disk.percent
    except Exception:
        disk_used, disk_total, disk_percent = 0, 0, 0

    boot_time = datetime.fromtimestamp(psutil.boot_time())
    uptime_delta = datetime.now() - boot_time
    days = uptime_delta.days
    hours, remainder = divmod(uptime_delta.seconds, 3600)
    minutes, _ = divmod(remainder, 60)
    uptime_str = f"{days}d {hours}h {minutes}m"

    # 2. Bandwidth & Traffic history
    history = await crud.get_traffic_history(limit=25)
    latest = history[-1] if history else {}
    rate_down_kbps = float(latest.get("rate_down_kbps", 0) or 0)
    rate_up_kbps = float(latest.get("rate_up_kbps", 0) or 0)
    current_rx_bps = int(rate_down_kbps * 1024 * 8)
    current_tx_bps = int(rate_up_kbps * 1024 * 8)

    # 3. Client details & aggregation
    online_data = await _fetch_online_data()
    all_clients = await crud.get_all_clients(online_data=online_data)
    total_clients = len(all_clients)
    online_clients = sum(1 for c in all_clients if c.get("online_status") or c.get("online"))
    active_clients = sum(1 for c in all_clients if c.get("is_active"))
    expired_clients = sum(1 for c in all_clients if c.get("is_expired"))
    quota_exceeded_clients = sum(1 for c in all_clients if c.get("is_quota_exceeded") or c.get("is_limit_reached"))
    disabled_clients = sum(1 for c in all_clients if not c.get("enable"))
    total_upload_bytes = sum(c.get("upload_bytes", 0) for c in all_clients)
    total_download_bytes = sum(c.get("download_bytes", 0) for c in all_clients)

    # 4. Hysteria & Inbound
    inbounds = await crud.get_all_inbounds()
    main_inbound = inbounds[0] if inbounds else None
    listen_port = main_inbound.get("listen_port", 443) if main_inbound else int(await crud.get_setting("listen_port", "443"))
    port_hopping_enabled = bool(main_inbound.get("port_hopping_enabled")) if main_inbound else ((await crud.get_setting("port_hopping_enabled", "0")) == "1")
    port_hopping_range = main_inbound.get("port_hopping_range", "") if main_inbound else (await crud.get_setting("port_hopping_range", ""))
    hysteria_running = is_hysteria_running()
    hysteria_ver = get_hysteria_version()

    # 5. Cloudflare WARP
    warp_info = await detect_warp(force_refresh=False)
    warp_status = warp_info.get("warp_status", "off")
    warp_active = bool(warp_info.get("active", False))
    warp_mode = warp_info.get("mode", "none")
    warp_ip = warp_info.get("external_ip")
    warp_latency = warp_info.get("latency_ms")
    warp_iface = warp_info.get("interface") or warp_info.get("socks5_addr")

    # 6. Routing & Presets
    global_outbound = await crud.get_setting("routing_global_outbound", "direct")
    custom_rules = await crud.get_routing_rules()
    custom_rules_count = len(custom_rules)
    presets_status = {
        "ru": await crud.get_setting("routing_ru", "direct"),
        "openai": await crud.get_setting("routing_openai", "warp"),
        "discord": await crud.get_setting("routing_discord", "direct"),
        "youtube": await crud.get_setting("routing_youtube", "direct"),
        "telegram": await crud.get_setting("routing_telegram", "direct"),
        "netflix": await crud.get_setting("routing_netflix", "warp"),
        "p2p": await crud.get_setting("routing_p2p", "block"),
        "ads": (await crud.get_setting("routing_ads", "1")) in ("1", "true", True),
        "win_spy": (await crud.get_setting("routing_win_spy", "1")) in ("1", "true", True)
    }

    server_data = {
        "uptime": uptime_str,
        "cpu_pct": cpu_percent,
        "cpu_percent": cpu_percent,
        "ram_pct": mem_percent,
        "mem_percent": mem_percent,
        "mem_used_gb": mem_used,
        "mem_total_gb": mem_total,
        "disk_pct": disk_percent,
        "disk_percent": disk_percent,
        "disk_used_gb": disk_used,
        "disk_total_gb": disk_total,
        "version": hysteria_ver,
        "port": listen_port,
        "egress_ip": await crud.get_setting("server_ip", ""),
        "stealth_path": await crud.get_setting("panel_secret_path", "panel"),
        "hysteria_running": hysteria_running,
    }

    clients_data = {
        "total": total_clients,
        "online": online_clients,
        "active": active_clients,
        "expired": expired_clients,
        "quota_exceeded": quota_exceeded_clients,
        "disabled": disabled_clients,
    }

    bandwidth_data = {
        "current_rx_bps": current_rx_bps,
        "current_tx_bps": current_tx_bps,
        "download_speed_bps": current_rx_bps,
        "upload_speed_bps": current_tx_bps,
        "total_upload_bytes": total_upload_bytes,
        "total_download_bytes": total_download_bytes,
        "total_rx_bytes": total_download_bytes,
        "total_tx_bytes": total_upload_bytes,
        "rate_down_kbps": rate_down_kbps,
        "rate_up_kbps": rate_up_kbps,
    }

    gateway_data = {
        "global_outbound": global_outbound,
        "warp_active": warp_active,
        "warp_ip": warp_ip,
        "warp_latency": warp_latency,
        "mode": warp_mode,
        "status": warp_status,
    }

    hysteria_data = {
        "running": hysteria_running,
        "active": hysteria_running,
        "listen_port": listen_port,
        "port_hopping_enabled": port_hopping_enabled,
        "port_hopping_range": port_hopping_range,
        "version": hysteria_ver,
    }

    warp_data = {
        "status": warp_status,
        "mode": warp_mode,
        "detected": warp_active,
        "interface": warp_iface,
        "port": await crud.get_setting("warp_port", "40000"),
        "active": warp_active,
        "ip": warp_ip,
        "latency_ms": warp_latency,
    }

    routing_data = {
        "global_outbound": global_outbound,
        "custom_rules_count": custom_rules_count,
        "rules_count": custom_rules_count,
        "presets_status": presets_status,
    }

    return {
        "server": server_data,
        "system": {**server_data, **bandwidth_data},
        "clients": clients_data,
        "clients_summary": clients_data,
        "bandwidth": bandwidth_data,
        "gateway": gateway_data,
        "hysteria": hysteria_data,
        "warp": warp_data,
        "routing": routing_data,
        "recent_clients": all_clients[:10],
        "traffic_history": history,
    }


def get_service_logs(service_name: str, lines: int = 80) -> str:
    """Safely get recent journalctl logs for given systemd unit."""
    try:
        import subprocess
        unit = "hysteria-server.service" if service_name == "hysteria" else "innerblitz.service"
        cmd = ["journalctl", "-u", unit, "-n", str(lines), "--no-pager"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return res.stdout or f"No logs available for {unit}."
    except Exception as e:
        return f"Error fetching logs: {e}"

@router.get("/logs")
async def get_logs(service: str = "hysteria", lines: int = 80):
    """Retrieve recent journalctl logs for Hysteria 2 or InnerBlitz panel."""
    return {"logs": get_service_logs(service_name=service, lines=lines)}

@router.post("/logs/clear")
async def clear_logs_endpoint():
    """Clear and rotate system journal logs."""
    ok, msg = clear_service_logs()
    return {"ok": ok, "message": msg}

class LogConfigPayload(BaseModel):
    level: str = "info"
    zero_logs: bool = False

@router.get("/logs/config")
async def get_logs_config():
    """Get current logging level and zero-logs status."""
    level = await crud.get_setting("log_level", "info")
    zero_logs = (await crud.get_setting("zero_logs", "0")) == "1"
    return {"level": level, "zero_logs": zero_logs}

@router.post("/logs/config")
async def update_logs_config(payload: LogConfigPayload):
    """Update log level and zero-logs privacy mode."""
    valid_levels = ["debug", "info", "warn", "error"]
    lvl = payload.level.lower() if payload.level.lower() in valid_levels else "info"
    await crud.set_setting("log_level", lvl)
    await crud.set_setting("zero_logs", "1" if payload.zero_logs else "0")
    ok, msg = configure_service_logging(level=lvl, zero_logs=payload.zero_logs)
    return {"ok": ok, "message": msg, "level": lvl, "zero_logs": payload.zero_logs}


