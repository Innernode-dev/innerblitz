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


