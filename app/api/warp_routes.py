"""
InnerBlitz WARP Management & Diagnostics API Router
Endpoints mounted at /api/warp
"""

from typing import Dict, Literal, Optional, Any, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.api.auth_routes import get_current_admin
from app.core import warp
from app.database import crud

router = APIRouter(prefix="/api/warp", tags=["WARP"], dependencies=[Depends(get_current_admin)])


class WarpStatusResponse(BaseModel):
    active: bool
    mode: Literal["wireguard", "socks5", "none"]
    interface: Optional[str] = None
    socks5_addr: Optional[str] = None
    external_ip: Optional[str] = None
    warp_status: Literal["on", "plus", "off"]
    status_level: Literal["active", "standby", "offline"]
    latency_ms: Optional[float] = None
    colo: Optional[str] = None
    timestamp: str


class TraceDetail(BaseModel):
    reachable: bool
    ip: Optional[str] = None
    warp: Optional[str] = "off"
    colo: Optional[str] = None
    loc: Optional[str] = None
    latency_ms: Optional[float] = None
    http: Optional[str] = None
    tls: Optional[str] = None
    error: Optional[str] = None


class DiagnosticsSummary(BaseModel):
    ip_masked: bool
    direct_ip: Optional[str] = None
    warp_ip: Optional[str] = None
    latency_delta_ms: Optional[float] = None
    warp_status: str
    colo: Optional[str] = None
    loc: Optional[str] = None


class WarpDiagnosticsResponse(BaseModel):
    timestamp: str
    warp_active: bool
    mode: str
    status_level: str
    direct: TraceDetail
    warp: TraceDetail
    summary: DiagnosticsSummary


class WarpToggleRequest(BaseModel):
    enabled: bool
    port: Optional[int] = Field(default=40000, ge=1024, le=65535)
    mode: Optional[Literal["socks5", "wireguard"]] = "socks5"


class WarpInstallPayload(BaseModel):
    mode: Literal["auto", "socks5", "wgcf"] = "auto"
    port: int = Field(default=40000, ge=1024, le=65535)
    force: bool = False  # If False, active pre-existing WARP connection blocks re-installation
    clean: bool = False


class WarpInstallLogResponse(BaseModel):
    status: str
    exit_code: Optional[int] = None
    error_message: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    total_lines: int
    offset: int
    next_offset: int
    has_more: bool
    logs: List[str]


@router.get("/status", response_model=WarpStatusResponse)
async def get_warp_status(
    force_refresh: bool = Query(default=False, description="Bypass TTL cache and re-probe")
):
    """
    Get current WARP connection status, egress IP, and latency.
    Used for live telemetry cards and status badges in web panel.
    """
    res = await warp.detect_warp(force_refresh=force_refresh)
    if isinstance(res, dict):
        raw_status = res.get("warp_status", "off")
        res["warp_status"] = raw_status if raw_status in ("on", "plus") else "off"
    return res


@router.get("/diagnostics", response_model=WarpDiagnosticsResponse)
async def get_warp_diagnostics(
    timeout: float = Query(default=5.0, ge=1.0, le=15.0, description="Diagnostics HTTP query timeout")
):
    """
    Execute real-time dual Cloudflare trace diagnostics (Direct Server IP vs WARP IP).
    Measures latency delta and confirms IP masking.
    """
    res = await warp.query_warp_diagnostics(timeout=timeout)
    return res


@router.post("/check", response_model=WarpStatusResponse)
async def trigger_warp_check():
    """
    Explicitly trigger socket handshake and WireGuard interface inspection.
    Adopts any newly detected pre-existing WARP connection.
    """
    res = await warp.detect_warp(force_refresh=True)
    if isinstance(res, dict):
        raw_status = res.get("warp_status", "off")
        res["warp_status"] = raw_status if raw_status in ("on", "plus") else "off"
        if res.get("active"):
            await warp.sync_warp_settings_from_detection(res)
    return res


@router.post("/toggle")
async def toggle_warp_outbound(payload: WarpToggleRequest):
    """
    Enable or disable Cloudflare WARP outbound in Hysteria 2 configuration.
    Validates configuration, writes to disk, and gracefully restarts Hysteria core.
    """
    updates = {
        "warp_enabled": "1" if payload.enabled else "0",
        "warp_port": str(payload.port or 40000),
        "warp_mode": payload.mode or "socks5"
    }
    await crud.set_settings(updates)

    from app.core.hysteria import apply_and_save_config, restart_hysteria
    ok = await apply_and_save_config()
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate or validate updated Hysteria configuration."
        )

    restart_hysteria()
    return {
        "ok": True,
        "warp_enabled": payload.enabled,
        "message": f"WARP outbound {'enabled' if payload.enabled else 'disabled'} successfully."
    }


@router.post("/install", status_code=status.HTTP_202_ACCEPTED)
async def install_warp_endpoint(payload: WarpInstallPayload):
    """
    1-Click WARP Installer Trigger with Connection Reuse Guard.
    Enforces 409 Conflict if an active connection already exists (unless force=true).
    """
    # Step 1: Idempotency Check — Do not create duplicate daemons if already active
    if not payload.force:
        current_warp = await warp.detect_warp(force_refresh=True)
        if current_warp["active"]:
            # Adopt the existing connection immediately
            await warp.sync_warp_settings_from_detection(current_warp)
            target = current_warp.get("socks5_addr") or current_warp.get("interface") or current_warp["mode"]
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"Active WARP connection already detected ({current_warp['mode']} on {target}). "
                    "Pre-existing connection adopted automatically. Pass 'force=true' to overwrite."
                )
            )

    # Step 2: Delegate to WarpProcessManager
    ok, msg = await warp.warp_installer.start_install(
        mode=payload.mode,
        port=payload.port,
        clean=payload.clean
    )
    if not ok:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=msg)

    return {
        "ok": True,
        "status": warp.WarpInstallStatus.INSTALLING.value,
        "message": msg,
        "start_time": warp.warp_installer.start_time
    }


@router.get("/install-log", response_model=WarpInstallLogResponse)
async def get_warp_install_log(
    offset: int = Query(default=0, ge=0, description="Log line offset for polling"),
    limit: int = Query(default=200, ge=1, le=1000, description="Maximum lines to fetch")
):
    """
    Poll live stdout/stderr log stream during and after installation.
    Supports incremental fetching via offset parameter.
    """
    return warp.warp_installer.get_logs(offset=offset, limit=limit)


@router.post("/install-cancel")
async def cancel_warp_install():
    """Cancel currently running installation process."""
    ok, msg = await warp.warp_installer.cancel_install()
    if not ok:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
    return {"ok": True, "message": msg}


@router.post("/restart")
async def restart_warp_endpoint():
    """Restart detected WARP systemd service unit."""
    ok, msg = warp.restart_warp_service()
    if not ok:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Restart failed: {msg}")
    return {"ok": True, "message": "WARP service restarted successfully."}


@router.post("/repair")
async def repair_warp_endpoint():
    """Run automated self-healing diagnostic and recovery sequence."""
    diag = warp.repair_warp_service()
    return diag
