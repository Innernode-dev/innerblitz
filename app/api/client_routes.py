from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from typing import List, Dict, Any, Optional
import aiohttp
import io
import base64
import qrcode
import logging

from app.config import settings
from app.api.auth_routes import get_current_admin
from app.database import crud
from app.database.models import (
    ClientCreate, ClientUpdate, ClientOut,
    InboundModel, InboundCreate, InboundUpdate
)
from app.core.subscription import build_hy2_uri, build_clash_yaml, build_singbox_json
from app.core.limiter import kick_users_api

logger = logging.getLogger("innerblitz.api.clients")

router = APIRouter(prefix="/api/clients", dependencies=[Depends(get_current_admin)])
inbound_router = APIRouter(prefix="/api/inbounds", dependencies=[Depends(get_current_admin)])

async def _fetch_online_data() -> Dict[str, Any]:
    """Fetch online connections from Hysteria 2 core."""
    secret = await crud.get_setting("traffic_secret", "")
    url = f"http://127.0.0.1:{settings.HYSTERIA_TRAFFIC_STATS_PORT}/online"
    headers = {"Authorization": secret}
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=2)) as session:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data if isinstance(data, dict) else {}
    except Exception:
        pass
    return {}

# ==================== CLIENT ROUTES (/api/clients) ====================

@router.get("", response_model=List[Dict[str, Any]])
async def list_clients(inbound_id: Optional[int] = Query(None, description="Filter by inbound ID")):
    """
    List clients with calculated metrics:
    used_traffic_bytes, used_traffic_gb, total_traffic_gb, percent_used,
    is_active, is_expired, is_quota_exceeded, days_left, expiry_date_str,
    online_status, and current_ips.
    """
    online_data = await _fetch_online_data()
    return await crud.get_all_clients(inbound_id=inbound_id, online_data=online_data)

@router.post("", status_code=status.HTTP_201_CREATED)
async def create_client(client: ClientCreate):
    """
    Create a new client under an inbound.
    Auto-generates password if omitted; supports total_gb or traffic_limit_gb,
    expiry_time or expiration_days.
    """
    existing = await crud.get_client_by_username(client.username)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Username '{client.username}' already exists"
        )
    created = await crud.create_client(client)
    return created

@router.get("/online")
async def get_online_clients():
    """Returns active clients, connection IPs, and session counts from Hysteria core."""
    online_data = await _fetch_online_data()
    summary = []
    for username, conns in online_data.items():
        if isinstance(conns, list):
            unique_ips = list({c.split(":")[0] for c in conns if ":" in c})
            summary.append({
                "username": username,
                "ips": unique_ips,
                "connections": len(conns)
            })
        else:
            summary.append({
                "username": username,
                "ips": [],
                "connections": 1
            })
    return {
        "active_clients_count": len(online_data),
        "clients": summary,
        "raw": online_data
    }

@router.get("/{id}")
async def get_client(id: str):
    """Retrieve client details by ID or username."""
    online_data = await _fetch_online_data()
    client = None
    if id.isdigit():
        client = await crud.get_client_by_id(int(id), online_data=online_data)
    if not client:
        client = await crud.get_client_by_username(id, online_data=online_data)
    if not client:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")
    return client

@router.put("/{id}")
async def update_client(id: str, data: ClientUpdate):
    """Update client parameters. If client is disabled, immediately kicks active connections."""
    existing = None
    if id.isdigit():
        existing = await crud.get_client_by_id(int(id))
    if not existing:
        existing = await crud.get_client_by_username(id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")

    updated = await crud.update_client(id, data)
    
    # If client was disabled, immediately terminate active sessions
    if data.enable is False or data.blocked is True:
        await kick_users_api([existing["username"]])

    return updated

@router.post("/{id}/toggle")
async def toggle_client(id: str):
    """1-click toggle client enable status."""
    existing = None
    if id.isdigit():
        existing = await crud.get_client_by_id(int(id))
    if not existing:
        existing = await crud.get_client_by_username(id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")

    updated = await crud.toggle_client_enable(id)
    if updated and not updated.get("enable", True):
        await kick_users_api([existing["username"]])

    return {
        "ok": True,
        "enable": updated.get("enable", False) if updated else False,
        "client": updated
    }

@router.post("/{id}/reset-traffic")
async def reset_client_traffic(id: str):
    """Pure traffic reset: zeroes out uploaded and downloaded bytes while preserving expiration date."""
    existing = None
    if id.isdigit():
        existing = await crud.get_client_by_id(int(id))
    if not existing:
        existing = await crud.get_client_by_username(id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")

    await crud.reset_client_traffic(existing["username"])
    refreshed = await crud.get_client_by_username(existing["username"])
    return {
        "ok": True,
        "message": f"Traffic reset for client '{existing['username']}'",
        "client": refreshed
    }

@router.delete("/{id}")
async def delete_client(id: str):
    """Delete client and kick any active sessions."""
    existing = None
    if id.isdigit():
        existing = await crud.get_client_by_id(int(id))
    if not existing:
        existing = await crud.get_client_by_username(id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")

    username = existing["username"]
    await crud.delete_client(id)
    await kick_users_api([username])
    return {"ok": True, "message": f"Client '{username}' deleted"}

@router.get("/{id}/config")
async def get_client_config(id: str, request: Request):
    """Generate hy2:// URI, Clash Meta YAML, Sing-box JSON, and QR code data URI."""
    existing = None
    if id.isdigit():
        existing = await crud.get_client_by_id(int(id))
    if not existing:
        existing = await crud.get_client_by_username(id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")

    settings_dict = await crud.get_all_settings()
    custom_rules = await crud.get_routing_rules(enabled_only=True)
    settings_dict["routing_rules"] = custom_rules
    req_host = request.url.hostname
    uri = build_hy2_uri(existing, settings_dict, request_host=req_host)

    # Generate QR Code image (PNG in base64)
    qr = qrcode.QRCode(box_size=8, border=2)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#000000", back_color="#ffffff")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    sub_token = existing.get("sub_token", "")
    return {
        "username": existing["username"],
        "uri": uri,
        "qr_base64": f"data:image/png;base64,{qr_b64}",
        "sub_token": sub_token,
        "sub_url": f"/sub/{sub_token}",
        "clash_yaml": build_clash_yaml(existing, settings_dict, request_host=req_host),
        "singbox_json": build_singbox_json(existing, settings_dict, request_host=req_host)
    }

# ==================== INBOUND ROUTES (/api/inbounds) ====================

@inbound_router.get("", response_model=List[Dict[str, Any]])
async def list_inbounds():
    """List all inbounds with active client count and total bandwidth."""
    inbounds = await crud.get_all_inbounds()
    online_data = await _fetch_online_data()
    all_clients = await crud.get_all_clients(online_data=online_data)
    
    # Enrich inbounds with client stats
    for ib in inbounds:
        ib_id = ib.get("id", 1)
        ib_clients = [c for c in all_clients if c.get("inbound_id", 1) == ib_id]
        ib["total_clients"] = len(ib_clients)
        ib["active_clients"] = len([c for c in ib_clients if c.get("is_active", True)])
        ib["online_clients"] = len([c for c in ib_clients if c.get("online_status", False)])
        total_up = sum(c.get("upload_bytes", 0) for c in ib_clients)
        total_down = sum(c.get("download_bytes", 0) for c in ib_clients)
        ib["total_traffic_bytes"] = total_up + total_down
        ib["total_traffic_gb"] = round((total_up + total_down) / (1024 ** 3), 2)
    return inbounds

@inbound_router.post("", status_code=status.HTTP_201_CREATED)
async def create_inbound(data: InboundCreate):
    """Create a new inbound."""
    created = await crud.create_inbound(data)
    return created

@inbound_router.get("/{id}")
async def get_inbound(id: int):
    """Retrieve an inbound by ID."""
    ib = await crud.get_inbound_by_id(id)
    if not ib:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Inbound not found")
    return ib

@inbound_router.put("/{id}")
async def update_inbound(id: int, data: InboundUpdate):
    """Update an inbound's configuration."""
    existing = await crud.get_inbound_by_id(id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Inbound not found")
    updated = await crud.update_inbound(id, data)
    return updated

@inbound_router.delete("/{id}")
async def delete_inbound(id: int):
    """Delete an inbound and its attached clients."""
    existing = await crud.get_inbound_by_id(id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Inbound not found")
    success = await crud.delete_inbound(id)
    if not success:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to delete inbound")
    return {"ok": True, "message": f"Inbound {id} deleted successfully"}

@inbound_router.post("/{id}/reset-traffic")
async def reset_inbound_traffic(id: int):
    """Reset traffic for all clients attached to this inbound."""
    existing = await crud.get_inbound_by_id(id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Inbound not found")
    await crud.reset_inbound_traffic(id)
    return {"ok": True, "message": f"Traffic reset for all clients on inbound {id}"}
