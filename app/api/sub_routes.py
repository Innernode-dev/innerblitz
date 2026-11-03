from fastapi import APIRouter, Request, HTTPException, status, Response
from fastapi.responses import HTMLResponse, PlainTextResponse
from pathlib import Path
import qrcode
import io
import base64
from datetime import datetime, timedelta

from app.database import crud
from app.core.subscription import build_hy2_uri, build_clash_yaml, build_singbox_json, build_base64_sub
from app.core.templates import render_template

router = APIRouter()


def _get_sub_userinfo_header(user: dict) -> str:
    """Generate Subscription-Userinfo header recognized by modern proxy clients."""
    upload = user.get("upload_bytes", 0) or 0
    download = user.get("download_bytes", 0) or 0
    total = user.get("total_bytes") if user.get("total_bytes") is not None else (user.get("max_download_bytes", 0) or 0)
    
    # Calculate expire timestamp
    expire_ts = 0
    expiry_time = user.get("expiry_time", 0) or 0
    if expiry_time > 0:
        expire_ts = int(expiry_time / 1000)
    else:
        exp_days = user.get("expiration_days", 0) or 0
        if exp_days > 0:
            try:
                creation_str = user.get("account_creation_date", "") or ""
                created = datetime.strptime(creation_str[:10], "%Y-%m-%d")
                expire_dt = created + timedelta(days=exp_days)
                expire_ts = int(expire_dt.timestamp())
            except Exception:
                pass

    return f"upload={upload}; download={download}; total={total}; expire={expire_ts}"

@router.get("/sub/{token}")
async def get_raw_subscription(token: str, request: Request):
    """Universal Base64 subscription endpoint for v2rayN, Shadowrocket, NekoBox, Hiddify."""
    user = await crud.get_user_by_token(token)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Subscription not found")

    settings_dict = await crud.get_all_settings()
    req_host = request.url.hostname
    sub_content = build_base64_sub(user, settings_dict, request_host=req_host)

    headers = {
        "Subscription-Userinfo": _get_sub_userinfo_header(user),
        "Content-Disposition": f'attachment; filename="InnerBlitz-{user["username"]}.txt"'
    }
    return PlainTextResponse(sub_content, headers=headers)

@router.get("/sub/{token}/clash")
async def get_clash_subscription(token: str, request: Request):
    """Clash Meta / Mihomo configuration subscription."""
    user = await crud.get_user_by_token(token)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Subscription not found")

    settings_dict = await crud.get_all_settings()
    custom_rules = await crud.get_routing_rules(enabled_only=True)
    settings_dict["routing_rules"] = custom_rules
    req_host = request.url.hostname
    clash_content = build_clash_yaml(user, settings_dict, request_host=req_host)

    headers = {
        "Subscription-Userinfo": _get_sub_userinfo_header(user),
        "Content-Disposition": f'attachment; filename="InnerBlitz-{user["username"]}.yaml"'
    }
    return PlainTextResponse(clash_content, media_type="text/yaml", headers=headers)

@router.get("/sub/{token}/singbox")
async def get_singbox_subscription(token: str, response: Response, request: Request):
    """Sing-box configuration subscription."""
    user = await crud.get_user_by_token(token)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Subscription not found")

    settings_dict = await crud.get_all_settings()
    custom_rules = await crud.get_routing_rules(enabled_only=True)
    settings_dict["routing_rules"] = custom_rules
    req_host = request.url.hostname
    singbox_data = build_singbox_json(user, settings_dict, request_host=req_host)

    response.headers["Subscription-Userinfo"] = _get_sub_userinfo_header(user)
    return singbox_data

@router.get("/portal/{token}", response_class=HTMLResponse)
async def client_portal_page(request: Request, token: str):
    """Personal web portal for client with data usage and 1-click import buttons."""
    user = await crud.get_user_by_token(token)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Portal not found or expired")

    settings_dict = await crud.get_all_settings()
    req_host = request.url.hostname
    hy2_uri = build_hy2_uri(user, settings_dict, request_host=req_host)

    # Generate QR Code image (PNG in base64)
    qr = qrcode.QRCode(box_size=6, border=2)
    qr.add_data(hy2_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#000000", back_color="#ffffff")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    host_url = str(request.base_url).rstrip("/")
    sub_url = f"{host_url}/sub/{token}"
    clash_sub_url = f"{host_url}/sub/{token}/clash"
    singbox_sub_url = f"{host_url}/sub/{token}/singbox"

    # Percentage calculation
    percent_used = 0
    if user["max_traffic_gb"] > 0:
        percent_used = min(100, int((user["used_traffic_gb"] / user["max_traffic_gb"]) * 100))

    return render_template(
        request,
        "client_portal.html",
        {
            "user": user,
            "hy2_uri": hy2_uri,
            "qr_base64": f"data:image/png;base64,{qr_b64}",
            "sub_url": sub_url,
            "clash_sub_url": clash_sub_url,
            "singbox_sub_url": singbox_sub_url,
            "percent_used": percent_used,
            "settings": settings_dict
        }
    )

