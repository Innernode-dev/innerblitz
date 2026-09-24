from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Dict, Any, Optional
import secrets
import qrcode
import io
import base64

from app.api.auth_routes import get_current_admin
from app.database import crud
from app.core.security import (
    hash_password, verify_password, generate_totp_secret, 
    get_totp_uri, verify_totp
)
from app.core.cert import generate_self_signed_cert
from app.core.hysteria import apply_and_save_config, restart_hysteria
from app.core.firewall import configure_port_hopping

router = APIRouter(prefix="/api/settings", dependencies=[Depends(get_current_admin)])

class SettingsPayload(BaseModel):
    server_ip: Optional[str] = None
    server_domain: Optional[str] = None
    listen_port: Optional[int] = None
    port_hopping_enabled: Optional[bool] = None
    port_hopping_range: Optional[str] = None
    tls_type: Optional[str] = None
    obfs_type: Optional[str] = None
    obfs_password: Optional[str] = None
    mimic_enabled: Optional[bool] = None
    masquerade_type: Optional[str] = None
    masquerade_target: Optional[str] = None
    up_mbps: Optional[str] = None
    down_mbps: Optional[str] = None
    ignore_client_bandwidth: Optional[bool] = None
    tg_bot_token: Optional[str] = None
    tg_admin_chat_id: Optional[str] = None
    tg_2fa_enabled: Optional[bool] = None
    tg_notifications_enabled: Optional[bool] = None
    decoy_enabled: Optional[bool] = None

class ChangePasswordPayload(BaseModel):
    old_password: str
    new_password: str

class VerifyTotpPayload(BaseModel):
    secret: str
    code: str

@router.get("")
async def get_settings():
    """Retrieve system settings safely (masking sensitive fields)."""
    data = await crud.get_all_settings()
    # Mask password hash
    data.pop("admin_password_hash", None)
    data.pop("_current_tg_otp", None)
    return data

@router.post("")
async def update_settings(payload: SettingsPayload):
    """Update system settings, rewrite config.yaml and update firewall."""
    updates = {}
    for k, v in payload.dict(exclude_unset=True).items():
        if isinstance(v, bool):
            updates[k] = "1" if v else "0"
        else:
            updates[k] = str(v)

    if updates:
        await crud.set_settings(updates)
        await apply_and_save_config()

        # Update port hopping firewall rule
        if "port_hopping_enabled" in updates or "port_hopping_range" in updates:
            hopping_on = updates.get("port_hopping_enabled") == "1"
            hopping_range = updates.get("port_hopping_range", "20000:50000")
            target_port = int(updates.get("listen_port", 443))
            configure_port_hopping(hopping_range, target_port, enable=hopping_on)

    return {"ok": True, "message": "Settings updated and Hysteria config applied"}

@router.post("/generate-ip-cert")
async def generate_ip_certificate():
    """Generate or renew self-signed certificate with IP Subject Alternative Name."""
    server_ip = await crud.get_setting("server_ip", "127.0.0.1")
    cert_path, key_path, sha256_pin = generate_self_signed_cert(server_ip)

    await crud.set_settings({
        "tls_type": "self_signed_ip",
        "cert_sha256": sha256_pin
    })
    await apply_and_save_config()
    restart_hysteria()

    return {
        "ok": True,
        "message": f"Certificate generated for {server_ip}",
        "cert_sha256": sha256_pin
    }

@router.post("/restart-hysteria")
async def restart_hysteria_service():
    """Restart Hysteria 2 server."""
    ok, out = restart_hysteria()
    return {"ok": ok, "output": out}

@router.post("/setup-totp")
async def setup_totp():
    """Generate a new TOTP secret and return QR code for Google Authenticator."""
    secret = generate_totp_secret()
    admin_user = await crud.get_setting("admin_username", "admin")
    uri = get_totp_uri(secret, username=admin_user)

    qr = qrcode.QRCode(box_size=6, border=2)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#000000", back_color="#ffffff")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    return {
        "secret": secret,
        "uri": uri,
        "qr_base64": f"data:image/png;base64,{qr_b64}"
    }

@router.post("/verify-enable-totp")
async def verify_enable_totp(payload: VerifyTotpPayload):
    """Verify code with new secret and enable TOTP 2FA."""
    if not verify_totp(payload.secret, payload.code):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid verification code")

    await crud.set_settings({
        "totp_secret": payload.secret,
        "totp_enabled": "1"
    })
    return {"ok": True, "message": "Two-factor authentication successfully enabled"}

@router.post("/disable-totp")
async def disable_totp():
    """Disable TOTP 2FA."""
    await crud.set_settings({
        "totp_secret": "",
        "totp_enabled": "0"
    })
    return {"ok": True, "message": "TOTP 2FA disabled"}

@router.post("/change-password")
async def change_admin_password(payload: ChangePasswordPayload):
    """Change admin password."""
    stored_hash = await crud.get_setting("admin_password_hash", "")
    if not verify_password(payload.old_password, stored_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")

    new_hash = hash_password(payload.new_password)
    await crud.set_setting("admin_password_hash", new_hash)
    return {"ok": True, "message": "Password changed successfully"}

@router.post("/apply-preset")
async def apply_preset(payload: Dict[str, str]):
    """Apply 1-click configuration presets (anti-dpi, speed, gaming)."""
    preset_name = payload.get("preset", "anti-dpi")
    updates = {"preset": preset_name}

    if preset_name == "anti-dpi":
        updates.update({
            "port_hopping_enabled": "1",
            "port_hopping_range": "20000:50000",
            "obfs_type": "salamander",
            "obfs_password": secrets.token_urlsafe(16),
            "masquerade_type": "proxy",
            "masquerade_target": "https://bing.com",
            "ignore_client_bandwidth": "0"
        })
    elif preset_name == "speed":
        updates.update({
            "port_hopping_enabled": "0",
            "up_mbps": "1000",
            "down_mbps": "1000",
            "ignore_client_bandwidth": "1"
        })
    elif preset_name == "gaming":
        updates.update({
            "port_hopping_enabled": "0",
            "up_mbps": "300",
            "down_mbps": "300",
            "ignore_client_bandwidth": "0"
        })

    await crud.set_settings(updates)
    await apply_and_save_config()
    restart_hysteria()
    return {"ok": True, "message": f"Preset '{preset_name}' applied successfully", "updates": updates}
