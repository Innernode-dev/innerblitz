import os
import tarfile
import tempfile
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Dict, Any, Optional
import secrets
import qrcode
import io
import base64

import subprocess
from pathlib import Path

from app.config import settings
from app.api.auth_routes import get_current_admin
from app.database import crud
from app.core.security import (
    hash_password, verify_password, generate_totp_secret, 
    get_totp_uri, verify_totp, generate_secret_path
)
from app.core.cert import generate_self_signed_cert
from app.core.hysteria import apply_and_save_config, restart_hysteria, run_systemctl
from app.core.firewall import configure_port_hopping, flush_port_hopping

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
    decoy_theme: Optional[str] = None
    panel_port: Optional[str] = None
    panel_secret_path: Optional[str] = None

class ChangePasswordPayload(BaseModel):
    old_password: str
    new_password: str

class ChangeUsernamePayload(BaseModel):
    new_username: str

class ResetPanelPayload(BaseModel):
    use_random: bool = False
    port: Optional[str] = "8080"
    path: Optional[str] = "panel"
    reset_2fa: bool = False

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

        # If panel port changed, schedule service restart after response is sent
        if "panel_port" in updates:
            try:
                subprocess.Popen(["bash", "-c", "sleep 1.2 && systemctl restart innerblitz.service"])
            except Exception:
                pass

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

@router.post("/change-username")
async def change_admin_username(payload: ChangeUsernamePayload):
    """Change admin username for web panel."""
    new_user = payload.new_username.strip()
    if not new_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username cannot be empty")
    await crud.set_setting("admin_username", new_user)
    return {"ok": True, "message": f"Admin username changed to '{new_user}'"}

@router.post("/reset-ports")
async def reset_ports_endpoint():
    """Reset Hysteria 2 ports to standard 443 UDP and flush iptables hopping rules."""
    flush_port_hopping()
    await crud.set_settings({
        "listen_port": "443",
        "port_hopping_enabled": "0"
    })
    await apply_and_save_config()
    ok, out = restart_hysteria()
    return {"ok": ok, "message": "Hysteria 2 ports reset to 443 UDP. Port hopping flushed and disabled."}

@router.post("/flush-hopping")
async def flush_hopping_endpoint():
    """Flush all UDP redirect port hopping rules from iptables."""
    ok, msg = flush_port_hopping()
    return {"ok": ok, "message": msg}

@router.post("/reset-panel-access")
async def reset_panel_access_endpoint(payload: ResetPanelPayload):
    """Reset panel port and secret URL path, optionally randomizing or resetting 2FA."""
    updates = {}
    if payload.use_random:
        updates["panel_port"] = str(secrets.randbelow(40000) + 20000)
        updates["panel_secret_path"] = generate_secret_path()
    else:
        updates["panel_port"] = str(payload.port or "8080")
        updates["panel_secret_path"] = str(payload.path or "panel").strip("/ ")

    if payload.reset_2fa:
        updates["totp_enabled"] = "0"
        updates["totp_secret"] = ""
        updates["tg_2fa_enabled"] = "0"

    await crud.set_settings(updates)
    server_ip = await crud.get_setting("server_ip", "127.0.0.1")

    # Schedule background service restart to bind new port
    try:
        subprocess.Popen(["bash", "-c", "sleep 1.2 && systemctl restart innerblitz.service"])
    except Exception:
        pass

    return {
        "ok": True,
        "message": "Panel access updated. Please reconnect using the new URL.",
        "panel_port": updates["panel_port"],
        "panel_secret_path": updates["panel_secret_path"],
        "new_url": f"http://{server_ip}:{updates['panel_port']}/{updates['panel_secret_path']}"
    }

@router.post("/optimize-bbr")
async def optimize_bbr_endpoint():
    """Enable Linux TCP BBR and high-performance UDP buffer tuning."""
    try:
        conf_content = """# InnerBlitz High-Performance Network Tuning for Hysteria 2 QUIC
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.optmem_max = 2048576
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
net.ipv4.ip_forward = 1
"""
        sysctl_dir = Path("/etc/sysctl.d")
        if sysctl_dir.exists():
            conf_file = sysctl_dir / "99-innerblitz.conf"
            with open(conf_file, "w") as f:
                f.write(conf_content)
            subprocess.run(["sysctl", "--system"], capture_output=True)
            return {"ok": True, "message": "TCP BBR and high-speed UDP buffers successfully applied"}
        return {"ok": False, "message": "/etc/sysctl.d not found on this system"}
    except Exception as e:
        return {"ok": False, "message": str(e)}

class RawConfigPayload(BaseModel):
    content: str

@router.get("/raw-config")
async def get_raw_config():
    """Retrieve raw Hysteria 2 config.yaml content."""
    cfg_path = Path(settings.HYSTERIA_CONFIG_PATH)
    if cfg_path.exists():
        with open(cfg_path, "r", encoding="utf-8") as f:
            content = f.read()
        return {"ok": True, "content": content}
    return {"ok": False, "content": "# Config not found on disk"}

@router.post("/raw-config")
async def save_raw_config(payload: RawConfigPayload):
    """Save raw Hysteria 2 config.yaml content and restart core."""
    try:
        cfg_path = Path(settings.HYSTERIA_CONFIG_PATH)
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write(payload.content)
        ok, out = restart_hysteria()
        return {"ok": ok, "message": "Raw YAML config applied and Hysteria restarted!", "output": out}
    except Exception as e:
        return {"ok": False, "message": str(e)}

@router.get("/backup/download")
async def download_backup_endpoint():
    """Create and download a full backup archive of SQLite DB and certificates."""
    try:
        data_dir = Path(settings.DATA_DIR)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = Path("/etc/hysteria/backups")
        backup_dir.mkdir(parents=True, exist_ok=True)
        target_file = backup_dir / f"innerblitz_backup_{timestamp}.tar.gz"

        with tarfile.open(target_file, "w:gz") as tar:
            if data_dir.exists():
                tar.add(data_dir, arcname="data")
            if Path(settings.HYSTERIA_CONFIG_PATH).exists():
                tar.add(settings.HYSTERIA_CONFIG_PATH, arcname="config.yaml")

        return FileResponse(
            path=str(target_file),
            filename=f"innerblitz_backup_{timestamp}.tar.gz",
            media_type="application/gzip"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/backup/upload")
async def upload_backup_endpoint(file: UploadFile = File(...)):
    """Upload and restore from a backup archive."""
    if not file.filename.endswith((".tar.gz", ".tgz")):
        raise HTTPException(status_code=400, detail="Only .tar.gz backup archives supported")
    
    with tempfile.NamedTemporaryFile(delete=False, suffix=".tar.gz") as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        run_systemctl("stop", "innerblitz.service")
        run_systemctl("stop", "hysteria-server.service")
        with tarfile.open(tmp_path, "r:gz") as tar:
            tar.extractall(path="/etc/hysteria")
        run_systemctl("start", "innerblitz.service")
        run_systemctl("start", "hysteria-server.service")
        return {"ok": True, "message": "System successfully restored from backup archive!"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Restore failed: {e}")
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


