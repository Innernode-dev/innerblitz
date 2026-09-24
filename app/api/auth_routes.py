from fastapi import APIRouter, Request, Response, HTTPException, status, Depends
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
import logging

from app.config import settings
from app.database import crud
from app.database.models import LoginRequest
from app.core.security import verify_password, verify_totp, generate_session_id
from app.core.auth import authenticate_client

logger = logging.getLogger("innerblitz.api.auth")
router = APIRouter()

# Global in-memory rate limiting map for login
_failed_attempts = {}

class HysteriaAuthRequest(BaseModel):
    addr: Optional[str] = ""
    auth: Optional[str] = ""
    tx: Optional[int] = 0

@router.post("/auth")
async def hysteria_http_auth(req: HysteriaAuthRequest):
    """
    Hysteria 2 HTTP Auth Hook endpoint.
    Called on every client connection by Hysteria 2 core.
    """
    is_ok, user_id, msg = await authenticate_client(req.auth or "", req.addr or "")
    if is_ok:
        return {"ok": True, "id": user_id}
    return {"ok": False, "msg": msg}

async def get_current_admin(request: Request) -> str:
    """Dependency: verify admin session cookie or Authorization header."""
    session_id = request.cookies.get(settings.COOKIE_NAME)
    if not session_id:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            session_id = auth_header.split(" ", 1)[1]

    if not session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    session = await crud.get_session(session_id)
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired or invalid")

    return session["username"]

@router.post("/api/login")
async def login(req: LoginRequest, request: Request, response: Response):
    """Admin login endpoint with rate limiting, bcrypt and flexible 2FA (TOTP/Telegram)."""
    client_ip = request.client.host if request.client else "127.0.0.1"

    # Rate limiting check
    now = datetime.now()
    if client_ip in _failed_attempts:
        attempts, blocked_until = _failed_attempts[client_ip]
        if blocked_until and now < blocked_until:
            wait_sec = int((blocked_until - now).total_seconds())
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=f"Too many failed attempts. Try again in {wait_sec}s.")
        if blocked_until and now >= blocked_until:
            del _failed_attempts[client_ip]

    # Verify admin credentials
    admin_user = await crud.get_setting("admin_username", "admin")
    admin_pwd_hash = await crud.get_setting("admin_password_hash", "")

    if req.username != admin_user or not verify_password(req.password, admin_pwd_hash):
        attempts = _failed_attempts.get(client_ip, (0, None))[0] + 1
        blocked_until = now + timedelta(seconds=settings.LOGIN_COOLDOWN_SECONDS) if attempts >= settings.MAX_LOGIN_ATTEMPTS else None
        _failed_attempts[client_ip] = (attempts, blocked_until)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

    # Check 2FA requirements
    totp_enabled = await crud.get_setting("totp_enabled", "0") == "1"
    tg_2fa_enabled = await crud.get_setting("tg_2fa_enabled", "0") == "1"

    if totp_enabled:
        totp_secret = await crud.get_setting("totp_secret", "")
        if not req.totp_code:
            return {"require_2fa": True, "type": "totp", "message": "Enter your 6-digit Google Authenticator code"}
        if not verify_totp(totp_secret, req.totp_code):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid TOTP code")

    if tg_2fa_enabled:
        # Check active Telegram OTP code from settings/cache
        expected_tg_code = await crud.get_setting("_current_tg_otp", "")
        if not req.tg_code:
            # Need Telegram code
            return {"require_2fa": True, "type": "telegram", "message": "Enter the verification code sent to your Telegram"}
        if req.tg_code != expected_tg_code:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Telegram verification code")

    # Clear failed attempts on success
    if client_ip in _failed_attempts:
        del _failed_attempts[client_ip]

    # Create session
    session_id = generate_session_id()
    expires_at = now + timedelta(hours=settings.SESSION_EXPIRE_HOURS)
    ua = request.headers.get("User-Agent", "")[:250]
    await crud.create_session(session_id, req.username, expires_at, client_ip, ua)

    response.set_cookie(
        key=settings.COOKIE_NAME,
        value=session_id,
        httponly=True,
        samesite="lax",
        secure=False, # Set to True if pure HTTPS
        max_age=settings.SESSION_EXPIRE_HOURS * 3600
    )
    return {"ok": True, "username": req.username}

@router.post("/api/logout")
async def logout(request: Request, response: Response):
    """Admin logout and session termination."""
    session_id = request.cookies.get(settings.COOKIE_NAME)
    if session_id:
        await crud.delete_session(session_id)
    response.delete_cookie(settings.COOKIE_NAME)
    return {"ok": True, "message": "Logged out successfully"}

@router.get("/api/me")
async def get_me(username: str = Depends(get_current_admin)):
    """Return current admin session info."""
    totp_enabled = await crud.get_setting("totp_enabled", "0") == "1"
    tg_2fa_enabled = await crud.get_setting("tg_2fa_enabled", "0") == "1"
    return {
        "username": username,
        "totp_enabled": totp_enabled,
        "tg_2fa_enabled": tg_2fa_enabled
    }
