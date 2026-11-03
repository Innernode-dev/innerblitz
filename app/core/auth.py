import logging
from datetime import datetime, timedelta, date
from typing import Dict, Any, Tuple
from app.database import crud
from app.core.security import timing_safe_compare

logger = logging.getLogger("innerblitz.auth")

async def authenticate_client(auth_str: str, client_ip: str = "") -> Tuple[bool, str, str]:
    """
    Authenticate Hysteria 2 client request.
    Returns: (is_ok, user_id, message)
    """
    if not auth_str or ":" not in auth_str:
        return False, "", "Invalid auth format"

    username, password = auth_str.split(":", 1)
    username = username.strip()

    user = await crud.get_user_by_username(username)
    if not user:
        return False, "", "User not found"

    # 1. Check if user is blocked or disabled
    if user.get("blocked", False) or not user.get("enable", True):
        return False, "", "User account is blocked"

    # 2. Timing-safe password comparison
    if not timing_safe_compare(user.get("password", ""), password):
        return False, "", "Invalid password"

    # 3. Expiration check (supports both epoch ms expiry_time and relative expiration_days)
    expiry_time = user.get("expiry_time", 0) or 0
    if expiry_time > 0:
        now_ms = int(datetime.utcnow().timestamp() * 1000)
        if now_ms >= expiry_time:
            return False, "", "Account expired"
    elif not (user.get("unlimited_user", False) or user.get("u_unlimited", False)):
        expiration_days = user.get("expiration_days", 0)
        if expiration_days > 0:
            creation_str = user.get("account_creation_date", "")
            try:
                created_date = datetime.strptime(creation_str[:10], "%Y-%m-%d").date()
                if date.today() > created_date + timedelta(days=expiration_days):
                    return False, "", "Account expired"
            except ValueError:
                pass

    # 4. Traffic limit check
    max_bytes = user.get("total_bytes") if user.get("total_bytes") is not None else user.get("max_download_bytes", 0)
    if max_bytes > 0:
        used_bytes = user.get("upload_bytes", 0) + user.get("download_bytes", 0)
        if used_bytes >= max_bytes:
            return False, "", "Traffic quota exceeded"

    # 5. Unlimited users bypass remaining limits
    if user.get("unlimited_user", False) or user.get("u_unlimited", False):
        return True, username, "Authenticated (Unlimited)"

    return True, username, "Authenticated"
