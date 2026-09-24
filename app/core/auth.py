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

    # 1. Check if user is blocked
    if user.get("blocked", False):
        return False, "", "User account is blocked"

    # 2. Timing-safe password comparison
    if not timing_safe_compare(user.get("password", ""), password):
        return False, "", "Invalid password"

    # 3. Unlimited users bypass expiration and traffic limits
    if user.get("unlimited_user", False):
        return True, username, "Authenticated (Unlimited)"

    # 4. Expiration check
    expiration_days = user.get("expiration_days", 0)
    if expiration_days > 0:
        creation_str = user.get("account_creation_date", "")
        try:
            created_date = datetime.strptime(creation_str, "%Y-%m-%d").date()
            if date.today() > created_date + timedelta(days=expiration_days):
                return False, "", "Account expired"
        except ValueError:
            pass

    # 5. Traffic limit check
    max_bytes = user.get("max_download_bytes", 0)
    if max_bytes > 0:
        used_bytes = user.get("upload_bytes", 0) + user.get("download_bytes", 0)
        if used_bytes >= max_bytes:
            return False, "", "Traffic quota exceeded"

    return True, username, "Authenticated"
