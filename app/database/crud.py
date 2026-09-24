import aiosqlite
import secrets
from datetime import datetime, date, timedelta
from typing import List, Optional, Dict, Any
from app.database.connection import get_db_connection
from app.database.models import UserCreate, UserUpdate, UserOut

def _calculate_user_metrics(row: aiosqlite.Row) -> Dict[str, Any]:
    """Helper to calculate user traffic, expiration, and status."""
    data = dict(row)
    data["blocked"] = bool(data["blocked"])
    data["unlimited_user"] = bool(data["unlimited_user"])
    
    total_bytes = data["upload_bytes"] + data["download_bytes"]
    max_bytes = data["max_download_bytes"]
    
    data["used_traffic_gb"] = round(total_bytes / (1024 ** 3), 2)
    data["max_traffic_gb"] = round(max_bytes / (1024 ** 3), 2) if max_bytes > 0 else 0.0
    
    # Traffic limit reached
    data["is_limit_reached"] = False
    if not data["unlimited_user"] and max_bytes > 0 and total_bytes >= max_bytes:
        data["is_limit_reached"] = True

    # Expiration calculation
    data["is_expired"] = False
    data["days_left"] = 999
    if not data["unlimited_user"] and data["expiration_days"] > 0:
        try:
            created = datetime.strptime(data["account_creation_date"], "%Y-%m-%d").date()
            expire_date = created + timedelta(days=data["expiration_days"])
            today = date.today()
            delta = (expire_date - today).days
            data["days_left"] = max(delta, 0)
            if delta < 0:
                data["is_expired"] = True
        except ValueError:
            pass

    return data

# ==================== USERS CRUD ====================

async def get_all_users() -> List[Dict[str, Any]]:
    db = await get_db_connection()
    try:
        cursor = await db.execute("SELECT * FROM users ORDER BY id DESC;")
        rows = await cursor.fetchall()
        return [_calculate_user_metrics(r) for r in rows]
    finally:
        await db.close()

async def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    db = await get_db_connection()
    try:
        cursor = await db.execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE;", (username,))
        row = await cursor.fetchone()
        return _calculate_user_metrics(row) if row else None
    finally:
        await db.close()

async def get_user_by_token(token: str) -> Optional[Dict[str, Any]]:
    db = await get_db_connection()
    try:
        cursor = await db.execute("SELECT * FROM users WHERE sub_token = ?;", (token,))
        row = await cursor.fetchone()
        return _calculate_user_metrics(row) if row else None
    finally:
        await db.close()

async def create_user(user: UserCreate) -> Dict[str, Any]:
    db = await get_db_connection()
    try:
        password = user.password or secrets.token_urlsafe(12)
        sub_token = secrets.token_urlsafe(16)
        max_bytes = int(user.traffic_limit_gb * (1024 ** 3))
        today_str = date.today().strftime("%Y-%m-%d")

        cursor = await db.execute("""
            INSERT INTO users (
                username, password, max_download_bytes, upload_bytes, download_bytes,
                expiration_days, account_creation_date, blocked, unlimited_user,
                max_ips, note, sub_token
            ) VALUES (?, ?, ?, 0, 0, ?, ?, 0, ?, ?, ?, ?);
        """, (
            user.username,
            password,
            max_bytes,
            user.expiration_days,
            today_str,
            1 if user.unlimited_user else 0,
            user.max_ips,
            user.note,
            sub_token
        ))
        await db.commit()
        return await get_user_by_username(user.username)
    finally:
        await db.close()

async def update_user(username: str, data: UserUpdate) -> Optional[Dict[str, Any]]:
    db = await get_db_connection()
    try:
        updates = []
        values = []

        if data.password is not None:
            updates.append("password = ?")
            values.append(data.password)
        if data.traffic_limit_gb is not None:
            updates.append("max_download_bytes = ?")
            values.append(int(data.traffic_limit_gb * (1024 ** 3)))
        if data.expiration_days is not None:
            updates.append("expiration_days = ?")
            values.append(data.expiration_days)
        if data.account_creation_date is not None:
            updates.append("account_creation_date = ?")
            values.append(data.account_creation_date)
        if data.blocked is not None:
            updates.append("blocked = ?")
            values.append(1 if data.blocked else 0)
        if data.unlimited_user is not None:
            updates.append("unlimited_user = ?")
            values.append(1 if data.unlimited_user else 0)
        if data.max_ips is not None:
            updates.append("max_ips = ?")
            values.append(data.max_ips)
        if data.note is not None:
            updates.append("note = ?")
            values.append(data.note)

        if not updates:
            return await get_user_by_username(username)

        updates.append("updated_at = CURRENT_TIMESTAMP")
        values.append(username)

        query = f"UPDATE users SET {', '.join(updates)} WHERE username = ? COLLATE NOCASE;"
        await db.execute(query, values)
        await db.commit()
        return await get_user_by_username(username)
    finally:
        await db.close()

async def reset_user_traffic(username: str) -> bool:
    db = await get_db_connection()
    try:
        today_str = date.today().strftime("%Y-%m-%d")
        await db.execute("""
            UPDATE users 
            SET upload_bytes = 0, download_bytes = 0, account_creation_date = ?, updated_at = CURRENT_TIMESTAMP
            WHERE username = ? COLLATE NOCASE;
        """, (today_str, username))
        await db.commit()
        return True
    finally:
        await db.close()

async def delete_user(username: str) -> bool:
    db = await get_db_connection()
    try:
        cursor = await db.execute("DELETE FROM users WHERE username = ? COLLATE NOCASE;", (username,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()

async def add_user_traffic(username: str, tx_bytes: int, rx_bytes: int):
    """Increment traffic for a user."""
    db = await get_db_connection()
    try:
        await db.execute("""
            UPDATE users 
            SET upload_bytes = upload_bytes + ?, download_bytes = download_bytes + ?, updated_at = CURRENT_TIMESTAMP
            WHERE username = ? COLLATE NOCASE;
        """, (tx_bytes, rx_bytes, username))
        await db.commit()
    finally:
        await db.close()

# ==================== SETTINGS CRUD ====================

async def get_setting(key: str, default: str = "") -> str:
    db = await get_db_connection()
    try:
        cursor = await db.execute("SELECT value FROM settings WHERE key = ?;", (key,))
        row = await cursor.fetchone()
        return row["value"] if row else default
    finally:
        await db.close()

async def get_all_settings() -> Dict[str, str]:
    db = await get_db_connection()
    try:
        cursor = await db.execute("SELECT key, value FROM settings;")
        rows = await cursor.fetchall()
        return {r["key"]: r["value"] for r in rows}
    finally:
        await db.close()

async def set_setting(key: str, value: str):
    db = await get_db_connection()
    try:
        await db.execute("""
            INSERT INTO settings (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value;
        """, (key, value))
        await db.commit()
    finally:
        await db.close()

async def set_settings(data: Dict[str, str]):
    db = await get_db_connection()
    try:
        for k, v in data.items():
            await db.execute("""
                INSERT INTO settings (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value;
            """, (k, str(v)))
        await db.commit()
    finally:
        await db.close()

# ==================== SESSIONS CRUD ====================

async def create_session(session_id: str, username: str, expires_at: datetime, ip: str, ua: str):
    db = await get_db_connection()
    try:
        await db.execute("""
            INSERT INTO admin_sessions (session_id, username, ip_address, user_agent, expires_at)
            VALUES (?, ?, ?, ?, ?);
        """, (session_id, username, ip, ua, expires_at.isoformat()))
        await db.commit()
    finally:
        await db.close()

async def get_session(session_id: str) -> Optional[Dict[str, Any]]:
    db = await get_db_connection()
    try:
        cursor = await db.execute("SELECT * FROM admin_sessions WHERE session_id = ?;", (session_id,))
        row = await cursor.fetchone()
        if not row:
            return None
        expires_at = datetime.fromisoformat(row["expires_at"])
        if datetime.now() > expires_at:
            await delete_session(session_id)
            return None
        return dict(row)
    finally:
        await db.close()

async def delete_session(session_id: str):
    db = await get_db_connection()
    try:
        await db.execute("DELETE FROM admin_sessions WHERE session_id = ?;", (session_id,))
        await db.commit()
    finally:
        await db.close()

async def cleanup_expired_sessions():
    db = await get_db_connection()
    try:
        now_str = datetime.now().isoformat()
        await db.execute("DELETE FROM admin_sessions WHERE expires_at < ?;", (now_str,))
        await db.commit()
    finally:
        await db.close()

# ==================== TRAFFIC METRICS ====================

async def record_traffic_metric(rate_up_kbps: float, rate_down_kbps: float, active_users: int):
    db = await get_db_connection()
    try:
        await db.execute("""
            INSERT INTO traffic_history (rate_up_kbps, rate_down_kbps, active_users)
            VALUES (?, ?, ?);
        """, (rate_up_kbps, rate_down_kbps, active_users))
        # Keep only the last 200 records to prevent growth
        await db.execute("""
            DELETE FROM traffic_history WHERE id NOT IN (
                SELECT id FROM traffic_history ORDER BY id DESC LIMIT 200
            );
        """)
        await db.commit()
    finally:
        await db.close()

async def get_traffic_history(limit: int = 30) -> List[Dict[str, Any]]:
    db = await get_db_connection()
    try:
        cursor = await db.execute("""
            SELECT * FROM traffic_history ORDER BY id DESC LIMIT ?;
        """, (limit,))
        rows = await cursor.fetchall()
        return [dict(r) for r in reversed(rows)]
    finally:
        await db.close()
