import aiosqlite
import secrets
from datetime import datetime, date, timedelta
from typing import List, Optional, Dict, Any
from app.database.connection import get_db_connection
from app.database.models import (
    UserCreate, UserUpdate, UserOut,
    ClientCreate, ClientUpdate, ClientOut,
    InboundModel, InboundCreate, InboundUpdate
)

def _calculate_client_metrics(row: aiosqlite.Row, online_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Calculate client and user metrics: status, quota, expiration, and online state."""
    data = dict(row)
    username = data.get("username", "")

    # Enable / Blocked state resolution
    if "enable" in data:
        data["enable"] = bool(data["enable"])
        data["blocked"] = not data["enable"]
    elif "blocked" in data:
        data["blocked"] = bool(data["blocked"])
        data["enable"] = not data["blocked"]
    else:
        data["enable"] = True
        data["blocked"] = False

    # Traffic quotas and totals
    upload = data.get("upload_bytes", 0)
    download = data.get("download_bytes", 0)
    used_bytes = upload + download
    total_bytes = data.get("total_bytes") if data.get("total_bytes") is not None else data.get("max_download_bytes", 0)
    expiry_time = data.get("expiry_time", 0) or data.get("c_expiry_time", 0) or 0
    exp_days = data.get("expiration_days", 0) or 0
    creation_str = data.get("account_creation_date", "")

    # If explicit limits are set (quota or expiry), the client is not unlimited
    has_explicit_limits = (total_bytes > 0) or (expiry_time > 0)
    data["unlimited_user"] = bool((data.get("unlimited_user") or data.get("u_unlimited", False)) and not has_explicit_limits)
    
    data["total_bytes"] = total_bytes
    data["max_download_bytes"] = total_bytes
    data["used_traffic_bytes"] = used_bytes
    data["used_traffic_gb"] = round(used_bytes / (1024 ** 3), 2)
    data["total_traffic_gb"] = round(total_bytes / (1024 ** 3), 2) if total_bytes > 0 else 0.0
    data["max_traffic_gb"] = data["total_traffic_gb"]
    data["percent_used"] = round((used_bytes / total_bytes) * 100, 1) if total_bytes > 0 else 0.0

    # Quota exceeded flag
    data["is_quota_exceeded"] = False
    data["is_limit_reached"] = False
    if not data["unlimited_user"] and total_bytes > 0 and used_bytes >= total_bytes:
        data["is_quota_exceeded"] = True
        data["is_limit_reached"] = True

    # Expiration calculation
    data["is_expired"] = False
    data["days_left"] = 999
    data["expiry_date_str"] = "Unlimited"
    
    now_ms = int(datetime.utcnow().timestamp() * 1000)

    if not data["unlimited_user"]:
        # 1. Absolute epoch timestamp expiration (3x-ui standard)
        if expiry_time > 0:
            if now_ms >= expiry_time:
                data["is_expired"] = True
                data["days_left"] = 0
            else:
                data["days_left"] = max(0, int((expiry_time - now_ms) / 86400000))
            try:
                data["expiry_date_str"] = datetime.utcfromtimestamp(expiry_time / 1000.0).strftime("%Y-%m-%d %H:%M")
            except Exception:
                data["expiry_date_str"] = "Invalid"
            data["expiry_time"] = expiry_time
        # 2. Relative expiration fallback for legacy users without expiry_time
        elif exp_days > 0 and creation_str:
            try:
                created = datetime.strptime(creation_str[:10], "%Y-%m-%d").date()
                expire_date = created + timedelta(days=exp_days)
                today = date.today()
                delta = (expire_date - today).days
                data["days_left"] = max(delta, 0)
                if delta < 0:
                    data["is_expired"] = True
                data["expiry_date_str"] = expire_date.strftime("%Y-%m-%d")
                exp_dt = datetime.combine(expire_date, datetime.min.time())
                data["expiry_time"] = int(exp_dt.timestamp() * 1000)
            except ValueError:
                pass
    else:
        data["is_expired"] = False
        data["days_left"] = 999
        data["expiry_date_str"] = "Unlimited"
        data["is_quota_exceeded"] = False
        data["is_limit_reached"] = False

    data["is_active"] = bool(data["enable"] and not data["is_expired"] and not data["is_quota_exceeded"])

    # Online status & IP count
    if online_data and username in online_data:
        conns = online_data[username]
        if isinstance(conns, list):
            unique_ips = {addr.split(":")[0] for addr in conns if ":" in addr}
            data["online_status"] = len(unique_ips) > 0
            data["current_ips"] = len(unique_ips)
        else:
            data["online_status"] = True
            data["current_ips"] = 1
    else:
        data["online_status"] = False
        data["current_ips"] = 0

    # Ensure backward compatible defaults
    if "expiration_days" not in data:
        data["expiration_days"] = data["days_left"]
    if "account_creation_date" not in data:
        data["account_creation_date"] = data.get("created_at", "")[:10] if data.get("created_at") else date.today().strftime("%Y-%m-%d")
    if "inbound_id" not in data:
        data["inbound_id"] = 1

    return data

def _calculate_user_metrics(row: aiosqlite.Row) -> Dict[str, Any]:
    """Helper for user metrics calculation with 3x-ui attributes."""
    return _calculate_client_metrics(row)

# ==================== INBOUNDS CRUD (3x-ui) ====================

async def get_all_inbounds() -> List[Dict[str, Any]]:
    """Retrieve all inbounds."""
    db = await get_db_connection()
    try:
        cursor = await db.execute("SELECT * FROM inbounds ORDER BY id ASC;")
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()

async def get_inbound_by_id(inbound_id: int = 1) -> Optional[Dict[str, Any]]:
    """Retrieve an inbound by ID."""
    db = await get_db_connection()
    try:
        cursor = await db.execute("SELECT * FROM inbounds WHERE id = ?;", (inbound_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()

async def create_inbound(data: InboundCreate) -> Dict[str, Any]:
    """Create a new inbound."""
    db = await get_db_connection()
    try:
        cursor = await db.execute("""
            INSERT INTO inbounds (
                tag, protocol, listen_ip, listen_port, port_hopping_enabled, port_hopping_range,
                tls_type, sni, cert_sha256, obfs_type, obfs_password, masquerade_type, masquerade_target,
                up_mbps, down_mbps, ignore_client_bandwidth, sniff_enabled, sniff_timeout, sniff_rewrite_domain
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            data.tag, data.protocol, data.listen_ip, data.listen_port,
            1 if data.port_hopping_enabled else 0, data.port_hopping_range,
            data.tls_type, data.sni, data.cert_sha256, data.obfs_type, data.obfs_password,
            data.masquerade_type, data.masquerade_target, data.up_mbps, data.down_mbps,
            1 if data.ignore_client_bandwidth else 0, 1 if data.sniff_enabled else 0,
            data.sniff_timeout, 1 if data.sniff_rewrite_domain else 0
        ))
        await db.commit()
        return await get_inbound_by_id(cursor.lastrowid)
    finally:
        await db.close()

async def update_inbound(inbound_id: int, data: InboundUpdate) -> Optional[Dict[str, Any]]:
    """Update an inbound's configuration."""
    db = await get_db_connection()
    try:
        updates = []
        values = []
        d = data.dict(exclude_unset=True)
        for k, v in d.items():
            if v is not None:
                if isinstance(v, bool):
                    v = 1 if v else 0
                updates.append(f"{k} = ?")
                values.append(v)
        if updates:
            updates.append("updated_at = CURRENT_TIMESTAMP")
            values.append(inbound_id)
            query = f"UPDATE inbounds SET {', '.join(updates)} WHERE id = ?;"
            await db.execute(query, values)
            await db.commit()
        return await get_inbound_by_id(inbound_id)
    finally:
        await db.close()

async def delete_inbound(inbound_id: int) -> bool:
    """Delete an inbound and its attached clients."""
    db = await get_db_connection()
    try:
        await db.execute("DELETE FROM users WHERE username IN (SELECT username FROM clients WHERE inbound_id = ?);", (inbound_id,))
        await db.execute("DELETE FROM clients WHERE inbound_id = ?;", (inbound_id,))
        cursor = await db.execute("DELETE FROM inbounds WHERE id = ?;", (inbound_id,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()

async def reset_inbound_traffic(inbound_id: int) -> bool:
    """Zero out traffic counters for all clients attached to an inbound."""
    db = await get_db_connection()
    try:
        cursor = await db.execute("""
            UPDATE clients SET upload_bytes = 0, download_bytes = 0, updated_at = CURRENT_TIMESTAMP
            WHERE inbound_id = ?;
        """, (inbound_id,))
        # Also mirror reset to legacy users
        await db.execute("""
            UPDATE users SET upload_bytes = 0, download_bytes = 0, updated_at = CURRENT_TIMESTAMP
            WHERE username IN (SELECT username FROM clients WHERE inbound_id = ?);
        """, (inbound_id,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()

# ==================== CLIENTS CRUD (3x-ui) ====================

async def get_all_clients(inbound_id: Optional[int] = None, online_data: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Retrieve all clients, optionally filtered by inbound_id, with calculated metrics."""
    db = await get_db_connection()
    try:
        if inbound_id is not None:
            cursor = await db.execute("""
                SELECT c.*, u.account_creation_date, u.expiration_days, u.unlimited_user as u_unlimited
                FROM clients c
                LEFT JOIN users u ON c.username = u.username COLLATE NOCASE
                WHERE c.inbound_id = ? ORDER BY c.id DESC;
            """, (inbound_id,))
        else:
            cursor = await db.execute("""
                SELECT c.*, u.account_creation_date, u.expiration_days, u.unlimited_user as u_unlimited
                FROM clients c
                LEFT JOIN users u ON c.username = u.username COLLATE NOCASE
                ORDER BY c.id DESC;
            """)
        rows = await cursor.fetchall()
        if not rows:
            cursor = await db.execute("SELECT * FROM users ORDER BY id DESC;")
            rows = await cursor.fetchall()
        return [_calculate_client_metrics(r, online_data) for r in rows]
    finally:
        await db.close()

async def get_client_by_id(client_id: int, online_data: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """Retrieve a client by integer ID."""
    db = await get_db_connection()
    try:
        cursor = await db.execute("""
            SELECT c.*, u.account_creation_date, u.expiration_days, u.unlimited_user as u_unlimited
            FROM clients c
            LEFT JOIN users u ON c.username = u.username COLLATE NOCASE
            WHERE c.id = ?;
        """, (client_id,))
        row = await cursor.fetchone()
        if not row:
            cursor = await db.execute("SELECT * FROM users WHERE id = ?;", (client_id,))
            row = await cursor.fetchone()
        return _calculate_client_metrics(row, online_data) if row else None
    finally:
        await db.close()

async def get_client_by_username(username: str, online_data: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """Retrieve a client by username."""
    db = await get_db_connection()
    try:
        cursor = await db.execute("""
            SELECT c.*, u.account_creation_date, u.expiration_days, u.unlimited_user as u_unlimited
            FROM clients c
            LEFT JOIN users u ON c.username = u.username COLLATE NOCASE
            WHERE c.username = ? COLLATE NOCASE;
        """, (username,))
        row = await cursor.fetchone()
        if not row:
            cursor = await db.execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE;", (username,))
            row = await cursor.fetchone()
        return _calculate_client_metrics(row, online_data) if row else None
    finally:
        await db.close()

async def get_client_by_token(token: str) -> Optional[Dict[str, Any]]:
    """Retrieve a client by subscription token."""
    db = await get_db_connection()
    try:
        cursor = await db.execute("""
            SELECT c.*, u.account_creation_date, u.expiration_days, u.unlimited_user as u_unlimited
            FROM clients c
            LEFT JOIN users u ON c.username = u.username COLLATE NOCASE
            WHERE c.sub_token = ?;
        """, (token,))
        row = await cursor.fetchone()
        if not row:
            cursor = await db.execute("SELECT * FROM users WHERE sub_token = ?;", (token,))
            row = await cursor.fetchone()
        return _calculate_client_metrics(row) if row else None
    finally:
        await db.close()

async def create_client(client: ClientCreate) -> Dict[str, Any]:
    """Create a new client and keep legacy users table in sync."""
    db = await get_db_connection()
    try:
        password = client.password or secrets.token_urlsafe(12)
        sub_token = secrets.token_urlsafe(16)
        
        # Determine total traffic quota
        if client.total_bytes is not None:
            total_bytes = client.total_bytes
        elif client.total_gb is not None:
            total_bytes = int(client.total_gb * (1024 ** 3))
        elif client.traffic_limit_gb is not None:
            total_bytes = int(client.traffic_limit_gb * (1024 ** 3))
        else:
            total_bytes = 0

        # Determine expiration time (epoch ms)
        now_ms = int(datetime.utcnow().timestamp() * 1000)
        if client.unlimited_user:
            expiry_time = 0
        elif client.expiry_time is not None:
            expiry_time = client.expiry_time
        elif client.expiration_days is not None and client.expiration_days > 0:
            expiry_time = now_ms + int(client.expiration_days * 86400 * 1000)
        else:
            expiry_time = 0

        has_limits = (total_bytes > 0) or (expiry_time > 0) or bool(client.expiration_days and client.expiration_days > 0)
        unlimited_val = 1 if (client.unlimited_user and not has_limits) else 0

        enable_val = 1 if client.enable else 0
        today_str = date.today().strftime("%Y-%m-%d")
        exp_days_val = max(0, int((expiry_time - now_ms) / (86400 * 1000))) if expiry_time > 0 else 0

        # 1. Insert into clients
        cursor = await db.execute("""
            INSERT INTO clients (
                inbound_id, username, password, enable, total_bytes, upload_bytes, download_bytes,
                expiry_time, max_ips, note, sub_token
            ) VALUES (?, ?, ?, ?, ?, 0, 0, ?, ?, ?, ?);
        """, (
            client.inbound_id, client.username, password, enable_val, total_bytes,
            expiry_time, client.max_ips, client.note, sub_token
        ))
        client_id = cursor.lastrowid

        # 2. Insert into users for backward compatibility
        await db.execute("""
            INSERT INTO users (
                username, password, max_download_bytes, upload_bytes, download_bytes,
                expiration_days, account_creation_date, blocked, unlimited_user,
                max_ips, note, sub_token
            ) VALUES (?, ?, ?, 0, 0, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(username) DO UPDATE SET
                password = excluded.password,
                max_download_bytes = excluded.max_download_bytes,
                blocked = excluded.blocked,
                expiration_days = excluded.expiration_days,
                max_ips = excluded.max_ips,
                note = excluded.note,
                sub_token = excluded.sub_token,
                updated_at = CURRENT_TIMESTAMP;
        """, (
            client.username, password, total_bytes, exp_days_val, today_str,
            1 - enable_val, unlimited_val, client.max_ips, client.note, sub_token
        ))

        await db.commit()
        return await get_client_by_id(client_id)
    finally:
        await db.close()

async def update_client(client_id_or_username: Any, data: ClientUpdate) -> Optional[Dict[str, Any]]:
    """Update client attributes across both clients and users tables."""
    existing = None
    if isinstance(client_id_or_username, int) or (isinstance(client_id_or_username, str) and client_id_or_username.isdigit()):
        existing = await get_client_by_id(int(client_id_or_username))
    if not existing:
        existing = await get_client_by_username(str(client_id_or_username))
    if not existing:
        return None

    username = existing["username"]
    db = await get_db_connection()
    try:
        updates_c = []
        values_c = []
        updates_u = []
        values_u = []

        if data.password is not None:
            updates_c.append("password = ?")
            values_c.append(data.password)
            updates_u.append("password = ?")
            values_u.append(data.password)

        # Enable / Blocked
        if data.enable is not None:
            updates_c.append("enable = ?")
            values_c.append(1 if data.enable else 0)
            updates_u.append("blocked = ?")
            values_u.append(0 if data.enable else 1)
        elif data.blocked is not None:
            updates_c.append("enable = ?")
            values_c.append(0 if data.blocked else 1)
            updates_u.append("blocked = ?")
            values_u.append(1 if data.blocked else 0)

        # Traffic limit
        new_total_bytes = None
        if data.total_bytes is not None:
            new_total_bytes = data.total_bytes
        elif data.total_gb is not None:
            new_total_bytes = int(data.total_gb * (1024 ** 3))
        elif data.traffic_limit_gb is not None:
            new_total_bytes = int(data.traffic_limit_gb * (1024 ** 3))

        if new_total_bytes is not None:
            updates_c.append("total_bytes = ?")
            values_c.append(new_total_bytes)
            updates_u.append("max_download_bytes = ?")
            values_u.append(new_total_bytes)

        # Expiry time
        if data.expiry_time is not None:
            updates_c.append("expiry_time = ?")
            values_c.append(data.expiry_time)
            now_ms = int(datetime.utcnow().timestamp() * 1000)
            exp_days = max(0, int((data.expiry_time - now_ms) / (86400 * 1000))) if data.expiry_time > 0 else 0
            updates_u.append("expiration_days = ?")
            values_u.append(exp_days)
        elif data.expiration_days is not None:
            now_ms = int(datetime.utcnow().timestamp() * 1000)
            exp_ms = (now_ms + data.expiration_days * 86400 * 1000) if data.expiration_days > 0 else 0
            updates_c.append("expiry_time = ?")
            values_c.append(exp_ms)
            updates_u.append("expiration_days = ?")
            values_u.append(data.expiration_days)

        if data.max_ips is not None:
            updates_c.append("max_ips = ?")
            values_c.append(data.max_ips)
            updates_u.append("max_ips = ?")
            values_u.append(data.max_ips)

        if data.note is not None:
            updates_c.append("note = ?")
            values_c.append(data.note)
            updates_u.append("note = ?")
            values_u.append(data.note)

        has_new_limits = (new_total_bytes is not None and new_total_bytes > 0) or \
                         (data.expiry_time is not None and data.expiry_time > 0) or \
                         (data.expiration_days is not None and data.expiration_days > 0)

        if data.unlimited_user is not None:
            updates_u.append("unlimited_user = ?")
            values_u.append(1 if (data.unlimited_user and not has_new_limits) else 0)
        elif has_new_limits:
            updates_u.append("unlimited_user = ?")
            values_u.append(0)

        if data.inbound_id is not None:
            updates_c.append("inbound_id = ?")
            values_c.append(data.inbound_id)

        if updates_c:
            updates_c.append("updated_at = CURRENT_TIMESTAMP")
            values_c.append(username)
            query_c = f"UPDATE clients SET {', '.join(updates_c)} WHERE username = ? COLLATE NOCASE;"
            await db.execute(query_c, values_c)

        if updates_u:
            updates_u.append("updated_at = CURRENT_TIMESTAMP")
            values_u.append(username)
            query_u = f"UPDATE users SET {', '.join(updates_u)} WHERE username = ? COLLATE NOCASE;"
            await db.execute(query_u, values_u)

        await db.commit()
        return await get_client_by_username(username)
    finally:
        await db.close()

async def toggle_client_enable(client_id_or_username: Any) -> Optional[Dict[str, Any]]:
    """1-click toggle client enable state."""
    client = None
    if isinstance(client_id_or_username, int) or (isinstance(client_id_or_username, str) and client_id_or_username.isdigit()):
        client = await get_client_by_id(int(client_id_or_username))
    if not client:
        client = await get_client_by_username(str(client_id_or_username))
    if not client:
        return None

    new_enable = not bool(client.get("enable", True))
    return await update_client(client["username"], ClientUpdate(enable=new_enable))

async def reset_client_traffic(client_id_or_username: Any) -> bool:
    """Pure traffic reset: zero out upload and download bytes only, preserving expiration."""
    client = None
    if isinstance(client_id_or_username, int) or (isinstance(client_id_or_username, str) and client_id_or_username.isdigit()):
        client = await get_client_by_id(int(client_id_or_username))
    if not client:
        client = await get_client_by_username(str(client_id_or_username))
    if not client:
        return False
    return await reset_user_traffic(client["username"])

async def delete_client(client_id_or_username: Any) -> bool:
    """Delete client from both clients and users tables."""
    client = None
    if isinstance(client_id_or_username, int) or (isinstance(client_id_or_username, str) and client_id_or_username.isdigit()):
        client = await get_client_by_id(int(client_id_or_username))
    if not client:
        client = await get_client_by_username(str(client_id_or_username))
    if not client:
        return False
    return await delete_user(client["username"])

# ==================== LEGACY USERS CRUD (Backward-Compatible) ====================

async def get_all_users() -> List[Dict[str, Any]]:
    """Retrieve all users with calculated metrics (delegates to get_all_clients)."""
    return await get_all_clients()

async def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Retrieve a single user by username (delegates to get_client_by_username)."""
    return await get_client_by_username(username)

async def get_user_by_token(token: str) -> Optional[Dict[str, Any]]:
    """Retrieve a single user by token (delegates to get_client_by_token)."""
    return await get_client_by_token(token)

async def create_user(user: UserCreate) -> Dict[str, Any]:
    """Create a user with backward compatibility."""
    client_in = ClientCreate(
        username=user.username,
        password=user.password,
        enable=user.enable and not getattr(user, "blocked", False),
        total_bytes=user.total_bytes,
        total_gb=user.total_gb,
        traffic_limit_gb=user.traffic_limit_gb,
        expiry_time=user.expiry_time,
        expiration_days=None if user.unlimited_user else user.expiration_days,
        unlimited_user=user.unlimited_user,
        max_ips=user.max_ips,
        note=user.note
    )
    return await create_client(client_in)

async def update_user(identifier: Any, data: UserUpdate) -> Optional[Dict[str, Any]]:
    """Update user by username or ID with backward compatibility."""
    client_update = ClientUpdate(
        password=data.password,
        enable=data.enable,
        blocked=data.blocked,
        total_bytes=data.total_bytes,
        total_gb=data.total_gb,
        traffic_limit_gb=data.traffic_limit_gb,
        expiry_time=data.expiry_time,
        expiration_days=data.expiration_days,
        unlimited_user=data.unlimited_user,
        max_ips=data.max_ips,
        note=data.note
    )
    return await update_client(identifier, client_update)


async def reset_user_traffic(username: str) -> bool:
    """Pure traffic reset: zero out upload_bytes and download_bytes only (no date modifications)."""
    db = await get_db_connection()
    try:
        c1 = await db.execute("""
            UPDATE users 
            SET upload_bytes = 0, download_bytes = 0, updated_at = CURRENT_TIMESTAMP
            WHERE username = ? COLLATE NOCASE;
        """, (username,))
        c2 = await db.execute("""
            UPDATE clients 
            SET upload_bytes = 0, download_bytes = 0, updated_at = CURRENT_TIMESTAMP
            WHERE username = ? COLLATE NOCASE;
        """, (username,))
        await db.commit()
        return (c1.rowcount > 0 or c2.rowcount > 0)
    finally:
        await db.close()

async def delete_user(username: str) -> bool:
    """Delete user from both users and clients tables."""
    db = await get_db_connection()
    try:
        c1 = await db.execute("DELETE FROM users WHERE username = ? COLLATE NOCASE;", (username,))
        c2 = await db.execute("DELETE FROM clients WHERE username = ? COLLATE NOCASE;", (username,))
        await db.commit()
        return (c1.rowcount > 0 or c2.rowcount > 0)
    finally:
        await db.close()

async def add_user_traffic(username: str, tx_bytes: int = 0, rx_bytes: int = 0):
    """
    Increment traffic for a user/client.
    Fixes inverted TX/RX bug:
    Hysteria tx (server transmit to client) = Client download_bytes.
    Hysteria rx (server receive from client) = Client upload_bytes.
    """
    db = await get_db_connection()
    try:
        await db.execute("""
            UPDATE users 
            SET upload_bytes = upload_bytes + ?, download_bytes = download_bytes + ?, updated_at = CURRENT_TIMESTAMP
            WHERE username = ? COLLATE NOCASE;
        """, (rx_bytes, tx_bytes, username))
        await db.execute("""
            UPDATE clients 
            SET upload_bytes = upload_bytes + ?, download_bytes = download_bytes + ?, updated_at = CURRENT_TIMESTAMP
            WHERE username = ? COLLATE NOCASE;
        """, (rx_bytes, tx_bytes, username))
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

INBOUND_SYNC_KEYS = {
    "listen_port", "port_hopping_enabled", "port_hopping_range",
    "tls_type", "sni", "cert_sha256", "obfs_type", "obfs_password",
    "masquerade_type", "masquerade_target", "up_mbps", "down_mbps",
    "ignore_client_bandwidth", "sniff_enable", "sniff_enabled",
    "sniff_timeout", "sniff_rewrite_domain"
}

async def _sync_default_inbound_from_settings(db):
    """Keep inbounds(id=1) strictly synchronized with settings table."""
    try:
        cursor = await db.execute("SELECT key, value FROM settings;")
        rows = await cursor.fetchall()
        s = {r["key"]: r["value"] for r in rows}

        listen_port = int(s.get("listen_port", 443)) if str(s.get("listen_port", "443")).isdigit() else 443
        hop_on = 1 if str(s.get("port_hopping_enabled", "1")).lower() in ("1", "true") else 0
        hop_range = s.get("port_hopping_range", "20000:50000")
        tls_type = s.get("tls_type", "self_signed_ip")
        sni = s.get("sni", "bing.com")
        cert_sha256 = s.get("cert_sha256", "")
        obfs_type = s.get("obfs_type", "salamander")
        obfs_password = s.get("obfs_password", "")
        masq_type = s.get("masquerade_type", "proxy")
        masq_target = s.get("masquerade_target", "https://bing.com")
        up_mbps = int(s.get("up_mbps", 200)) if str(s.get("up_mbps", "200")).isdigit() else 200
        down_mbps = int(s.get("down_mbps", 200)) if str(s.get("down_mbps", "200")).isdigit() else 200
        ignore_bw = 1 if str(s.get("ignore_client_bandwidth", "0")).lower() in ("1", "true") else 0
        sniff_raw = s.get("sniff_enable", s.get("sniff_enabled", "1"))
        sniff_on = 1 if str(sniff_raw).lower() in ("1", "true") else 0
        sniff_timeout = s.get("sniff_timeout", "2s")
        sniff_rewrite = 1 if str(s.get("sniff_rewrite_domain", "1")).lower() in ("1", "true") else 0

        await db.execute("""
            UPDATE inbounds SET
                listen_port = ?,
                port_hopping_enabled = ?,
                port_hopping_range = ?,
                tls_type = ?,
                sni = ?,
                cert_sha256 = ?,
                obfs_type = ?,
                obfs_password = ?,
                masquerade_type = ?,
                masquerade_target = ?,
                up_mbps = ?,
                down_mbps = ?,
                ignore_client_bandwidth = ?,
                sniff_enabled = ?,
                sniff_timeout = ?,
                sniff_rewrite_domain = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = 1;
        """, (
            listen_port, hop_on, hop_range, tls_type, sni, cert_sha256,
            obfs_type, obfs_password, masq_type, masq_target,
            up_mbps, down_mbps, ignore_bw, sniff_on, sniff_timeout, sniff_rewrite
        ))
    except Exception as e:
        logger.warning(f"Failed to sync default inbound from settings: {e}")

async def set_setting(key: str, value: str):
    db = await get_db_connection()
    try:
        await db.execute("""
            INSERT INTO settings (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value;
        """, (key, str(value)))
        if key in INBOUND_SYNC_KEYS:
            await _sync_default_inbound_from_settings(db)
        await db.commit()
    finally:
        await db.close()

async def set_settings(data: Dict[str, str]):
    db = await get_db_connection()
    try:
        needs_sync = False
        for k, v in data.items():
            if k in INBOUND_SYNC_KEYS:
                needs_sync = True
            await db.execute("""
                INSERT INTO settings (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value;
            """, (k, str(v)))
        if needs_sync:
            await _sync_default_inbound_from_settings(db)
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

# ==================== ROUTING RULES CRUD (Milestone M2) ====================
from app.database.routing_crud import (
    get_routing_rules,
    get_routing_rule_by_id,
    create_routing_rule,
    update_routing_rule,
    delete_routing_rule,
    toggle_routing_rule,
    reorder_routing_rules
)

