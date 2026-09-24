import aiosqlite
import logging
import os
import secrets
from pathlib import Path
from typing import AsyncGenerator
from app.config import settings

logger = logging.getLogger("innerblitz.db")

async def get_db_connection() -> aiosqlite.Connection:
    """Connect to SQLite database with optimized pragmas."""
    Path(settings.DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    db = await aiosqlite.connect(settings.DB_PATH)
    db.row_factory = aiosqlite.Row
    # Enable WAL mode for high concurrency & foreign keys
    await db.execute("PRAGMA journal_mode = WAL;")
    await db.execute("PRAGMA busy_timeout = 5000;")
    await db.execute("PRAGMA foreign_keys = ON;")
    return db

async def init_db():
    """Initialize database tables, default settings and admin account."""
    db = await get_db_connection()
    try:
        # 1. Users table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password TEXT NOT NULL,
                max_download_bytes INTEGER DEFAULT 0,
                upload_bytes INTEGER DEFAULT 0,
                download_bytes INTEGER DEFAULT 0,
                expiration_days INTEGER DEFAULT 30,
                account_creation_date TEXT NOT NULL,
                blocked INTEGER DEFAULT 0,
                unlimited_user INTEGER DEFAULT 0,
                max_ips INTEGER DEFAULT 0,
                note TEXT DEFAULT '',
                sub_token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        await db.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_users_sub_token ON users(sub_token);")

        # 2. Settings table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        """)

        # 3. Admin sessions table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS admin_sessions (
                session_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL
            );
        """)

        # 4. Traffic metrics history (for live charts)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS traffic_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                rate_up_kbps REAL DEFAULT 0,
                rate_down_kbps REAL DEFAULT 0,
                active_users INTEGER DEFAULT 0
            );
        """)

        # 5. Populate initial default settings if empty
        cursor = await db.execute("SELECT COUNT(*) as count FROM settings;")
        row = await cursor.fetchone()
        if row and row["count"] == 0:
            import bcrypt
            from app.core.security import generate_secret_path
            default_salt = bcrypt.gensalt(rounds=12)
            default_password_hash = bcrypt.hashpw(b"admin", default_salt).decode("utf-8")
            traffic_uuid = secrets.token_hex(16)
            obfs_pwd = secrets.token_urlsafe(16)
            rand_secret_path = generate_secret_path()
            rand_panel_port = str(secrets.randbelow(40000) + 20000)

            default_settings = [
                ("admin_username", "admin"),
                ("admin_password_hash", default_password_hash),
                ("totp_secret", ""),
                ("totp_enabled", "0"),
                ("tg_bot_token", ""),
                ("tg_admin_chat_id", ""),
                ("tg_2fa_enabled", "0"),
                ("tg_notifications_enabled", "0"),
                ("server_ip", ""),
                ("server_domain", ""),
                ("listen_port", "443"),
                ("port_hopping_enabled", "1"),
                ("port_hopping_range", "20000:50000"),
                ("tls_type", "self_signed_ip"),
                ("cert_sha256", ""),
                ("obfs_type", "salamander"),
                ("obfs_password", obfs_pwd),
                ("mimic_enabled", "0"),
                ("masquerade_type", "proxy"),
                ("masquerade_target", "https://bing.com"),
                ("traffic_secret", traffic_uuid),
                ("up_mbps", "200"),
                ("down_mbps", "200"),
                ("ignore_client_bandwidth", "0"),
                ("preset", "anti-dpi"),
                ("decoy_enabled", "1"),
                ("panel_port", rand_panel_port),
                ("panel_secret_path", rand_secret_path),
            ]
            await db.executemany("INSERT INTO settings (key, value) VALUES (?, ?);", default_settings)
            logger.info("Default settings and admin account created.")

        await db.commit()
    finally:
        await db.close()
