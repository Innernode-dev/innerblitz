import aiosqlite
import logging
import os
import secrets
from datetime import datetime, timedelta, date
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

        # 5. Inbounds table (3x-ui Inbound model)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS inbounds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tag TEXT NOT NULL DEFAULT 'Hysteria-Main',
                protocol TEXT NOT NULL DEFAULT 'hysteria2',
                listen_ip TEXT NOT NULL DEFAULT '0.0.0.0',
                listen_port INTEGER NOT NULL DEFAULT 443,
                port_hopping_enabled INTEGER NOT NULL DEFAULT 1,
                port_hopping_range TEXT NOT NULL DEFAULT '20000:50000',
                tls_type TEXT NOT NULL DEFAULT 'self_signed_ip',
                sni TEXT NOT NULL DEFAULT 'bing.com',
                cert_sha256 TEXT NOT NULL DEFAULT '',
                obfs_type TEXT NOT NULL DEFAULT 'salamander',
                obfs_password TEXT NOT NULL DEFAULT '',
                masquerade_type TEXT NOT NULL DEFAULT 'proxy',
                masquerade_target TEXT NOT NULL DEFAULT 'https://bing.com',
                up_mbps INTEGER NOT NULL DEFAULT 200,
                down_mbps INTEGER NOT NULL DEFAULT 200,
                ignore_client_bandwidth INTEGER NOT NULL DEFAULT 0,
                sniff_enabled INTEGER NOT NULL DEFAULT 1,
                sniff_timeout TEXT NOT NULL DEFAULT '2s',
                sniff_rewrite_domain INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # 6. Clients table (3x-ui Client model with epoch ms expiry)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                inbound_id INTEGER NOT NULL DEFAULT 1,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password TEXT NOT NULL,
                enable INTEGER NOT NULL DEFAULT 1,
                total_bytes INTEGER NOT NULL DEFAULT 0,
                upload_bytes INTEGER NOT NULL DEFAULT 0,
                download_bytes INTEGER NOT NULL DEFAULT 0,
                expiry_time INTEGER NOT NULL DEFAULT 0,
                max_ips INTEGER NOT NULL DEFAULT 0,
                note TEXT NOT NULL DEFAULT '',
                sub_token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        await db.execute("CREATE INDEX IF NOT EXISTS idx_clients_inbound ON clients(inbound_id);")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_clients_username ON clients(username);")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_clients_sub_token ON clients(sub_token);")

        # 7. Routing rules table (custom dynamic routing engine)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS routing_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                priority INTEGER NOT NULL DEFAULT 100,
                name TEXT NOT NULL,
                action TEXT NOT NULL CHECK(action IN ('direct', 'warp', 'block')),
                rule_type TEXT NOT NULL CHECK(rule_type IN ('domain', 'suffix', 'keyword', 'ip_cidr', 'geoip', 'geosite')),
                rule_values TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                description TEXT NOT NULL DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        await db.execute("CREATE INDEX IF NOT EXISTS idx_routing_rules_priority ON routing_rules(priority ASC, id ASC);")

        # 8. Populate initial default settings if empty
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
                ("panel_ssl_mode", "http"),
                ("sni", "bing.com"),
                ("custom_firewall_ports", "[]"),
                ("routing_global_outbound", "direct"),
                ("routing_ru", "direct"),
                ("routing_openai", "warp"),
                ("routing_discord", "warp"),
                ("routing_youtube", "warp"),
                ("routing_telegram", "direct"),
                ("routing_netflix", "warp"),
                ("routing_p2p", "block"),
                ("routing_ads", "1"),
                ("routing_win_spy", "1"),
            ]
            await db.executemany("INSERT INTO settings (key, value) VALUES (?, ?);", default_settings)
            logger.info("Default settings and admin account created.")

        # Ensure critical keys exist even on upgraded databases
        critical_defaults = [
            ("sni", "bing.com"),
            ("custom_firewall_ports", "[]"),
            ("panel_ssl_mode", "http"),
            ("port_hopping_enabled", "1"),
            ("port_hopping_range", "20000:50000"),
            ("listen_port", "443"),
            ("tls_type", "self_signed_ip"),
            ("obfs_type", "salamander"),
            ("masquerade_type", "proxy"),
            ("masquerade_target", "https://bing.com"),
            ("routing_global_outbound", "direct"),
            ("routing_ru", "direct"),
            ("routing_openai", "warp"),
            ("routing_discord", "warp"),
            ("routing_youtube", "warp"),
            ("routing_telegram", "direct"),
            ("routing_netflix", "warp"),
            ("routing_p2p", "block"),
            ("routing_ads", "1"),
            ("routing_win_spy", "1"),
        ]
        for k, v in critical_defaults:
            await db.execute("""
                INSERT INTO settings (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO NOTHING;
            """, (k, v))

        # Seed default inbound if table is empty
        cursor = await db.execute("SELECT COUNT(*) as count FROM inbounds;")
        ib_row = await cursor.fetchone()
        if ib_row and ib_row["count"] == 0:
            cursor = await db.execute("SELECT key, value FROM settings;")
            s_rows = await cursor.fetchall()
            s_map = {r["key"]: r["value"] for r in s_rows}
            
            listen_port = int(s_map.get("listen_port", 443)) if s_map.get("listen_port", "").isdigit() else 443
            port_hopping_enabled = 1 if str(s_map.get("port_hopping_enabled", "1")).lower() in ("1", "true") else 0
            port_hopping_range = s_map.get("port_hopping_range", "20000:50000")
            tls_type = s_map.get("tls_type", "self_signed_ip")
            sni = s_map.get("sni", "bing.com")
            cert_sha256 = s_map.get("cert_sha256", "")
            obfs_type = s_map.get("obfs_type", "salamander")
            obfs_password = s_map.get("obfs_password", "")
            masquerade_type = s_map.get("masquerade_type", "proxy")
            masquerade_target = s_map.get("masquerade_target", "https://bing.com")
            up_mbps = int(s_map.get("up_mbps", 200)) if s_map.get("up_mbps", "").isdigit() else 200
            down_mbps = int(s_map.get("down_mbps", 200)) if s_map.get("down_mbps", "").isdigit() else 200
            ignore_client_bandwidth = 1 if str(s_map.get("ignore_client_bandwidth", "0")).lower() in ("1", "true") else 0

            await db.execute("""
                INSERT INTO inbounds (
                    id, tag, protocol, listen_ip, listen_port, port_hopping_enabled, port_hopping_range,
                    tls_type, sni, cert_sha256, obfs_type, obfs_password, masquerade_type, masquerade_target,
                    up_mbps, down_mbps, ignore_client_bandwidth, sniff_enabled, sniff_timeout, sniff_rewrite_domain
                ) VALUES (
                    1, 'Hysteria-Main', 'hysteria2', '0.0.0.0', ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, 1, '2s', 0
                );
            """, (
                listen_port, port_hopping_enabled, port_hopping_range,
                tls_type, sni, cert_sha256, obfs_type, obfs_password, masquerade_type, masquerade_target,
                up_mbps, down_mbps, ignore_client_bandwidth
            ))
            logger.info("Default Hysteria-Main inbound created.")

        # Seamless SQLite migration: migrate legacy users table rows into clients table
        try:
            cursor = await db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
            if await cursor.fetchone():
                cursor = await db.execute("SELECT * FROM users;")
                users_rows = await cursor.fetchall()
                for u in users_rows:
                    try:
                        u_dict = dict(u)
                        uname = u_dict.get("username") or ""
                        if not uname:
                            continue
                        chk = await db.execute("SELECT id FROM clients WHERE username = ? COLLATE NOCASE;", (uname,))
                        if not await chk.fetchone():
                            enable_val = 0 if (u_dict.get("blocked") or 0) else 1
                            total_bytes_val = u_dict.get("max_download_bytes") or 0
                            exp_days = u_dict.get("expiration_days") or 0
                            is_unlimited = bool(u_dict.get("unlimited_user") or 0)
                            expiry_time_val = 0
                            if not is_unlimited and exp_days > 0:
                                try:
                                    created_str = u_dict.get("account_creation_date") or ""
                                    c_date = datetime.strptime(created_str[:10], "%Y-%m-%d").date()
                                    exp_date = c_date + timedelta(days=exp_days)
                                    exp_dt = datetime.combine(exp_date, datetime.min.time())
                                    expiry_time_val = int(exp_dt.timestamp() * 1000)
                                except Exception:
                                    expiry_time_val = 0

                            await db.execute("""
                                INSERT INTO clients (
                                    inbound_id, username, password, enable, total_bytes,
                                    upload_bytes, download_bytes, expiry_time, max_ips, note, sub_token,
                                    created_at, updated_at
                                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                            """, (
                                uname,
                                u_dict.get("password") or "",
                                enable_val,
                                total_bytes_val,
                                u_dict.get("upload_bytes") or 0,
                                u_dict.get("download_bytes") or 0,
                                expiry_time_val,
                                u_dict.get("max_ips") or 0,
                                u_dict.get("note") or "",
                                u_dict.get("sub_token") or secrets.token_urlsafe(16),
                                u_dict.get("created_at") or datetime.utcnow().isoformat(),
                                u_dict.get("updated_at") or datetime.utcnow().isoformat()
                            ))
                            logger.info(f"Migrated legacy user '{uname}' to clients table.")
                    except Exception as row_err:
                        logger.warning(f"Notice during migrating user '{u_dict.get('username', '')}': {row_err}")
        except Exception as e:
            logger.warning(f"Notice during users to clients migration: {e}")

        await db.commit()
    finally:
        await db.close()
