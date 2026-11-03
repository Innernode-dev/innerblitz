"""
InnerBlitz Hysteria 2 Next-Gen Panel (3x-ui Overhaul)
Adversarial Stress Test Suite: Challenger 2 (Milestone M1 Empirical Verification)

Focus Areas:
1. Legacy SQLite Database Migration (Data integrity, blocked, expired, unlimited, ISO dates, NULL fields, idempotency).
2. SQLite WAL High-Concurrency Stress (50 concurrent traffic increments, mixed CRUD/Auth/Traffic storm).
3. Subscription Profile Integrity & Boundaries (hy2:// URIs, Clash Meta YAML, Sing-box JSON, special chars escaping).
4. Subscription-Userinfo Header & Client Expiration Drift.
"""

import asyncio
import os
import shutil
import tempfile
import unittest
import urllib.parse
from datetime import datetime, date, timedelta
from pathlib import Path
from typing import Dict, Any

import aiosqlite
import yaml
from starlette.testclient import TestClient

from app.config import settings
from app.database import crud
from app.database.connection import init_db, get_db_connection
from app.database.models import ClientCreate, ClientUpdate
from app.core.subscription import build_hy2_uri, build_clash_yaml, build_singbox_json, build_base64_sub
from app.core.auth import authenticate_client
from app.api.sub_routes import _get_sub_userinfo_header
from tests.e2e.harness import IsolatedEnvironment, OpaqueE2ETestCase


class TestChallenger2SQLiteMigration(unittest.TestCase):
    """Adversarial stress-testing of legacy SQLite migration into 3x-ui schema."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="innerblitz_migr_test_")
        self.old_base_dir = settings.BASE_DIR
        settings.BASE_DIR = self.temp_dir
        os.environ["INNERBLITZ_DIR"] = self.temp_dir
        self.db_path = settings.DB_PATH

    def tearDown(self):
        settings.BASE_DIR = self.old_base_dir
        if "INNERBLITZ_DIR" in os.environ:
            del os.environ["INNERBLITZ_DIR"]
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    async def _create_legacy_database(self):
        """Creates legacy database pre-populated with varied user types and edge cases."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        db = await aiosqlite.connect(self.db_path)
        try:
            # Create legacy users table (as existed before M1 3x-ui overhaul)
            await db.execute("""
                CREATE TABLE users (
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

            # Pre-populate legacy users
            legacy_users = [
                # 1. Standard active user with quota and traffic
                (
                    "active_user", "pass_active123",
                    10 * 1024 * 1024 * 1024,  # 10 GB
                    1024 * 1024 * 1024,       # 1 GB up
                    2 * 1024 * 1024 * 1024,   # 2 GB down
                    30, "2026-11-01", 0, 0, 2, "Standard Active Note", "tok_active_01"
                ),
                # 2. Blocked user
                (
                    "blocked_user", "pass_blocked",
                    5 * 1024 * 1024 * 1024,
                    500 * 1024 * 1024, 500 * 1024 * 1024,
                    15, "2026-10-15", 1, 0, 1, "Blocked User Note", "tok_blocked_02"
                ),
                # 3. Expired user (created in 2020 with 10 days expiry)
                (
                    "expired_user", "pass_expired",
                    0, 1000, 2000,
                    10, "2020-01-01", 0, 0, 1, "Expired Legacy User", "tok_expired_03"
                ),
                # 4. Unlimited user
                (
                    "unlimited_user", "pass_unlimited",
                    0, 50 * 1024 * 1024 * 1024, 100 * 1024 * 1024 * 1024,
                    0, "2026-01-01", 0, 1, 0, "Unlimited VIP", "tok_unlim_04"
                ),
                # 5. User with ISO8601 timestamp with 'T' and timezone
                (
                    "iso_date_user", "pass_iso",
                    20 * 1024 * 1024 * 1024, 0, 0,
                    60, "2026-09-15T14:30:00Z", 0, 0, 3, "ISO Timestamp User", "tok_iso_05"
                ),
                # 6. User with malformed date
                (
                    "malformed_date_user", "pass_bad_date",
                    1024 * 1024, 100, 200,
                    30, "invalid-date-string", 0, 0, 1, "Bad Date User", "tok_bad_date_06"
                ),
                # 7. User with special characters in username and symbols in password
                (
                    "client-user.special_07", "P@ssw0rd!#%^&*()",
                    1024 * 1024 * 1024, 1000, 5000,
                    30, "2026-10-01", 0, 0, 4, "Special Chars Client", "tok_special_07"
                ),
                # 8. User with empty note and negative expiration days edge case
                (
                    "edge_case_user", "pass_edge",
                    0, 0, 0,
                    -5, "2026-10-01", 0, 0, 0, "", "tok_edge_08"
                )
            ]

            await db.executemany("""
                INSERT INTO users (
                    username, password, max_download_bytes, upload_bytes, download_bytes,
                    expiration_days, account_creation_date, blocked, unlimited_user,
                    max_ips, note, sub_token
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, legacy_users)

            await db.commit()
        finally:
            await db.close()

    def test_legacy_migration_data_integrity_and_idempotency(self):
        """Verify migration converts all legacy users to clients without loss or corruption."""
        # 1. Create legacy DB
        asyncio.run(self._create_legacy_database())

        # 2. Run init_db() migration
        asyncio.run(init_db())

        # 3. Inspect database content
        async def _verify_migration():
            db = await get_db_connection()
            try:
                # Inbounds table checks
                ib_cursor = await db.execute("SELECT * FROM inbounds;")
                inbounds = await ib_cursor.fetchall()
                self.assertEqual(len(inbounds), 1, "Expected exactly 1 default inbound after migration")
                self.assertEqual(inbounds[0]["tag"], "Hysteria-Main")
                self.assertEqual(inbounds[0]["id"], 1)

                # Clients table checks
                cl_cursor = await db.execute("SELECT * FROM clients ORDER BY id ASC;")
                clients = [dict(c) for c in await cl_cursor.fetchall()]
                self.assertEqual(len(clients), 8, f"Expected 8 clients migrated, got {len(clients)}")

                client_map = {c["username"].lower(): c for c in clients}

                # Verify active_user
                c1 = client_map["active_user"]
                self.assertEqual(c1["password"], "pass_active123")
                self.assertEqual(c1["enable"], 1)
                self.assertEqual(c1["total_bytes"], 10 * 1024 * 1024 * 1024)
                self.assertEqual(c1["upload_bytes"], 1024 * 1024 * 1024)
                self.assertEqual(c1["download_bytes"], 2 * 1024 * 1024 * 1024)
                self.assertEqual(c1["max_ips"], 2)
                self.assertEqual(c1["note"], "Standard Active Note")
                self.assertEqual(c1["sub_token"], "tok_active_01")
                self.assertGreater(c1["expiry_time"], 0)

                # Verify blocked_user -> enable must be 0
                c2 = client_map["blocked_user"]
                self.assertEqual(c2["enable"], 0, "Blocked user must have enable=0 in clients table")
                self.assertEqual(c2["sub_token"], "tok_blocked_02")

                # Verify expired_user -> expiry_time must match 2020-01-11
                c3 = client_map["expired_user"]
                exp_dt = datetime(2020, 1, 11)
                expected_ms = int(exp_dt.timestamp() * 1000)
                self.assertEqual(c3["expiry_time"], expected_ms)

                # Verify unlimited_user -> expiry_time must be 0 (unlimited)
                c4 = client_map["unlimited_user"]
                self.assertEqual(c4["expiry_time"], 0, "Unlimited user should have expiry_time=0")

                # Verify iso_date_user -> parsed date without crashing
                c5 = client_map["iso_date_user"]
                self.assertGreater(c5["expiry_time"], 0)

                # Verify malformed_date_user -> fallback to 0 without crashing
                c6 = client_map["malformed_date_user"]
                self.assertEqual(c6["expiry_time"], 0)

                # Verify special chars user
                c7 = client_map["client-user.special_07"]
                self.assertEqual(c7["password"], "P@ssw0rd!#%^&*()")
                self.assertEqual(c7["sub_token"], "tok_special_07")

            finally:
                await db.close()

        asyncio.run(_verify_migration())

        # 4. Verify IDEMPOTENCY: run init_db() a second and third time
        asyncio.run(init_db())
        asyncio.run(init_db())

        async def _verify_idempotency():
            db = await get_db_connection()
            try:
                cl_cursor = await db.execute("SELECT COUNT(*) as cnt FROM clients;")
                row = await cl_cursor.fetchone()
                self.assertEqual(row["cnt"], 8, "Multiple init_db() calls must not duplicate client records")

                ib_cursor = await db.execute("SELECT COUNT(*) as cnt FROM inbounds;")
                row = await ib_cursor.fetchone()
                self.assertEqual(row["cnt"], 1, "Multiple init_db() calls must not duplicate inbounds")
            finally:
                await db.close()

        asyncio.run(_verify_idempotency())

    def test_migration_null_column_abortion(self):
        """
        Adversarial Test: Legacy database where optional columns contain NULL values.
        Tests whether a NULL column in one record causes silent migration abort for subsequent records.
        """
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        async def _setup_null_db():
            db = await aiosqlite.connect(self.db_path)
            try:
                await db.execute("""
                    CREATE TABLE users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                        password TEXT NOT NULL,
                        max_download_bytes INTEGER,
                        upload_bytes INTEGER,
                        download_bytes INTEGER,
                        expiration_days INTEGER,
                        account_creation_date TEXT,
                        blocked INTEGER,
                        unlimited_user INTEGER,
                        max_ips INTEGER,
                        note TEXT,
                        sub_token TEXT UNIQUE NOT NULL
                    );
                """)
                # User 1: Has NULL upload_bytes and download_bytes
                await db.execute("""
                    INSERT INTO users (username, password, max_download_bytes, upload_bytes, download_bytes, expiration_days, account_creation_date, blocked, unlimited_user, max_ips, note, sub_token)
                    VALUES ('null_metrics_user', 'pass1', 1000, NULL, NULL, 30, '2026-11-01', 0, 0, NULL, NULL, 'tok_null_1');
                """)
                # User 2: Normal user following User 1
                await db.execute("""
                    INSERT INTO users (username, password, max_download_bytes, upload_bytes, download_bytes, expiration_days, account_creation_date, blocked, unlimited_user, max_ips, note, sub_token)
                    VALUES ('subsequent_user', 'pass2', 2000, 100, 200, 30, '2026-11-01', 0, 0, 1, 'note2', 'tok_subseq_2');
                """)
                await db.commit()
            finally:
                await db.close()

        asyncio.run(_setup_null_db())
        asyncio.run(init_db())

        async def _check_migration():
            db = await get_db_connection()
            try:
                # Check if subsequent_user was migrated or if null_metrics_user aborted the loop
                c1 = await (await db.execute("SELECT * FROM clients WHERE username = 'null_metrics_user';")).fetchone()
                c2 = await (await db.execute("SELECT * FROM clients WHERE username = 'subsequent_user';")).fetchone()
                return c1, c2
            finally:
                await db.close()

        c1, c2 = asyncio.run(_check_migration())
        # If NULL values triggered IntegrityError, c1 would fail and c2 would be skipped
        self.assertIsNotNone(c1, "User with NULL columns should be safely migrated with 0/empty defaults")
        self.assertIsNotNone(c2, "Subsequent user must be migrated even if previous record had NULL fields")


class TestChallenger2Concurrency(OpaqueE2ETestCase):
    """High concurrency stress testing on SQLite WAL mode."""

    def test_heavy_concurrent_traffic_accumulation(self):
        """
        Stress test: 50 concurrent async tasks incrementing traffic simultaneously.
        Verifies:
        1. No 'database is locked' errors under WAL mode.
        2. Absolute atomicity: sum of increments matches exact final total.
        """
        user = self.create_test_user("concurrency_user", "pass_concurrent")
        username = user["username"]

        num_tasks = 50
        rx_step = 10000  # 10 KB (upload)
        tx_step = 25000  # 25 KB (download)

        async def _task():
            await crud.add_user_traffic(username, tx_bytes=tx_step, rx_bytes=rx_step)

        async def _run_concurrently():
            await asyncio.gather(*[_task() for _ in range(num_tasks)])

        self.run_async(_run_concurrently())

        # Inspect accumulated totals
        refreshed = self.run_async(crud.get_client_by_username(username))
        expected_upload = num_tasks * rx_step
        expected_download = num_tasks * tx_step

        self.assertEqual(
            refreshed["upload_bytes"], expected_upload,
            f"Expected {expected_upload} upload_bytes, got {refreshed['upload_bytes']}"
        )
        self.assertEqual(
            refreshed["download_bytes"], expected_download,
            f"Expected {expected_download} download_bytes, got {refreshed['download_bytes']}"
        )

    def test_concurrent_mixed_crud_traffic_and_auth(self):
        """
        Stress test: 40 concurrent operations mixing authentication, traffic updates,
        client creations, updates, and reads simultaneously.
        """
        for i in range(5):
            self.create_test_user(f"base_user_{i}", f"pass_{i}")

        async def _auth_task(i):
            uname = f"base_user_{i % 5}"
            ok, uid, msg = await authenticate_client(f"{uname}:pass_{i % 5}")
            self.assertTrue(ok, f"Auth failed for {uname}: {msg}")

        async def _traffic_task(i):
            uname = f"base_user_{i % 5}"
            await crud.add_user_traffic(uname, tx_bytes=500, rx_bytes=200)

        async def _read_task():
            clients = await crud.get_all_clients()
            self.assertGreaterEqual(len(clients), 5)

        async def _create_task(i):
            new_client = ClientCreate(
                username=f"concurrent_new_{i}",
                password=f"pass_new_{i}",
                total_bytes=100000
            )
            created = await crud.create_client(new_client)
            self.assertEqual(created["username"], f"concurrent_new_{i}")

        async def _run_mixed_storm():
            tasks = []
            for i in range(10):
                tasks.append(_auth_task(i))
                tasks.append(_traffic_task(i))
                tasks.append(_read_task())
                tasks.append(_create_task(i))
            await asyncio.gather(*tasks)

        self.run_async(_run_mixed_storm())


class TestChallenger2SubscriptionProfiles(OpaqueE2ETestCase):
    """Stress testing of subscription exports, format validation, and client lifecycle states."""

    def test_hy2_uri_structure_and_parameters(self):
        """Verify hy2:// URI contains all required components and is properly parseable."""
        user = self.create_test_user("test_sub_client", "PassWord123")
        self.run_async(crud.set_settings({
            "server_domain": "hysteria.example.com",
            "listen_port": "443",
            "port_hopping_enabled": "1",
            "port_hopping_range": "25000:35000",
            "obfs_type": "salamander",
            "obfs_password": "obfs_secret_token",
            "sni": "custom.sni.com",
            "cert_sha256": "ab12cd34ef56"
        }))

        settings_dict = self.run_async(crud.get_all_settings())
        client_data = self.run_async(crud.get_client_by_username("test_sub_client"))

        uri = build_hy2_uri(client_data, settings_dict)

        self.assertTrue(uri.startswith("hy2://"))
        parsed = urllib.parse.urlparse(uri)
        self.assertEqual(parsed.scheme, "hy2")
        self.assertEqual(parsed.hostname, "hysteria.example.com")
        self.assertEqual(parsed.port, 443)
        self.assertEqual(parsed.username, "test_sub_client")

        qs = urllib.parse.parse_qs(parsed.query)
        self.assertEqual(qs.get("mport"), ["25000-35000"])
        self.assertEqual(qs.get("obfs"), ["salamander"])
        self.assertEqual(qs.get("obfs-password"), ["obfs_secret_token"])
        self.assertEqual(qs.get("sni"), ["custom.sni.com"])
        self.assertEqual(qs.get("pinSHA256"), ["ab12cd34ef56"])
        self.assertNotIn("insecure", qs)

    def test_clash_meta_yaml_validity(self):
        """Verify Clash Meta configuration is syntactically valid YAML with all fields."""
        user = self.create_test_user("clash_client", "clash_pass")
        self.run_async(crud.set_settings({
            "server_domain": "vpn.example.com",
            "listen_port": "8443",
            "routing_ru": "warp"
        }))
        settings_dict = self.run_async(crud.get_all_settings())
        client_data = self.run_async(crud.get_client_by_username("clash_client"))

        yaml_str = build_clash_yaml(client_data, settings_dict)
        doc = yaml.safe_load(yaml_str)

        self.assertIsInstance(doc, dict)
        self.assertIn("proxies", doc)
        self.assertEqual(doc["proxies"][0]["password"], "clash_client:clash_pass")

    def test_singbox_json_validity(self):
        """Verify Sing-box JSON conforms to v1.10+ schema."""
        user = self.create_test_user("sb_client", "sb_pass")
        self.run_async(crud.set_settings({
            "server_ip": "1.2.3.4",
            "listen_port": "443"
        }))
        settings_dict = self.run_async(crud.get_all_settings())
        client_data = self.run_async(crud.get_client_by_username("sb_client"))

        sb_dict = build_singbox_json(client_data, settings_dict)
        self.assertIsInstance(sb_dict, dict)
        self.assertIn("outbounds", sb_dict)
        h2 = [o for o in sb_dict["outbounds"] if o.get("type") == "hysteria2"]
        self.assertEqual(len(h2), 1)
        self.assertEqual(h2[0]["password"], "sb_client:sb_pass")

    def test_hy2_uri_special_character_escaping(self):
        """
        Adversarial Test: Passwords with '@', ':', '#', '?' in build_hy2_uri.
        Verifies whether hy2:// URI preserves the actual server host, port, and credentials.
        """
        special_pass = "p@ss:w0rd#special?query"
        user = {"username": "spec_user", "password": special_pass}
        settings_dict = {"server_ip": "1.2.3.4", "listen_port": 443}

        uri = build_hy2_uri(user, settings_dict)
        parsed = urllib.parse.urlparse(uri)

        # Host must remain 1.2.3.4
        self.assertEqual(parsed.hostname, "1.2.3.4", f"Hostname corrupted by unescaped password in URI: {parsed.hostname}")
        self.assertEqual(parsed.port, 443)

    def test_subscription_header_epoch_expiration_accuracy_and_update_drift(self):
        """
        Adversarial Test: Check Subscription-Userinfo expire timestamp when client
        is updated with a new expiry_time in epoch milliseconds.
        """
        user = self.create_test_user("sub_drift_user", "pass123", expiration_days=30)
        twenty_days_ago = (date.today() - timedelta(days=20)).strftime("%Y-%m-%d")
        async def _backdate():
            db = await get_db_connection()
            try:
                await db.execute("UPDATE users SET account_creation_date = ? WHERE username = ?;", (twenty_days_ago, "sub_drift_user"))
                await db.commit()
            finally:
                await db.close()
        self.run_async(_backdate())

        # Admin extends expiry to 10 days in the future from now
        future_dt = datetime.utcnow() + timedelta(days=10)
        future_ms = int(future_dt.timestamp() * 1000)
        self.run_async(crud.update_client("sub_drift_user", ClientUpdate(expiry_time=future_ms)))

        user_obj = self.run_async(crud.get_user_by_token(user["sub_token"]))
        header = _get_sub_userinfo_header(user_obj)

        parts = dict(kv.split("=") for kv in header.split("; "))
        header_expire = int(parts.get("expire", 0))
        now_ts = int(datetime.utcnow().timestamp())

        # An active client whose expiration is 10 days in the future MUST NOT have expire in the past
        self.assertGreater(header_expire, now_ts, f"Header expire ({header_expire}) must be in future, but now is {now_ts}")


if __name__ == "__main__":
    unittest.main()
