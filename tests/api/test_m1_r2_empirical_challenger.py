"""
Empirical Adversarial Stress Suite — Milestone M1 Iteration 2 Re-Verification
Author: Challenger M1 Iteration 2 (teamwork_challenger)

Adversarially probes:
1. `_calculate_client_metrics` with past creation dates and future `expiry_time` values.
2. Limiter session kicking on disabled accounts with unlimited traffic flags.
3. Updating initially unlimited accounts with quotas and testing authentication rejections.
4. Cascading user cleanup on inbound deletion.
5. Subscription headers with epoch timestamps.
6. `hy2://` URIs with RFC 3986 reserved password characters (`@`, `:`, `#`, `?`, `/`).
7. Migration idempotency with NULL columns and multiple re-runs.
"""

import asyncio
import os
import shutil
import tempfile
import unittest
import urllib.parse
from datetime import datetime, date, timedelta
from pathlib import Path
from unittest.mock import patch, AsyncMock

import aiosqlite
from starlette.testclient import TestClient

from app.config import settings
from app.database import crud
from app.database.connection import init_db, get_db_connection
from app.database.models import ClientCreate, ClientUpdate, InboundCreate
from app.core.subscription import build_hy2_uri
from app.core.auth import authenticate_client
from app.core.limiter import limiter_daemon
from app.api.sub_routes import _get_sub_userinfo_header
from tests.e2e.harness import IsolatedEnvironment, OpaqueE2ETestCase


class TestM1R2EmpiricalChallenger(OpaqueE2ETestCase):
    """Empirical adversarial challenger test suite for Milestone M1 R2."""

    # =========================================================================
    # 1. _calculate_client_metrics with past creation date and future expiry
    # =========================================================================

    def test_calculate_client_metrics_past_creation_future_expiry(self):
        """
        Adversarial Test: An account with an ancient account_creation_date (e.g. 500 days ago)
        and legacy expiration_days=30 (which under legacy logic expired 470 days ago),
        BUT updated with a 3x-ui future epoch ms expiry_time (e.g. 30 days into the future).
        
        Empirically verifies:
        - Absolute epoch ms expiry_time ALWAYS supersedes legacy relative expiration.
        - is_expired is False.
        - days_left reflects future days remaining (>= 29).
        - exact expiry_time millisecond timestamp is preserved.
        """
        now_ms = int(datetime.utcnow().timestamp() * 1000)
        future_ms = now_ms + (30 * 86400 * 1000)  # 30 days from now

        raw_data = {
            "id": 1,
            "username": "legacy_drift_user",
            "enable": 1,
            "blocked": 0,
            "total_bytes": 10 * 1024 * 1024 * 1024,
            "upload_bytes": 1000,
            "download_bytes": 2000,
            "expiry_time": future_ms,
            "expiration_days": 30,
            "account_creation_date": "2020-01-01",  # 6+ years in the past
            "unlimited_user": 0,
        }

        metrics = crud._calculate_client_metrics(dict(raw_data))

        self.assertFalse(metrics["is_expired"], "Client with future expiry_time must NOT be marked expired")
        self.assertGreaterEqual(metrics["days_left"], 29, "days_left must reflect future days, not ancient creation date")
        self.assertEqual(metrics["expiry_time"], future_ms, "Exact millisecond epoch expiry_time must be preserved")
        self.assertTrue(metrics["is_active"], "Client must be active")

        # Boundary test: expiry_time exactly 1 ms in the past
        past_data = dict(raw_data)
        past_data["expiry_time"] = now_ms - 1
        metrics_past = crud._calculate_client_metrics(past_data)
        self.assertTrue(metrics_past["is_expired"], "Client with expiry_time in the past must be expired")
        self.assertEqual(metrics_past["days_left"], 0)
        self.assertFalse(metrics_past["is_active"])

    # =========================================================================
    # 2. Limiter kicking on disabled accounts with unlimited traffic flags
    # =========================================================================

    def test_limiter_kicks_disabled_accounts_with_unlimited_flags(self):
        """
        Adversarial Test: Accounts that have unlimited_user=True, total_bytes=0,
        and expiry_time=0, BUT are disabled (enable=False or blocked=True).
        
        LimiterDaemon MUST NOT skip these accounts. It must kick all of them.
        """
        c1 = ClientCreate(username="unlim_disabled_1", password="p1", enable=False, total_bytes=0, expiry_time=0)
        c2 = ClientCreate(username="unlim_disabled_2", password="p2", enable=False, total_bytes=0, expiry_time=0)
        c3 = ClientCreate(username="unlim_active_valid", password="p3", enable=True, total_bytes=0, expiry_time=0)

        self.run_async(crud.create_client(c1))
        self.run_async(crud.create_client(c2))
        self.run_async(crud.create_client(c3))

        # Explicitly ensure unlimited_user flag is set in users table
        async def _set_unlim_flags():
            db = await get_db_connection()
            try:
                await db.execute("UPDATE users SET unlimited_user = 1 WHERE username IN ('unlim_disabled_1', 'unlim_disabled_2', 'unlim_active_valid');")
                await db.commit()
            finally:
                await db.close()
        self.run_async(_set_unlim_flags())

        with patch("app.core.limiter.kick_users_api", new_callable=AsyncMock) as mock_kick:
            mock_kick.return_value = True
            self.run_async(limiter_daemon.check_and_enforce())

            self.assertTrue(mock_kick.called, "kick_users_api must be called")
            kicked = mock_kick.call_args[0][0]
            self.assertIn("unlim_disabled_1", kicked, "Disabled client 1 with unlimited_user=1 must be kicked")
            self.assertIn("unlim_disabled_2", kicked, "Disabled client 2 with unlimited_user=1 must be kicked")
            self.assertNotIn("unlim_active_valid", kicked, "Active valid unlimited client must not be kicked")

    # =========================================================================
    # 3. Updating initially unlimited accounts with quotas & auth rejections
    # =========================================================================

    def test_updating_initially_unlimited_account_lifecycle(self):
        """
        Adversarial Test: Comprehensive lifecycle of initially unlimited accounts:
        - Created as unlimited (total_bytes=0, expiry_time=0).
        - Authenticates successfully.
        - Admin sets quota to 2000 bytes.
        - Pumping 1999 bytes -> auth succeeds.
        - Pumping 1 byte (exact 2000 bytes) -> auth rejected for quota.
        - Admin sets quota back to 0 -> auth restored.
        - Admin sets expiry_time to 1 second in the past -> auth rejected for expired.
        - Admin extends expiry_time to 10 days in the future -> auth restored.
        - Admin toggles enable=False -> auth rejected for blocked.
        - Admin toggles enable=True -> auth restored.
        """
        self.login_admin()
        client = ClientCreate(username="lifecycle_target", password="TargetPassword456!", total_bytes=0, expiry_time=0)
        created = self.run_async(crud.create_client(client))
        cid = created["id"]

        # Step 1: Initial auth as unlimited
        ok, _, msg = self.run_async(authenticate_client("lifecycle_target:TargetPassword456!"))
        self.assertTrue(ok, f"Initial unlimited auth failed: {msg}")

        # Step 2: Set quota = 2000 bytes
        self.run_async(crud.update_client("lifecycle_target", ClientUpdate(total_bytes=2000)))

        # Step 3: Add 1999 bytes
        self.run_async(crud.add_user_traffic("lifecycle_target", tx_bytes=1000, rx_bytes=999))
        ok, _, msg = self.run_async(authenticate_client("lifecycle_target:TargetPassword456!"))
        self.assertTrue(ok, f"Auth at 1999/2000 bytes should succeed, got: {msg}")

        # Step 4: Add 1 byte -> exact 2000 bytes boundary
        self.run_async(crud.add_user_traffic("lifecycle_target", tx_bytes=1, rx_bytes=0))
        ok, _, msg = self.run_async(authenticate_client("lifecycle_target:TargetPassword456!"))
        self.assertFalse(ok, "Auth at 2000/2000 bytes must fail")
        self.assertIn("quota", msg.lower())

        # Step 5: Remove quota (set total_bytes=0)
        self.run_async(crud.update_client("lifecycle_target", ClientUpdate(total_bytes=0)))
        ok, _, msg = self.run_async(authenticate_client("lifecycle_target:TargetPassword456!"))
        self.assertTrue(ok, f"Auth should succeed after quota removed, got: {msg}")

        # Step 6: Set expiry_time to 1 second in past
        now_ms = int(datetime.utcnow().timestamp() * 1000)
        self.run_async(crud.update_client("lifecycle_target", ClientUpdate(expiry_time=now_ms - 1000)))
        ok, _, msg = self.run_async(authenticate_client("lifecycle_target:TargetPassword456!"))
        self.assertFalse(ok, "Auth must fail when expired")
        self.assertIn("expired", msg.lower())

        # Step 7: Extend expiry_time to future
        self.run_async(crud.update_client("lifecycle_target", ClientUpdate(expiry_time=now_ms + 10000000)))
        ok, _, msg = self.run_async(authenticate_client("lifecycle_target:TargetPassword456!"))
        self.assertTrue(ok, f"Auth must succeed when expiry extended, got: {msg}")

        # Step 8: Disable account
        self.run_async(crud.update_client("lifecycle_target", ClientUpdate(enable=False)))
        ok, _, msg = self.run_async(authenticate_client("lifecycle_target:TargetPassword456!"))
        self.assertFalse(ok, "Auth must fail when disabled")
        self.assertIn("blocked", msg.lower())

        # Step 9: Re-enable account
        self.run_async(crud.update_client("lifecycle_target", ClientUpdate(enable=True)))
        ok, _, msg = self.run_async(authenticate_client("lifecycle_target:TargetPassword456!"))
        self.assertTrue(ok, f"Auth must succeed when re-enabled, got: {msg}")

    # =========================================================================
    # 4. Cascading user cleanup on inbound deletion
    # =========================================================================

    def test_cascading_cleanup_multi_client_isolation(self):
        """
        Adversarial Test: An inbound with multiple clients is deleted.
        - All attached clients must be deleted from BOTH clients and users tables.
        - Clients on other inbounds MUST remain intact.
        - Inbound table row must be deleted.
        """
        self.login_admin()

        # Inbound A
        ib_a = self.run_async(crud.create_inbound(InboundCreate(tag="Inbound-A", listen_port=10001)))
        # Inbound B
        ib_b = self.run_async(crud.create_inbound(InboundCreate(tag="Inbound-B", listen_port=10002)))

        # Clients on Inbound A
        c_a1 = self.run_async(crud.create_client(ClientCreate(inbound_id=ib_a["id"], username="user_a1", password="p")))
        c_a2 = self.run_async(crud.create_client(ClientCreate(inbound_id=ib_a["id"], username="user_a2", password="p")))

        # Client on Inbound B
        c_b1 = self.run_async(crud.create_client(ClientCreate(inbound_id=ib_b["id"], username="user_b1", password="p")))

        # Delete Inbound A via CRUD
        deleted = self.run_async(crud.delete_inbound(ib_a["id"]))
        self.assertTrue(deleted)

        async def _check_db():
            db = await get_db_connection()
            try:
                # Check clients
                cur_c_a1 = await db.execute("SELECT * FROM clients WHERE username = 'user_a1';")
                cur_c_a2 = await db.execute("SELECT * FROM clients WHERE username = 'user_a2';")
                cur_c_b1 = await db.execute("SELECT * FROM clients WHERE username = 'user_b1';")
                # Check users
                cur_u_a1 = await db.execute("SELECT * FROM users WHERE username = 'user_a1';")
                cur_u_a2 = await db.execute("SELECT * FROM users WHERE username = 'user_a2';")
                cur_u_b1 = await db.execute("SELECT * FROM users WHERE username = 'user_b1';")
                # Check inbound
                cur_ib_a = await db.execute("SELECT * FROM inbounds WHERE id = ?;", (ib_a["id"],))
                cur_ib_b = await db.execute("SELECT * FROM inbounds WHERE id = ?;", (ib_b["id"],))

                return {
                    "c_a1": await cur_c_a1.fetchone(),
                    "c_a2": await cur_c_a2.fetchone(),
                    "c_b1": await cur_c_b1.fetchone(),
                    "u_a1": await cur_u_a1.fetchone(),
                    "u_a2": await cur_u_a2.fetchone(),
                    "u_b1": await cur_u_b1.fetchone(),
                    "ib_a": await cur_ib_a.fetchone(),
                    "ib_b": await cur_ib_b.fetchone(),
                }
            finally:
                await db.close()

        res = self.run_async(_check_db())

        # Inbound A clients wiped from clients table
        self.assertIsNone(res["c_a1"], "user_a1 must be deleted from clients")
        self.assertIsNone(res["c_a2"], "user_a2 must be deleted from clients")
        # Inbound A clients wiped from users table
        self.assertIsNone(res["u_a1"], "user_a1 must be deleted from users")
        self.assertIsNone(res["u_a2"], "user_a2 must be deleted from users")
        # Inbound A itself wiped
        self.assertIsNone(res["ib_a"], "Inbound-A must be deleted from inbounds")

        # Inbound B client fully preserved in both tables
        self.assertIsNotNone(res["c_b1"], "user_b1 on Inbound-B must remain in clients")
        self.assertIsNotNone(res["u_b1"], "user_b1 on Inbound-B must remain in users")
        self.assertIsNotNone(res["ib_b"], "Inbound-B must remain in inbounds")

    # =========================================================================
    # 5. Subscription headers with epoch timestamps
    # =========================================================================

    def test_subscription_header_epoch_timestamps(self):
        """
        Adversarial Test: Subscription-Userinfo header formatting:
        - Exact epoch ms conversion to second timestamp.
        - upload, download, and total byte formatting.
        - Dynamic updates when client expiry_time changes.
        """
        target_ms = 1844683200000  # 1844683200 seconds
        user_dict = {
            "username": "sub_header_client",
            "upload_bytes": 123456,
            "download_bytes": 654321,
            "total_bytes": 10737418240,  # 10 GB
            "expiry_time": target_ms,
        }

        header = _get_sub_userinfo_header(user_dict)
        self.assertIn("upload=123456", header)
        self.assertIn("download=654321", header)
        self.assertIn("total=10737418240", header)
        self.assertIn("expire=1844683200", header)

        # Unlimited user (expiry_time = 0)
        user_dict_unlim = dict(user_dict)
        user_dict_unlim["expiry_time"] = 0
        user_dict_unlim["expiration_days"] = 0
        header_unlim = _get_sub_userinfo_header(user_dict_unlim)
        self.assertIn("expire=0", header_unlim)

    # =========================================================================
    # 6. hy2:// URIs with RFC 3986 reserved password characters
    # =========================================================================

    def test_hy2_uri_rfc3986_reserved_characters(self):
        """
        Adversarial Test: RFC 3986 reserved and delimiter characters in passwords:
        '@', ':', '#', '?', '/', '&', '=', '+', '%', ' '
        
        The generated hy2:// URI must:
        - Have the server host and port perfectly parseable.
        - Never corrupt the URI authority segment.
        - Decode back to the exact original username and password via urllib.parse.unquote.
        """
        adversarial_passwords = [
            "pass@word",
            "p:a:s:s",
            "hash#tag#val",
            "query?param=1&other=2",
            "path/to/secret",
            "all_in_one@123:secret#anchor?query=yes/path+space%20",
        ]

        settings_dict = {
            "server_domain": "vpn.example.com",
            "listen_port": "443",
            "server_ip": "1.2.3.4"
        }

        for pwd in adversarial_passwords:
            with self.subTest(pwd=pwd):
                user = {
                    "username": "adv_user",
                    "password": pwd
                }
                uri = build_hy2_uri(user, settings_dict)
                parsed = urllib.parse.urlparse(uri)

                self.assertEqual(parsed.scheme, "hy2")
                self.assertEqual(parsed.hostname, "vpn.example.com")
                self.assertEqual(parsed.port, 443)
                
                # Verify username and password recover precisely
                recovered_user = urllib.parse.unquote(parsed.username)
                recovered_pass = urllib.parse.unquote(parsed.password)
                self.assertEqual(recovered_user, "adv_user")
                self.assertEqual(recovered_pass, pwd, f"Password failed to recover: {recovered_pass} != {pwd}")


class TestM1R2MigrationIdempotencyStress(unittest.TestCase):
    """Adversarial stress-testing of legacy SQLite migration with NULL fields and idempotency."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="innerblitz_migr_stress_")
        self.old_base_dir = settings.BASE_DIR
        settings.BASE_DIR = self.temp_dir
        os.environ["INNERBLITZ_DIR"] = self.temp_dir
        self.db_path = settings.DB_PATH

    def tearDown(self):
        settings.BASE_DIR = self.old_base_dir
        if "INNERBLITZ_DIR" in os.environ:
            del os.environ["INNERBLITZ_DIR"]
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_migration_null_columns_and_multi_rerun_idempotency(self):
        """
        Adversarial Test:
        1. Legacy database with multiple rows containing NULLs across all nullable and non-nullable columns.
        2. Run init_db() migration.
        3. Verify all valid rows migrated with safe zero/empty fallbacks.
        4. Re-run init_db() 5 consecutive times to prove absolute idempotency without row duplication.
        """
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        async def _create_adversarial_legacy_db():
            db = await aiosqlite.connect(self.db_path)
            try:
                await db.execute("""
                    CREATE TABLE users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                        password TEXT,
                        max_download_bytes INTEGER,
                        upload_bytes INTEGER,
                        download_bytes INTEGER,
                        expiration_days INTEGER,
                        account_creation_date TEXT,
                        blocked INTEGER,
                        unlimited_user INTEGER,
                        max_ips INTEGER,
                        note TEXT,
                        sub_token TEXT
                    );
                """)

                # Row 1: All metrics NULL
                await db.execute("""
                    INSERT INTO users (username, password, max_download_bytes, upload_bytes, download_bytes, expiration_days, account_creation_date, blocked, unlimited_user, max_ips, note, sub_token)
                    VALUES ('null_metrics_1', 'pass1', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'tok_1');
                """)
                # Row 2: NULL password and NULL sub_token
                await db.execute("""
                    INSERT INTO users (username, password, max_download_bytes, upload_bytes, download_bytes, expiration_days, account_creation_date, blocked, unlimited_user, max_ips, note, sub_token)
                    VALUES ('null_pass_token_2', NULL, 1000, 10, 20, 30, '2026-11-01', 0, 0, 1, 'some note', NULL);
                """)
                # Row 3: Standard complete row
                await db.execute("""
                    INSERT INTO users (username, password, max_download_bytes, upload_bytes, download_bytes, expiration_days, account_creation_date, blocked, unlimited_user, max_ips, note, sub_token)
                    VALUES ('standard_row_3', 'secure_pass', 50000, 100, 200, 15, '2026-10-20', 1, 0, 2, 'standard note', 'tok_3');
                """)

                await db.commit()
            finally:
                await db.close()

        asyncio.run(_create_adversarial_legacy_db())

        # First migration run
        asyncio.run(init_db())

        async def _verify_first_run():
            db = await get_db_connection()
            try:
                cursor = await db.execute("SELECT * FROM clients ORDER BY id ASC;")
                clients = [dict(c) for c in await cursor.fetchall()]
                self.assertEqual(len(clients), 3, f"Expected 3 migrated clients, got {len(clients)}")

                c_map = {c["username"]: c for c in clients}

                # null_metrics_1 checks
                c1 = c_map["null_metrics_1"]
                self.assertEqual(c1["total_bytes"], 0)
                self.assertEqual(c1["upload_bytes"], 0)
                self.assertEqual(c1["download_bytes"], 0)
                self.assertEqual(c1["max_ips"], 0)
                self.assertEqual(c1["note"], "")
                self.assertEqual(c1["enable"], 1)

                # null_pass_token_2 checks
                c2 = c_map["null_pass_token_2"]
                self.assertEqual(c2["password"], "")
                self.assertTrue(len(c2["sub_token"]) > 0, "sub_token must have a generated fallback token")

                # standard_row_3 checks
                c3 = c_map["standard_row_3"]
                self.assertEqual(c3["password"], "secure_pass")
                self.assertEqual(c3["enable"], 0)  # blocked=1 -> enable=0
                self.assertEqual(c3["total_bytes"], 50000)
                self.assertEqual(c3["upload_bytes"], 100)
                self.assertEqual(c3["download_bytes"], 200)
                self.assertEqual(c3["note"], "standard note")

            finally:
                await db.close()

        asyncio.run(_verify_first_run())

        # Re-run init_db() 5 consecutive times
        for run_idx in range(5):
            asyncio.run(init_db())

        # Verify idempotency
        async def _verify_idempotent_counts():
            db = await get_db_connection()
            try:
                c_cur = await db.execute("SELECT COUNT(*) as cnt FROM clients;")
                self.assertEqual((await c_cur.fetchone())["cnt"], 3, "Client count must not grow on repeated init_db() calls")

                ib_cur = await db.execute("SELECT COUNT(*) as cnt FROM inbounds;")
                self.assertEqual((await ib_cur.fetchone())["cnt"], 1, "Inbound count must not grow on repeated init_db() calls")
            finally:
                await db.close()

        asyncio.run(_verify_idempotent_counts())


if __name__ == "__main__":
    unittest.main()
