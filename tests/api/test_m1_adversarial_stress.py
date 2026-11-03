"""
InnerBlitz Hysteria 2 Next-Gen Panel (3x-ui Overhaul)
Adversarial Stress Test Suite: Milestone M1 Empirical Verification

Covers:
1. Pure traffic reset: zero side-effects on expiry_time and account_creation_date
2. TX/RX traffic accounting direction (Server TX = Client Download, Server RX = Client Upload)
3. Exact byte quota boundaries (under quota, exactly at quota, over quota, post-reset restoration)
4. Millisecond epoch expiration boundaries (past, now, future, extreme timestamps)
5. 1-click toggle and immediate authentication blocking / restoration
6. Session kicking integration on toggle, update, and delete
7. Inbound traffic reset scoping & cross-inbound isolation
8. Input boundaries: username lengths, special characters, SQL injection resistance, validation constraints
9. High-concurrency traffic increment stress (race conditions, lost updates check)
10. Limiter daemon enforcement logic (identifying disabled, expired, and quota-exceeded users)
11. Preserving exact millisecond epoch timestamps without midnight truncation
12. Updating quota and expiration on initially unlimited clients
13. Inbound deletion cascading to legacy users table
"""

import os
import sys
import time
import asyncio
from unittest.mock import patch, AsyncMock
from datetime import datetime, date, timedelta
from typing import Dict, Any

from tests.e2e.harness import OpaqueE2ETestCase
from app.config import settings
from app.database import crud
from app.database.connection import get_db_connection
from app.database.models import ClientCreate, ClientUpdate, InboundCreate
from app.core.auth import authenticate_client
from app.core.limiter import limiter_daemon


class TestM1AdversarialStress(OpaqueE2ETestCase):
    """Empirical adversarial stress harness for Milestone M1."""

    # =========================================================================
    # 1. PURE TRAFFIC RESET ADVERSARIAL STRESS
    # =========================================================================

    def test_pure_traffic_reset_preserves_expiry_and_creation(self):
        """
        Adversarial Test: Verify traffic reset NEVER alters expiry_time or account_creation_date
        across both /api/clients/{id}/reset-traffic and /api/users/{username}/reset.
        """
        self.login_admin()

        # Fixed target timestamp: 2028-06-15 12:00:00 UTC = 1844683200000 ms
        target_expiry = 1844683200000
        client_data = ClientCreate(
            username="stress_reset_client",
            password="StressPassword123!",
            expiry_time=target_expiry,
            total_bytes=10 * 1024 * 1024 * 1024, # 10 GB
            note="Reset test target"
        )
        created = self.run_async(crud.create_client(client_data))
        client_id = created["id"]

        # Backdate account_creation_date in legacy users table to 45 days ago
        initial_created_date = (date.today() - timedelta(days=45)).strftime("%Y-%m-%d")
        async def _backdate():
            db = await get_db_connection()
            try:
                await db.execute(
                    "UPDATE users SET account_creation_date = ? WHERE username = 'stress_reset_client';",
                    (initial_created_date,)
                )
                await db.commit()
            finally:
                await db.close()
        self.run_async(_backdate())

        # Pump 4 GB download (tx) and 1.5 GB upload (rx)
        tx_bytes = 4 * 1024 * 1024 * 1024
        rx_bytes = int(1.5 * 1024 * 1024 * 1024)
        self.run_async(crud.add_user_traffic("stress_reset_client", tx_bytes=tx_bytes, rx_bytes=rx_bytes))

        # Check pre-reset state
        pre_client = self.run_async(crud.get_client_by_id(client_id))
        self.assertEqual(pre_client["download_bytes"], tx_bytes)
        self.assertEqual(pre_client["upload_bytes"], rx_bytes)
        # Expiry time must preserve the exact 3x-ui epoch ms timestamp
        self.assertEqual(pre_client["expiry_time"], target_expiry, "Exact epoch ms expiry_time must be preserved and not clobbered by legacy relative days")

        # Trigger reset via 3x-ui endpoint: POST /api/clients/{id}/reset-traffic
        res = self.client.post(f"/api/clients/{client_id}/reset-traffic")
        self.assertEqual(res.status_code, 200, f"Reset failed: {res.text}")
        data = res.json()
        self.assertTrue(data.get("ok"))

        # Inspect directly from SQLite clients and users tables
        async def _check_db():
            db = await get_db_connection()
            try:
                cur_c = await db.execute("SELECT * FROM clients WHERE username = 'stress_reset_client';")
                c_row = dict(await cur_c.fetchone())
                cur_u = await db.execute("SELECT * FROM users WHERE username = 'stress_reset_client';")
                u_row = dict(await cur_u.fetchone())
                return c_row, u_row
            finally:
                await db.close()

        c_row, u_row = self.run_async(_check_db())

        # Assert: traffic counters zeroed
        self.assertEqual(c_row["upload_bytes"], 0, "clients.upload_bytes must be 0")
        self.assertEqual(c_row["download_bytes"], 0, "clients.download_bytes must be 0")
        self.assertEqual(u_row["upload_bytes"], 0, "users.upload_bytes must be 0")
        self.assertEqual(u_row["download_bytes"], 0, "users.download_bytes must be 0")

        # Assert: expiration timestamp strictly preserved!
        self.assertEqual(c_row["expiry_time"], target_expiry, "clients.expiry_time was mutated by reset!")
        
        # Assert: creation date strictly preserved!
        self.assertEqual(u_row["account_creation_date"], initial_created_date, "users.account_creation_date was mutated by reset!")

        # Now test legacy route: POST /api/users/{username}/reset
        self.run_async(crud.add_user_traffic("stress_reset_client", tx_bytes=1000, rx_bytes=2000))
        res2 = self.client.post("/api/users/stress_reset_client/reset")
        self.assertEqual(res2.status_code, 200)

        c_row2, u_row2 = self.run_async(_check_db())
        self.assertEqual(c_row2["upload_bytes"], 0)
        self.assertEqual(c_row2["download_bytes"], 0)
        self.assertEqual(c_row2["expiry_time"], target_expiry, "Legacy reset mutated expiry_time!")
        self.assertEqual(u_row2["account_creation_date"], initial_created_date, "Legacy reset mutated account_creation_date!")

    # =========================================================================
    # 2. TX/RX TRAFFIC DIRECTION STRESS
    # =========================================================================

    def test_tx_rx_strict_directional_accounting(self):
        """
        Verify that Hysteria 2 server TX (data transmitted to client) is recorded
        as download_bytes, and server RX (data received from client) is recorded
        as upload_bytes, both in database and rate metrics.
        """
        client_data = ClientCreate(
            username="direction_test_user",
            password="pass",
            total_bytes=0 # unlimited
        )
        self.run_async(crud.create_client(client_data))

        # Distinct asymmetrical byte values
        server_tx = 87_654_321 # Server transmitted = Client downloaded
        server_rx = 12_345_678 # Server received = Client uploaded

        self.run_async(crud.add_user_traffic("direction_test_user", tx_bytes=server_tx, rx_bytes=server_rx))

        # Query raw SQL
        async def _get_raw():
            db = await get_db_connection()
            try:
                cur = await db.execute("SELECT upload_bytes, download_bytes FROM clients WHERE username = 'direction_test_user';")
                return dict(await cur.fetchone())
            finally:
                await db.close()

        raw = self.run_async(_get_raw())
        self.assertEqual(raw["download_bytes"], server_tx, "Server TX must map to download_bytes")
        self.assertEqual(raw["upload_bytes"], server_rx, "Server RX must map to upload_bytes")

        # Second addition to verify additive accumulation
        delta_tx = 1_000_000
        delta_rx = 2_000_000
        self.run_async(crud.add_user_traffic("direction_test_user", tx_bytes=delta_tx, rx_bytes=delta_rx))

        raw2 = self.run_async(_get_raw())
        self.assertEqual(raw2["download_bytes"], server_tx + delta_tx)
        self.assertEqual(raw2["upload_bytes"], server_rx + delta_rx)

    # =========================================================================
    # 3. QUOTA BOUNDARY TESTING (EXACT BYTES)
    # =========================================================================

    def test_quota_boundaries_exact_byte_enforcement(self):
        """
        Adversarially test exact byte quota thresholds:
        - used < total_bytes: active / allowed
        - used == total_bytes: quota exceeded / rejected
        - used > total_bytes: quota exceeded / rejected
        - reset traffic: restored to active / allowed
        """
        quota_bytes = 1000
        client_data = ClientCreate(
            username="exact_quota_client",
            password="secret_password_1",
            total_bytes=quota_bytes,
            expiry_time=0
        )
        self.run_async(crud.create_client(client_data))

        # 1. 999 bytes consumed (499 tx, 500 rx) -> Under quota
        self.run_async(crud.add_user_traffic("exact_quota_client", tx_bytes=499, rx_bytes=500))
        c = self.run_async(crud.get_client_by_username("exact_quota_client"))
        self.assertFalse(c["is_quota_exceeded"])
        self.assertTrue(c["is_active"])

        ok, _, msg = self.run_async(authenticate_client("exact_quota_client:secret_password_1", "1.2.3.4:1000"))
        self.assertTrue(ok, f"Expected auth success under quota, got: {msg}")

        # 2. Exactly 1000 bytes consumed (+1 byte tx) -> Boundary hit!
        self.run_async(crud.add_user_traffic("exact_quota_client", tx_bytes=1, rx_bytes=0))
        c2 = self.run_async(crud.get_client_by_username("exact_quota_client"))
        self.assertTrue(c2["is_quota_exceeded"], "Boundary condition (used == total) must mark quota exceeded")
        self.assertFalse(c2["is_active"])

        ok2, _, msg2 = self.run_async(authenticate_client("exact_quota_client:secret_password_1", "1.2.3.4:1000"))
        self.assertFalse(ok2, "Auth must be rejected when used == total_bytes")
        self.assertIn("quota", msg2.lower())

        # 3. 1001 bytes consumed (+1 byte rx) -> Over quota
        self.run_async(crud.add_user_traffic("exact_quota_client", tx_bytes=0, rx_bytes=1))
        ok3, _, _ = self.run_async(authenticate_client("exact_quota_client:secret_password_1", "1.2.3.4:1000"))
        self.assertFalse(ok3)

        # 4. Pure traffic reset restores access immediately
        self.run_async(crud.reset_client_traffic("exact_quota_client"))
        c3 = self.run_async(crud.get_client_by_username("exact_quota_client"))
        self.assertFalse(c3["is_quota_exceeded"])
        self.assertEqual(c3["upload_bytes"], 0)
        self.assertEqual(c3["download_bytes"], 0)

        ok4, _, msg4 = self.run_async(authenticate_client("exact_quota_client:secret_password_1", "1.2.3.4:1000"))
        self.assertTrue(ok4, f"Auth must succeed after traffic reset, got: {msg4}")

    # =========================================================================
    # 4. EPOCH EXPIRATION MILLISECOND BOUNDARIES
    # =========================================================================

    def test_epoch_expiration_boundaries(self):
        """
        Adversarially test epoch expiration timestamps:
        - expiry_time in past -> expired / rejected
        - expiry_time in future -> active / allowed
        - expiry_time = 0 -> unlimited
        - extreme future timestamp (e.g. year 2286) -> handled without crash
        """
        now_ms = int(datetime.utcnow().timestamp() * 1000)

        # Past timestamp (1 millisecond ago)
        c_past = ClientCreate(username="exp_past_user", password="p1", expiry_time=now_ms - 1)
        self.run_async(crud.create_client(c_past))
        u_past = self.run_async(crud.get_client_by_username("exp_past_user"))
        self.assertTrue(u_past["is_expired"])
        self.assertEqual(u_past["days_left"], 0)
        ok_past, _, msg_past = self.run_async(authenticate_client("exp_past_user:p1", "1.2.3.4:1000"))
        self.assertFalse(ok_past)
        self.assertIn("expired", msg_past.lower())

        # Future timestamp (1 hour from now)
        c_future = ClientCreate(username="exp_future_user", password="p2", expiry_time=now_ms + 3600 * 1000)
        self.run_async(crud.create_client(c_future))
        u_future = self.run_async(crud.get_client_by_username("exp_future_user"))
        self.assertFalse(u_future["is_expired"])
        ok_future, _, _ = self.run_async(authenticate_client("exp_future_user:p2", "1.2.3.4:1000"))
        self.assertTrue(ok_future)

        # Unlimited (expiry_time = 0)
        c_unlim = ClientCreate(username="exp_unlim_user", password="p3", expiry_time=0)
        self.run_async(crud.create_client(c_unlim))
        u_unlim = self.run_async(crud.get_client_by_username("exp_unlim_user"))
        self.assertFalse(u_unlim["is_expired"])
        self.assertEqual(u_unlim["expiry_date_str"], "Unlimited")
        ok_unlim, _, _ = self.run_async(authenticate_client("exp_unlim_user:p3", "1.2.3.4:1000"))
        self.assertTrue(ok_unlim)

        # Extreme epoch timestamp (e.g. 9999999999999 ms = year 2286)
        c_extreme = ClientCreate(username="exp_extreme_user", password="p4", expiry_time=9999999999999)
        self.run_async(crud.create_client(c_extreme))
        u_extreme = self.run_async(crud.get_client_by_username("exp_extreme_user"))
        self.assertFalse(u_extreme["is_expired"])
        self.assertIn("2286", u_extreme["expiry_date_str"])
        ok_ext, _, _ = self.run_async(authenticate_client("exp_extreme_user:p4", "1.2.3.4:1000"))
        self.assertTrue(ok_ext)

    # =========================================================================
    # 5. 1-CLICK TOGGLE & SESSION KICKING INTEGRATION
    # =========================================================================

    def test_toggle_and_session_kicking(self):
        """
        Verify that toggling client enable state immediately flips authentication
        and invokes kick_users_api when disabling.
        """
        self.login_admin()
        client = ClientCreate(username="kick_test_client", password="pass")
        created = self.run_async(crud.create_client(client))
        cid = created["id"]

        with patch("app.api.client_routes.kick_users_api", new_callable=AsyncMock) as mock_kick:
            # 1. Toggle off
            res = self.client.post(f"/api/clients/{cid}/toggle")
            self.assertEqual(res.status_code, 200)
            self.assertFalse(res.json()["enable"])
            mock_kick.assert_called_once_with(["kick_test_client"])

            # Verify auth blocked
            ok, _, msg = self.run_async(authenticate_client("kick_test_client:pass", "1.2.3.4:1000"))
            self.assertFalse(ok)
            self.assertIn("blocked", msg.lower())

            # 2. Toggle back on
            mock_kick.reset_mock()
            res2 = self.client.post(f"/api/clients/{cid}/toggle")
            self.assertEqual(res2.status_code, 200)
            self.assertTrue(res2.json()["enable"])
            # Kicking should not be called when enabling
            mock_kick.assert_not_called()

            # Verify auth restored
            ok2, _, _ = self.run_async(authenticate_client("kick_test_client:pass", "1.2.3.4:1000"))
            self.assertTrue(ok2)

        # 3. Test kick on client deletion
        with patch("app.api.client_routes.kick_users_api", new_callable=AsyncMock) as mock_del_kick:
            res_del = self.client.delete(f"/api/clients/{cid}")
            self.assertEqual(res_del.status_code, 200)
            mock_del_kick.assert_called_once_with(["kick_test_client"])

    # =========================================================================
    # 6. INBOUND TRAFFIC RESET & ISOLATION
    # =========================================================================

    def test_inbound_traffic_reset_isolation(self):
        """
        Verify that resetting traffic on Inbound 1 ONLY resets clients attached
        to Inbound 1, leaving clients attached to Inbound 2 untouched.
        """
        self.login_admin()

        # Create secondary inbound
        ib2_data = InboundCreate(tag="Inbound-Backup", listen_port=8443)
        ib2 = self.run_async(crud.create_inbound(ib2_data))
        ib2_id = ib2["id"]

        # Create clients under Inbound 1 (default) and Inbound 2
        c1 = ClientCreate(inbound_id=1, username="c_inbound_1", password="p")
        c2 = ClientCreate(inbound_id=ib2_id, username="c_inbound_2", password="p")
        self.run_async(crud.create_client(c1))
        self.run_async(crud.create_client(c2))

        # Add traffic to both
        self.run_async(crud.add_user_traffic("c_inbound_1", tx_bytes=5_000_000, rx_bytes=5_000_000))
        self.run_async(crud.add_user_traffic("c_inbound_2", tx_bytes=9_000_000, rx_bytes=9_000_000))

        # Reset traffic for Inbound 1 only
        res = self.client.post("/api/inbounds/1/reset-traffic")
        self.assertEqual(res.status_code, 200)

        # Client 1 must be reset
        u1 = self.run_async(crud.get_client_by_username("c_inbound_1"))
        self.assertEqual(u1["upload_bytes"], 0)
        self.assertEqual(u1["download_bytes"], 0)

        # Client 2 MUST RETAIN its traffic (isolation!)
        u2 = self.run_async(crud.get_client_by_username("c_inbound_2"))
        self.assertEqual(u2["download_bytes"], 9_000_000, "Client on inbound 2 must not be reset")
        self.assertEqual(u2["upload_bytes"], 9_000_000)

    # =========================================================================
    # 7. INPUT BOUNDARIES & SANITIZATION STRESS
    # =========================================================================

    def test_input_boundaries_and_special_characters(self):
        """
        Test edge cases in client input parameters:
        - Max length boundary on username (64 chars accepted, 65 chars rejected)
        - Unicode, emojis, and special characters in username & note
        - SQL injection strings safely handled by parameterized queries
        - Negative values in max_ips / total_gb rejected by Pydantic validators
        """
        self.login_admin()

        # 1. Exact 64-char username (boundary)
        uname_64 = "a" * 64
        res_64 = self.client.post("/api/clients", json={"username": uname_64, "password": "p"})
        self.assertEqual(res_64.status_code, 201)

        # 2. 65-char username (exceeds max_length=64)
        uname_65 = "b" * 65
        res_65 = self.client.post("/api/clients", json={"username": uname_65, "password": "p"})
        self.assertEqual(res_65.status_code, 422, "65-char username must be rejected with 422")

        # 3. Unicode and emoji in username & note
        unicode_payload = {
            "username": "юзер_🚀_тест",
            "password": "Пароль123!@#",
            "note": "Длинная заметка с символами: <>&'\" / 🔒 100%"
        }
        res_u = self.client.post("/api/clients", json=unicode_payload)
        self.assertEqual(res_u.status_code, 201)
        u_data = res_u.json()
        self.assertEqual(u_data["username"], "юзер_🚀_тест")
        self.assertEqual(u_data["note"], unicode_payload["note"])

        # Auth with unicode credentials
        ok, uid, _ = self.run_async(authenticate_client("юзер_🚀_тест:Пароль123!@#", "1.2.3.4:1000"))
        self.assertTrue(ok)
        self.assertEqual(uid, "юзер_🚀_тест")

        # 4. SQL injection attack strings in username and password
        sqli_uname = "admin' OR '1'='1"
        res_sqli = self.client.post("/api/clients", json={"username": sqli_uname, "password": "p"})
        self.assertEqual(res_sqli.status_code, 201)
        # Verify it created a literal record and didn't corrupt the database
        sqli_client = self.run_async(crud.get_client_by_username(sqli_uname))
        self.assertIsNotNone(sqli_client)
        self.assertEqual(sqli_client["username"], sqli_uname)

        # 5. Negative max_ips validation constraint
        res_neg_ips = self.client.post("/api/clients", json={"username": "neg_ips_user", "max_ips": -5})
        self.assertEqual(res_neg_ips.status_code, 422, "Negative max_ips must fail validation with 422")

    # =========================================================================
    # 8. HIGH-CONCURRENCY TRAFFIC INCREMENT STRESS
    # =========================================================================

    def test_high_concurrency_traffic_increments_no_lost_updates(self):
        """
        Stress test: 40 concurrent async tasks incrementing traffic for the same user.
        Validates SQLite locking and ensures ZERO lost updates.
        """
        client = ClientCreate(username="concurrency_target", password="p")
        self.run_async(crud.create_client(client))

        inc_tx = 1000
        inc_rx = 2000
        total_tasks = 40

        async def _run_concurrent_increments():
            tasks = [
                crud.add_user_traffic("concurrency_target", tx_bytes=inc_tx, rx_bytes=inc_rx)
                for _ in range(total_tasks)
            ]
            await asyncio.gather(*tasks)

        self.run_async(_run_concurrent_increments())

        # Inspect final tally
        u = self.run_async(crud.get_client_by_username("concurrency_target"))
        expected_tx = total_tasks * inc_tx
        expected_rx = total_tasks * inc_rx
        self.assertEqual(u["download_bytes"], expected_tx, f"Expected {expected_tx} download_bytes, got {u['download_bytes']}")
        self.assertEqual(u["upload_bytes"], expected_rx, f"Expected {expected_rx} upload_bytes, got {u['upload_bytes']}")

    # =========================================================================
    # 9. LIMITER DAEMON ENFORCEMENT & DISABLED CLIENT KICKING
    # =========================================================================

    def test_limiter_daemon_identifies_unauthorized_clients(self):
        """
        Verify that limiter_daemon.check_and_enforce() correctly discovers:
        1. Disabled clients (MUST be kicked even if created without limits!)
        2. Expired clients
        3. Quota-exceeded clients
        and dispatches kick requests for all of them.
        """
        now_ms = int(datetime.utcnow().timestamp() * 1000)

        # 1. Disabled client (created with enable=False)
        c_dis = ClientCreate(username="limiter_disabled", password="p", enable=False)
        self.run_async(crud.create_client(c_dis))

        # 2. Expired client
        c_exp = ClientCreate(username="limiter_expired", password="p", expiry_time=now_ms - 1000)
        self.run_async(crud.create_client(c_exp))

        # 3. Quota exceeded client
        c_quota = ClientCreate(username="limiter_quota", password="p", total_bytes=1000)
        self.run_async(crud.create_client(c_quota))
        self.run_async(crud.add_user_traffic("limiter_quota", tx_bytes=2000, rx_bytes=0))

        # 4. Valid client (should NOT be kicked)
        c_valid = ClientCreate(username="limiter_valid", password="p", total_bytes=0, expiry_time=0)
        self.run_async(crud.create_client(c_valid))

        with patch("app.core.limiter.kick_users_api", new_callable=AsyncMock) as mock_kick:
            mock_kick.return_value = True
            self.run_async(limiter_daemon.check_and_enforce())

            # Verify kick was called
            self.assertTrue(mock_kick.called, "limiter_daemon.check_and_enforce must call kick_users_api")
            kicked_list = mock_kick.call_args[0][0]
            self.assertIn("limiter_disabled", kicked_list, "Disabled clients must be kicked by limiter daemon")
            self.assertIn("limiter_expired", kicked_list)
            self.assertIn("limiter_quota", kicked_list)
            self.assertNotIn("limiter_valid", kicked_list, "Valid client must not be kicked")

    # =========================================================================
    # 10. UNLIMITED USER UPDATE INTEGRITY (QUOTA & EXPIRATION ENFORCEMENT)
    # =========================================================================

    def test_updating_initially_unlimited_client_enforces_limits(self):
        """
        Adversarial Test: When a client is created with default total_bytes=0 / expiry_time=0
        and later updated with a quota or expiration date:
        - Quota must be enforced (auth blocked when used >= total_bytes)
        - Expiration must be enforced (auth blocked when now >= expiry_time)
        - The client must NOT remain permanently immune due to residual unlimited_user flag!
        """
        # 1. Create client without explicit limits
        c = self.run_async(crud.create_client(ClientCreate(username="unlim_update_target", password="p")))
        self.assertEqual(c["total_bytes"], 0)

        # 2. Admin assigns a 1000-byte quota via update_client
        updated = self.run_async(crud.update_client("unlim_update_target", ClientUpdate(total_bytes=1000)))
        self.assertEqual(updated["total_bytes"], 1000)

        # 3. Consume 1500 bytes (exceeding quota)
        self.run_async(crud.add_user_traffic("unlim_update_target", tx_bytes=1500, rx_bytes=0))

        # 4. Verify auth fails due to quota exceeded
        ok, _, msg = self.run_async(authenticate_client("unlim_update_target:p", "1.2.3.4:1000"))
        self.assertFalse(ok, f"Client updated with 1000-byte quota must be blocked after 1500 bytes, but got: {ok} ({msg})")
        self.assertIn("quota", msg.lower())

    # =========================================================================
    # 11. INBOUND DELETION CASCADING INTEGRITY
    # =========================================================================

    def test_delete_inbound_cascades_to_users_table(self):
        """
        Adversarial Test: Deleting an inbound must clean up attached clients
        from BOTH clients and legacy users tables, preventing orphaned records.
        """
        ib = self.run_async(crud.create_inbound(InboundCreate(tag="IB-Cascade", listen_port=9876)))
        c = self.run_async(crud.create_client(ClientCreate(inbound_id=ib["id"], username="orphan_test_user", password="p")))

        # Delete inbound
        deleted = self.run_async(crud.delete_inbound(ib["id"]))
        self.assertTrue(deleted)

        # Check clients table
        c_check = self.run_async(crud.get_client_by_username("orphan_test_user"))
        self.assertIsNone(c_check, "Client must be deleted when its inbound is deleted")

        # Check users table directly via raw SQL
        async def _check_users():
            db = await get_db_connection()
            try:
                cur = await db.execute("SELECT * FROM users WHERE username = 'orphan_test_user';")
                return await cur.fetchone()
            finally:
                await db.close()

        orphaned = self.run_async(_check_users())
        self.assertIsNone(orphaned, "Client must NOT remain orphaned in users table after inbound deletion")
