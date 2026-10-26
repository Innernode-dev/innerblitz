import os
import sys
import json
import base64
from pathlib import Path
from typing import Dict, Any

import yaml
from tests.e2e.harness import OpaqueE2ETestCase, CLOUDFLARE_TRACE_SAMPLES, REPO_ROOT
from app.config import settings
from app.database import crud
from app.database.models import UserCreate, UserUpdate
from app.core.hysteria import build_hysteria_yaml, apply_and_save_config
from app.core.subscription import build_hy2_uri, build_clash_yaml, build_singbox_json, build_base64_sub
from app.core.auth import authenticate_client


class TestScenario01_AdminOnboardingAndStealthLockdown(OpaqueE2ETestCase):
    """Scenario 1: End-to-end Administrator Onboarding & Stealth Camouflage Lockdown."""

    def test_workflow_admin_onboarding_and_stealth(self):
        # 1. Verify default initial state
        admin_user = self.run_async(crud.get_setting("admin_username"))
        self.assertEqual(admin_user, "admin")

        # 2. Login with default credentials
        login_resp = self.client.post("/api/login", json={"username": "admin", "password": "admin"})
        self.assertEqual(login_resp.status_code, 200)
        self.assertIn(settings.COOKIE_NAME, login_resp.cookies)

        # 3. Change password via API
        self.login_admin()
        change_pwd_resp = self.client.post("/api/settings/change-password", json={
            "old_password": "admin",
            "new_password": "NewStrongAdminPassword2026!"
        })
        self.assertEqual(change_pwd_resp.status_code, 200)

        # 4. Configure stealth settings: custom secret path & enable decoy
        stealth_path = "blitz_stealth_portal_88"
        self.client.post("/api/settings", json={
            "panel_secret_path": stealth_path,
            "decoy_enabled": True,
            "decoy_theme": "innernode"
        })

        # 5. Clear session to simulate unauthenticated external visitor
        self.client.cookies.clear()

        # 6. Visitor to root '/' receives decoy site (anti-scanner camouflage)
        root_resp = self.client.get("/")
        self.assertEqual(root_resp.status_code, 200)
        self.assertIn("InnerNode Daemon", root_resp.text)
        self.assertNotIn("InnerBlitz", root_resp.text)

        # 7. Visitor to standard '/login' also receives decoy site
        std_login_resp = self.client.get("/login")
        self.assertEqual(std_login_resp.status_code, 200)
        self.assertIn("InnerNode Daemon", std_login_resp.text)

        # 8. Genuine administrator accesses secret path
        secret_entry_resp = self.client.get(f"/{stealth_path}")
        self.assertEqual(secret_entry_resp.status_code, 200)
        self.assertIn("InnerBlitz Panel", secret_entry_resp.text)
        self.assertIn("loginForm", secret_entry_resp.text)

        # 9. Login with new credentials succeeds
        auth_resp = self.client.post("/api/login", json={
            "username": "admin",
            "password": "NewStrongAdminPassword2026!"
        })
        self.assertEqual(auth_resp.status_code, 200)
        self.assertIn(settings.COOKIE_NAME, auth_resp.cookies)


class TestScenario02_ClientUserLifecycleAndQuotaEnforcement(OpaqueE2ETestCase):
    """Scenario 2: Client User Provisioning, Consumption, Quota Rejection & Re-authorization."""

    def test_workflow_client_lifecycle_and_quota_enforcement(self):
        # 1. Admin creates user with 1.0 GB traffic limit and 30 days validity
        user = self.create_test_user(
            username="client_alpha",
            password="client_alpha_pass_123",
            traffic_limit_gb=1.0,
            expiration_days=30
        )
        token = user["sub_token"]
        user_id = user["id"]
        auth_str = f"client_alpha:client_alpha_pass_123"

        # 2. Client queries subscription endpoint
        sub_resp = self.client.get(f"/sub/{token}")
        self.assertEqual(sub_resp.status_code, 200)
        userinfo = sub_resp.headers["subscription-userinfo"]
        self.assertIn("total=1073741824", userinfo) # 1 GB in bytes
        self.assertIn("upload=0", userinfo)
        self.assertIn("download=0", userinfo)

        # 3. Client connects: Hysteria 2 HTTP Auth Hook verifies client
        is_ok, authed_id, msg = self.run_async(authenticate_client(auth_str, "198.51.100.2:54321"))
        self.assertTrue(is_ok)
        self.assertEqual(authed_id, "client_alpha")

        # 4. Simulate client downloading 1.2 GB (exceeding quota)
        consumed_bytes = int(1.2 * 1024 * 1024 * 1024)
        self.run_async(crud.add_user_traffic("client_alpha", tx_bytes=1000000, rx_bytes=consumed_bytes))

        # 5. Client connects again: Auth hook immediately rejects connection
        is_ok, _, msg = self.run_async(authenticate_client(auth_str, "198.51.100.2:54322"))
        self.assertFalse(is_ok)
        self.assertEqual(msg, "Traffic quota exceeded")

        # 6. Admin extends user quota to 5.0 GB
        new_max_bytes = 5 * 1024 * 1024 * 1024
        self.run_async(crud.update_user("client_alpha", UserUpdate(traffic_limit_gb=5.0)))

        # 7. Client connects again: Immediately re-authorized
        is_ok, authed_id, msg = self.run_async(authenticate_client(auth_str, "198.51.100.2:54323"))
        self.assertTrue(is_ok)
        self.assertEqual(authed_id, "client_alpha")

        # 8. Admin blocks user manually
        self.run_async(crud.update_user("client_alpha", UserUpdate(blocked=True)))
        is_ok, _, msg = self.run_async(authenticate_client(auth_str, "198.51.100.2:54324"))
        self.assertFalse(is_ok)
        self.assertEqual(msg, "User account is blocked")


class TestScenario03_WARPEgressAndRoutingPolicySwitch(OpaqueE2ETestCase):
    """Scenario 3: Complete WARP Activation, Egress Configuration & Client Sync."""

    def test_workflow_warp_activation_and_routing_policy(self):
        self.login_admin()

        # 1. Initial State: WARP disabled
        cfg_initial = self.run_async(crud.get_all_settings())
        yaml_initial = build_hysteria_yaml(cfg_initial)
        self.assertNotIn("outbounds", yaml_initial)

        # 2. Admin enables WARP in Settings
        resp = self.client.post("/api/settings", json={
            "warp_enabled": True,
            "server_ip": "198.51.100.1",
            "listen_port": 443
        })
        self.assertEqual(resp.status_code, 200)

        # 3. Verify generated config has valid outbounds and OpenAI/Netflix routes
        cfg_updated = self.run_async(crud.get_all_settings())
        yaml_warp = build_hysteria_yaml(cfg_updated)
        data = self.verify_valid_hysteria_yaml(yaml_warp)
        self.assertIn("outbounds", data)
        self.assertIn("outbound(warp, geosite:openai)", yaml_warp)
        self.assertIn("outbound(warp, geosite:netflix)", yaml_warp)

        # 4. Generate Sing-box client profile for client under new policy
        user = self.create_test_user("sync_user", "sync_pass")
        sb_profile = build_singbox_json(user, cfg_updated)
        self.verify_valid_singbox_profile(sb_profile)

        # 5. Generate Clash Meta profile and ensure proxy definition is complete
        clash_profile = build_clash_yaml(user, cfg_updated)
        clash_data = self.verify_valid_clash_yaml(clash_profile)
        self.assertEqual(clash_data["proxies"][0]["server"], "198.51.100.1")
        self.assertEqual(clash_data["proxies"][0]["port"], 443)


class TestScenario04_MultiClientSubscriptionDistribution(OpaqueE2ETestCase):
    """Scenario 4: Multi-client subscription distribution across Sing-box, Clash, and Base64."""

    def test_workflow_multi_client_distribution(self):
        user = self.create_test_user("dist_user", "dist_pass_456", traffic_limit_gb=20.0)
        token = user["sub_token"]

        # 1. Base64 endpoint for v2rayN / Shadowrocket / NekoBox
        raw_resp = self.client.get(f"/sub/{token}")
        self.assertEqual(raw_resp.status_code, 200)
        b64_content = raw_resp.text.strip()
        decoded_uri = base64.b64decode(b64_content.encode("utf-8")).decode("utf-8")
        self.assertTrue(decoded_uri.startswith("hy2://dist_user:dist_pass_456@"))

        # 2. Clash Meta endpoint for Clash Verge / Mihomo
        clash_resp = self.client.get(f"/sub/{token}/clash")
        self.assertEqual(clash_resp.status_code, 200)
        self.assertIn("text/yaml", clash_resp.headers["content-type"])
        clash_data = self.verify_valid_clash_yaml(clash_resp.text)
        self.assertEqual(clash_data["proxies"][0]["password"], "dist_user:dist_pass_456")

        # 3. Sing-box endpoint for Sing-box v1.10+
        sb_resp = self.client.get(f"/sub/{token}/singbox")
        self.assertEqual(sb_resp.status_code, 200)
        sb_data = sb_resp.json()
        self.verify_valid_singbox_profile(sb_data)

        # 4. Personal Web Portal
        portal_resp = self.client.get(f"/portal/{token}")
        self.assertEqual(portal_resp.status_code, 200)
        self.assertIn("dist_user", portal_resp.text)
        self.assertIn("data:image/png;base64,", portal_resp.text)


class TestScenario05_PortHoppingDynamicRangeAndTeardown(OpaqueE2ETestCase):
    """Scenario 5: Port Hopping Range Configuration, Subscriptions Update & Clean Teardown."""

    def test_workflow_port_hopping_lifecycle(self):
        self.login_admin()

        # 1. Set initial port hopping range
        self.client.post("/api/settings", json={
            "port_hopping_enabled": True,
            "port_hopping_range": "20000:40000"
        })

        # 2. Client URI embeds mport=20000-40000
        user = self.create_test_user("hop_life_user", "pass")
        cfg1 = self.run_async(crud.get_all_settings())
        uri1 = build_hy2_uri(user, cfg1)
        self.assertIn("mport=20000-40000", uri1)

        # 3. Update range to 30000:50000
        self.client.post("/api/settings", json={
            "port_hopping_range": "30000:50000"
        })
        cfg2 = self.run_async(crud.get_all_settings())
        uri2 = build_hy2_uri(user, cfg2)
        self.assertIn("mport=30000-50000", uri2)

        # 4. Disable port hopping
        self.client.post("/api/settings", json={
            "port_hopping_enabled": False
        })
        cfg3 = self.run_async(crud.get_all_settings())
        uri3 = build_hy2_uri(user, cfg3)
        self.assertNotIn("mport=", uri3)
