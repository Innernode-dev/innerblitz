import os
import sys
import json
import base64
import urllib.parse
from pathlib import Path
from typing import Dict, Any

import yaml
from tests.e2e.harness import OpaqueE2ETestCase, CLOUDFLARE_TRACE_SAMPLES, REPO_ROOT
from app.config import settings
from app.database import crud
from app.database.models import UserCreate, UserUpdate
from app.core.hysteria import build_hysteria_yaml, apply_and_save_config, run_systemctl
from app.core.subscription import build_hy2_uri, build_clash_yaml, build_singbox_json, build_base64_sub
from app.core.firewall import configure_port_hopping, flush_port_hopping
from app.core.security import hash_password, verify_password, generate_totp_secret, verify_totp, generate_secret_path


class TestPairwise_WARP_and_RURouting(OpaqueE2ETestCase):
    """Pairwise 1: WARP Outbounds & RU Routing Interaction."""

    def test_p1_01_warp_enabled_and_ru_direct(self):
        """WARP active, RU traffic routed Direct: OpenAI via WARP, private subnets blocked."""
        cfg = {"listen_port": 443, "warp_enabled": True, "warp_port": "40000", "ru_routing": "direct"}
        yaml_str = build_hysteria_yaml(cfg)
        data = self.verify_valid_hysteria_yaml(yaml_str)
        self.assertIn("outbounds", data)
        self.assertIn("outbound(warp, geosite:openai)", yaml_str)

    def test_p1_02_warp_enabled_and_ru_warp(self):
        """WARP active, RU traffic routed through WARP."""
        cfg = {"listen_port": 443, "warp_enabled": True, "warp_port": "40000", "ru_routing": "warp"}
        yaml_str = build_hysteria_yaml(cfg)
        data = self.verify_valid_hysteria_yaml(yaml_str)
        outbounds = data["outbounds"]
        names = [o["name"] for o in outbounds]
        self.assertIn("warp", names)

    def test_p1_03_warp_enabled_and_ru_blocked(self):
        """WARP active, RU traffic blocked: reject rules exist in ACL inline."""
        cfg = {"listen_port": 443, "warp_enabled": True, "warp_port": "40000", "ru_routing": "block"}
        yaml_str = build_hysteria_yaml(cfg)
        self.assertIn("reject(geosite:category-ads-all)", yaml_str)
        self.assertIn("outbound(warp, geosite:openai)", yaml_str)

    def test_p1_04_warp_disabled_and_ru_routing(self):
        """WARP disabled: outbounds block omitted entirely regardless of RU setting."""
        cfg = {"listen_port": 443, "warp_enabled": False, "ru_routing": "direct"}
        yaml_str = build_hysteria_yaml(cfg)
        data = self.verify_valid_hysteria_yaml(yaml_str)
        self.assertNotIn("outbounds", data)
        self.assertNotIn("outbound(warp", yaml_str)

    def test_p1_05_client_subscription_consistency_with_warp_policy(self):
        """Client profiles (Sing-box & Clash) parse cleanly under WARP + RU combination."""
        user = self.create_test_user("warp_ru_client", "pass123")
        cfg = {"server_ip": "1.2.3.4", "listen_port": 443, "warp_enabled": True}
        sb = build_singbox_json(user, cfg)
        self.verify_valid_singbox_profile(sb)
        clash = build_clash_yaml(user, cfg)
        self.verify_valid_clash_yaml(clash)


class TestPairwise_PortHopping_and_Sniffing(OpaqueE2ETestCase):
    """Pairwise 2: Port Hopping & Sniffing Visual Controls Interaction."""

    def test_p2_01_both_hopping_and_sniffing_enabled(self):
        """Both Port Hopping and Sniffing active."""
        cfg = {
            "listen_port": 443,
            "port_hopping_enabled": True,
            "port_hopping_range": "20000:50000",
            "sniff_enable": True
        }
        yaml_str = build_hysteria_yaml(cfg)
        data = self.verify_valid_hysteria_yaml(yaml_str)
        self.assertEqual(data["listen"], ":443")
        self.assertTrue(data["sniff"]["enable"])

    def test_p2_02_hopping_enabled_and_sniffing_disabled(self):
        """Port Hopping active, Sniffing disabled."""
        cfg = {
            "listen_port": 443,
            "port_hopping_enabled": True,
            "port_hopping_range": "25000:35000",
            "sniff_enable": False
        }
        yaml_str = build_hysteria_yaml(cfg)
        data = self.verify_valid_hysteria_yaml(yaml_str)
        self.assertEqual(data["listen"], ":443")

    def test_p2_03_hopping_disabled_and_sniffing_enabled(self):
        """Port Hopping disabled, Sniffing enabled."""
        cfg = {"listen_port": 443, "port_hopping_enabled": False, "sniff_enable": True}
        yaml_str = build_hysteria_yaml(cfg)
        data = self.verify_valid_hysteria_yaml(yaml_str)
        self.assertTrue(data["sniff"]["enable"])

    def test_p2_04_both_disabled(self):
        """Both Port Hopping and Sniffing disabled."""
        cfg = {"listen_port": 443, "port_hopping_enabled": False, "sniff_enable": False}
        yaml_str = build_hysteria_yaml(cfg)
        self.verify_valid_hysteria_yaml(yaml_str)

    def test_p2_05_client_hy2_uri_mport_matches_hopping_range(self):
        """Client URI embeds mport when hopping is enabled, regardless of sniffing."""
        user = self.create_test_user("hop_sniff_user", "pass")
        cfg = {
            "server_ip": "1.2.3.4",
            "listen_port": 443,
            "port_hopping_enabled": True,
            "port_hopping_range": "40000:60000"
        }
        uri = build_hy2_uri(user, cfg)
        self.assertIn("mport=40000-60000", uri)


class TestPairwise_TLSMode_and_PortHopping(OpaqueE2ETestCase):
    """Pairwise 3: TLS Mode & Port Hopping Interaction."""

    def test_p3_01_self_signed_ip_with_port_hopping(self):
        """Self-signed IP cert mode with port hopping: pinSHA256 & mport."""
        user = self.create_test_user("tls_hop_1", "pass")
        cfg = {
            "server_ip": "1.2.3.4",
            "listen_port": 443,
            "tls_type": "self_signed_ip",
            "cert_sha256": "fake_sha256_hash",
            "port_hopping_enabled": True,
            "port_hopping_range": "20000:50000"
        }
        uri = build_hy2_uri(user, cfg)
        self.assertIn("pinSHA256=fake_sha256_hash", uri)
        self.assertIn("mport=20000-50000", uri)

    def test_p3_02_acme_domain_with_port_hopping(self):
        """ACME domain mode with port hopping: no insecure/pinSHA256, domain in host."""
        user = self.create_test_user("tls_hop_2", "pass")
        cfg = {
            "server_domain": "vpn.example.com",
            "listen_port": 443,
            "tls_type": "acme",
            "port_hopping_enabled": True,
            "port_hopping_range": "20000:50000"
        }
        uri = build_hy2_uri(user, cfg)
        self.assertIn("@vpn.example.com:443", uri)
        self.assertNotIn("insecure=1", uri)
        self.assertIn("mport=20000-50000", uri)

    def test_p3_03_custom_sni_with_self_signed_ip_and_hopping(self):
        """Custom SNI specified with self-signed cert and port hopping."""
        user = self.create_test_user("tls_hop_3", "pass")
        cfg = {
            "server_ip": "1.2.3.4",
            "listen_port": 443,
            "tls_type": "self_signed_ip",
            "sni": "my-custom-sni.com",
            "port_hopping_enabled": True,
            "port_hopping_range": "30000:40000"
        }
        uri = build_hy2_uri(user, cfg)
        self.assertIn("sni=my-custom-sni.com", uri)
        self.assertIn("mport=30000-40000", uri)

    def test_p3_04_acme_yaml_config_block(self):
        """ACME mode generates acme block in Hysteria YAML."""
        cfg = {
            "listen_port": 443,
            "tls_type": "acme",
            "server_domain": "sub.domain.org"
        }
        yaml_str = build_hysteria_yaml(cfg)
        data = self.verify_valid_hysteria_yaml(yaml_str)
        self.assertEqual(data["tls"]["type"], "acme")
        self.assertIn("sub.domain.org", data["tls"]["acme"]["domains"])

    def test_p3_05_self_signed_yaml_config_block(self):
        """Self-signed mode generates cert and key paths in Hysteria YAML."""
        cfg = {"listen_port": 443, "tls_type": "self_signed_ip"}
        yaml_str = build_hysteria_yaml(cfg)
        data = self.verify_valid_hysteria_yaml(yaml_str)
        self.assertIn("cert", data["tls"])
        self.assertIn("key", data["tls"])


class TestPairwise_Decoy_and_SecretPath(OpaqueE2ETestCase):
    """Pairwise 4: Decoy Site & Secret URL Path Interaction."""

    def test_p4_01_decoy_enabled_with_custom_secret_path(self):
        """Decoy enabled with custom secret path: root serves decoy, secret path serves login."""
        self.run_async(crud.set_settings({
            "decoy_enabled": "1",
            "decoy_theme": "innernode",
            "panel_secret_path": "mysecretentry"
        }))
        # Root request serves decoy
        root_resp = self.client.get("/")
        self.assertEqual(root_resp.status_code, 200)
        self.assertIn("InnerNode Daemon", root_resp.text)

        # Standard /login hidden
        login_resp = self.client.get("/login")
        self.assertEqual(login_resp.status_code, 200)
        self.assertIn("InnerNode Daemon", login_resp.text)

        # Secret path displays login page
        secret_resp = self.client.get("/mysecretentry")
        self.assertEqual(secret_resp.status_code, 200)
        self.assertIn("InnerBlitz Panel", secret_resp.text)
        self.assertIn("loginForm", secret_resp.text)

    def test_p4_02_decoy_theme_404_status(self):
        """Decoy theme '404' returns HTTP 404 status code."""
        self.run_async(crud.set_settings({
            "decoy_enabled": "1",
            "decoy_theme": "404",
            "panel_secret_path": "mysecretentry"
        }))
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 404)

    def test_p4_03_decoy_disabled_with_custom_secret_path(self):
        """Decoy disabled: root redirects to login or 404."""
        self.run_async(crud.set_settings({
            "decoy_enabled": "0",
            "panel_secret_path": "customsecret99"
        }))
        resp = self.client.get("/login")
        self.assertEqual(resp.status_code, 404)

        # Secret path still works
        secret_resp = self.client.get("/customsecret99")
        self.assertEqual(secret_resp.status_code, 200)

    def test_p4_04_authenticated_admin_bypasses_decoy(self):
        """Logged-in admin visiting root '/' sees dashboard (index.html), not decoy."""
        self.login_admin()
        self.run_async(crud.set_settings({"decoy_enabled": "1", "decoy_theme": "innernode"}))
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Панель управления", resp.text)
        self.assertNotIn("InnerNode Daemon", resp.text)

    def test_p4_05_authenticated_admin_visiting_secret_path_redirects_home(self):
        """Logged-in admin visiting secret path is redirected to '/'."""
        self.login_admin()
        self.run_async(crud.set_setting("panel_secret_path", "secretvault"))
        resp = self.client.get("/secretvault", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.headers["location"], "/")


class TestPairwise_Subscription_and_ClientPolicy(OpaqueE2ETestCase):
    """Pairwise 5: Subscription Formats & Client Policies Interaction."""

    def test_p5_01_user_quota_singbox_profile(self):
        """Sing-box profile generated for user with quota and expiration."""
        user = self.create_test_user("quota_sb", "pass123", traffic_limit_gb=25.0, expiration_days=60)
        cfg = {"server_ip": "1.2.3.4", "listen_port": 443}
        sb = build_singbox_json(user, cfg)
        self.verify_valid_singbox_profile(sb)

    def test_p5_02_user_quota_clash_yaml(self):
        """Clash Meta profile generated for user with quota and obfuscation."""
        user = self.create_test_user("quota_clash", "pass123", traffic_limit_gb=15.0)
        cfg = {
            "server_ip": "1.2.3.4",
            "listen_port": 443,
            "obfs_type": "salamander",
            "obfs_password": "obfs_pw_cross"
        }
        clash = build_clash_yaml(user, cfg)
        data = self.verify_valid_clash_yaml(clash)
        self.assertEqual(data["proxies"][0]["obfs-password"], "obfs_pw_cross")

    def test_p5_03_base64_subscription_contains_valid_hy2_uri(self):
        """Base64 subscription endpoint decodes back to identical hy2:// URI."""
        user = self.create_test_user("b64_user", "pass123")
        cfg = {"server_ip": "1.2.3.4", "listen_port": 443}
        b64_sub = build_base64_sub(user, cfg)
        decoded = base64.b64decode(b64_sub.encode("utf-8")).decode("utf-8")
        expected = build_hy2_uri(user, cfg)
        self.assertEqual(decoded, expected)

    def test_p5_04_portal_links_reflect_updated_hopping_range(self):
        """Changing port hopping range in settings updates hy2 URI in portal."""
        user = self.create_test_user("hop_dyn_user", "pass123")
        self.run_async(crud.set_settings({
            "port_hopping_enabled": "1",
            "port_hopping_range": "33333:44444"
        }))
        resp = self.client.get(f"/portal/{user['sub_token']}")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("mport=33333-44444", resp.text)

    def test_p5_05_blocked_user_endpoint_subscription_header(self):
        """Blocked user fetches /sub/{token} with userinfo header reflecting state."""
        user = self.create_test_user("block_header_user", "pass123")
        self.run_async(crud.update_user(user["id"], UserUpdate(blocked=True)))
        resp = self.client.get(f"/sub/{user['sub_token']}")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("subscription-userinfo", resp.headers)


class TestPairwise_Security2FA_and_RateLimiting(OpaqueE2ETestCase):
    """Pairwise 6: 2FA & Rate Limiter Interaction."""

    def test_p6_01_totp_required_flow(self):
        """Admin login with TOTP enabled returns require_2fa on valid password without code."""
        secret = generate_totp_secret()
        self.run_async(crud.set_settings({
            "totp_enabled": "1",
            "totp_secret": secret
        }))
        resp = self.client.post("/api/login", json={"username": "admin", "password": "admin"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get("require_2fa"))
        self.assertEqual(data.get("type"), "totp")

    def test_p6_02_totp_successful_completion(self):
        """Admin login with valid TOTP code creates session and sets cookie."""
        secret = generate_totp_secret()
        self.run_async(crud.set_settings({
            "totp_enabled": "1",
            "totp_secret": secret
        }))
        import pyotp
        code = pyotp.TOTP(secret).now()
        resp = self.client.post("/api/login", json={
            "username": "admin",
            "password": "admin",
            "totp_code": code
        })
        self.assertEqual(resp.status_code, 200)
        self.assertIn(settings.COOKIE_NAME, resp.cookies)

    def test_p6_03_totp_invalid_code_rejected(self):
        """Admin login with wrong TOTP code fails with 401."""
        secret = generate_totp_secret()
        self.run_async(crud.set_settings({
            "totp_enabled": "1",
            "totp_secret": secret
        }))
        resp = self.client.post("/api/login", json={
            "username": "admin",
            "password": "admin",
            "totp_code": "000000"
        })
        self.assertEqual(resp.status_code, 401)
