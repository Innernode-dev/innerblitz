"""
InnerBlitz Hysteria 2 Next-Gen Panel
Milestone M2: Visual Routing Engine & Dynamic Config Generator E2E Tests.

Covers:
- Database schema and routing default keys
- validate_hysteria_config (PyYAML syntax & key checks)
- build_hysteria_yaml (outbounds, ads, win-spy, p2p, services, RU, private IP, fallback)
- apply_and_save_config (atomic write, backup, validation, rollback)
- GET /api/routing and POST /api/routing
- SettingsPayload routing fields
- Raw config validation guard
"""

import os
import sys
from pathlib import Path
from typing import Dict, Any

import yaml
from tests.e2e.harness import OpaqueE2ETestCase
from app.config import settings
from app.database import crud
from app.database.connection import init_db
from app.core.hysteria import (
    validate_hysteria_config,
    build_hysteria_yaml,
    apply_and_save_config,
    ConfigApplyResult
)


class TestM2_DatabaseRoutingDefaults(OpaqueE2ETestCase):
    """M2.1: Database schema and default keys for visual routing."""

    def test_routing_default_keys_present_after_init(self):
        """Verify init_db initializes all 10 visual routing keys with expected defaults."""
        all_s = self.run_async(crud.get_all_settings())
        expected_keys = {
            "routing_global_outbound": "direct",
            "routing_ru": "direct",
            "routing_openai": "warp",
            "routing_discord": "warp",
            "routing_youtube": "warp",
            "routing_telegram": "direct",
            "routing_netflix": "warp",
            "routing_p2p": "block",
            "routing_ads": "1",
            "routing_win_spy": "1",
        }
        for k, v in expected_keys.items():
            self.assertIn(k, all_s, f"Key '{k}' missing from settings table")
            self.assertEqual(all_s[k], v, f"Default value mismatch for '{k}'")

    def test_routing_keys_preservation_on_subsequent_init(self):
        """Verify re-running init_db preserves existing customized routing keys."""
        self.run_async(crud.set_settings({
            "routing_global_outbound": "warp",
            "routing_ru": "block",
            "routing_p2p": "allow",
            "routing_ads": "0",
        }))
        # Re-run init_db (simulating server restart or migration)
        self.run_async(init_db())
        all_s = self.run_async(crud.get_all_settings())
        self.assertEqual(all_s["routing_global_outbound"], "warp")
        self.assertEqual(all_s["routing_ru"], "block")
        self.assertEqual(all_s["routing_p2p"], "allow")
        self.assertEqual(all_s["routing_ads"], "0")


class TestM2_HysteriaConfigValidation(OpaqueE2ETestCase):
    """M2.2: validate_hysteria_config validator tests."""

    def test_valid_minimal_hysteria_config(self):
        """Valid YAML with listen, tls, auth passes validation."""
        valid_yaml = """
listen: :443
tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key
auth:
  type: http
  http:
    url: http://127.0.0.1:28262/auth
"""
        is_valid, msg = validate_hysteria_config(valid_yaml)
        self.assertTrue(is_valid)
        self.assertEqual(msg, "Configuration is valid")

    def test_empty_or_whitespace_config(self):
        """Empty or blank configuration is detected and rejected."""
        for empty_val in ("", "   \n\t  ", None):
            is_valid, msg = validate_hysteria_config(empty_val)
            self.assertFalse(is_valid)
            self.assertIn("empty", msg.lower())

    def test_malformed_yaml_syntax(self):
        """YAML syntax errors (bad indentation, unclosed tokens) fail with descriptive error."""
        malformed = """
listen: :443
tls:
  cert: /path
    key: /bad_indent
auth: [unclosed array
"""
        is_valid, msg = validate_hysteria_config(malformed)
        self.assertFalse(is_valid)
        self.assertIn("syntax error", msg.lower())

    def test_missing_mandatory_keys(self):
        """Missing listen, tls, or auth fails validation with list of missing keys."""
        no_listen = "tls: {cert: a, key: b}\nauth: {type: http}\n"
        is_valid, msg = validate_hysteria_config(no_listen)
        self.assertFalse(is_valid)
        self.assertIn("listen", msg)

        no_tls = "listen: :443\nauth: {type: http}\n"
        is_valid, msg = validate_hysteria_config(no_tls)
        self.assertFalse(is_valid)
        self.assertIn("tls", msg)

        no_auth = "listen: :443\ntls: {cert: a, key: b}\n"
        is_valid, msg = validate_hysteria_config(no_auth)
        self.assertFalse(is_valid)
        self.assertIn("auth", msg)

    def test_invalid_outbounds_structure(self):
        """Non-list outbounds section fails validation."""
        bad_outbounds = """
listen: :443
tls: {cert: a, key: b}
auth: {type: http}
outbounds: "not a list"
"""
        is_valid, msg = validate_hysteria_config(bad_outbounds)
        self.assertFalse(is_valid)
        self.assertIn("outbounds", msg.lower())

    def test_invalid_acl_inline_structure(self):
        """Non-list acl.inline section fails validation."""
        bad_acl = """
listen: :443
tls: {cert: a, key: b}
auth: {type: http}
acl:
  inline: "not a list"
"""
        is_valid, msg = validate_hysteria_config(bad_acl)
        self.assertFalse(is_valid)
        self.assertIn("inline", msg.lower())


class TestM2_DynamicHysteriaYAMLGenerator(OpaqueE2ETestCase):
    """M2.3: Dynamic build_hysteria_yaml configuration generation."""

    def test_global_outbound_direct_generation(self):
        """When global outbound is direct and warp is disabled, outbounds is omitted."""
        cfg = {
            "listen_port": 443,
            "routing_global_outbound": "direct",
            "warp_enabled": False
        }
        yaml_str = build_hysteria_yaml(cfg)
        parsed = self.verify_valid_hysteria_yaml(yaml_str)
        self.assertNotIn("outbounds", parsed)
        self.assertNotIn("outbound(warp", yaml_str)

    def test_global_outbound_warp_generation(self):
        """When global outbound is warp, outbounds are generated and fallback is outbound(warp, all)."""
        cfg = {
            "listen_port": 443,
            "routing_global_outbound": "warp",
            "warp_port": "40000"
        }
        yaml_str = build_hysteria_yaml(cfg)
        parsed = self.verify_valid_hysteria_yaml(yaml_str)
        self.assertIn("outbounds", parsed)
        names = [o["name"] for o in parsed["outbounds"]]
        self.assertIn("direct", names)
        self.assertIn("warp", names)
        self.assertIn("outbound(warp, all)", yaml_str)

    def test_ads_and_win_spy_toggles(self):
        """Ads and Win-Spy toggles control presence of reject rules."""
        # Enabled
        cfg_on = {"listen_port": 443, "routing_ads": "1", "routing_win_spy": "1"}
        y_on = build_hysteria_yaml(cfg_on)
        self.assertIn("reject(geosite:category-ads-all)", y_on)
        self.assertIn("reject(geosite:win-spy)", y_on)

        # Disabled
        cfg_off = {"listen_port": 443, "routing_ads": "0", "routing_win_spy": "0"}
        y_off = build_hysteria_yaml(cfg_off)
        self.assertNotIn("reject(geosite:category-ads-all)", y_off)
        self.assertNotIn("reject(geosite:win-spy)", y_off)

    def test_p2p_bittorrent_blocking(self):
        """P2P block generates reject(geosite:bittorrent); allow omits it."""
        cfg_block = {"listen_port": 443, "routing_p2p": "block"}
        y_block = build_hysteria_yaml(cfg_block)
        self.assertIn("reject(geosite:bittorrent)", y_block)

        cfg_allow = {"listen_port": 443, "routing_p2p": "allow"}
        y_allow = build_hysteria_yaml(cfg_allow)
        self.assertNotIn("reject(geosite:bittorrent)", y_allow)

    def test_ru_routing_3way_modes(self):
        """RU routing direct, warp, and block modes."""
        # 1. Block mode
        cfg_block = {"listen_port": 443, "warp_enabled": True, "routing_ru": "block"}
        y_block = build_hysteria_yaml(cfg_block)
        self.assertIn("reject(geosite:ru)", y_block)
        self.assertIn("reject(geoip:ru)", y_block)

        # 2. WARP mode
        cfg_warp = {"listen_port": 443, "warp_enabled": True, "routing_ru": "warp"}
        y_warp = build_hysteria_yaml(cfg_warp)
        self.assertIn("outbound(warp, geosite:ru)", y_warp)
        self.assertIn("outbound(warp, geoip:ru)", y_warp)

        # 3. Direct mode with global warp
        cfg_direct = {"listen_port": 443, "routing_global_outbound": "warp", "routing_ru": "direct"}
        y_direct = build_hysteria_yaml(cfg_direct)
        self.assertIn("direct(geosite:ru)", y_direct)
        self.assertIn("direct(geoip:ru)", y_direct)

        # 4. Unsupported fallback
        cfg_invalid = {"listen_port": 443, "routing_ru": "invalid_mode_xyz"}
        y_invalid = build_hysteria_yaml(cfg_invalid)
        self.verify_valid_hysteria_yaml(y_invalid)

    def test_service_presets_routing(self):
        """Individual service presets (OpenAI, Discord, YouTube, Telegram, Netflix)."""
        cfg = {
            "listen_port": 443,
            "warp_enabled": True,
            "routing_openai": "warp",
            "routing_discord": "block",
            "routing_youtube": "warp",
            "routing_telegram": "block",
            "routing_netflix": "warp"
        }
        y = build_hysteria_yaml(cfg)
        self.assertIn("outbound(warp, geosite:openai)", y)
        self.assertIn("reject(geosite:discord)", y)
        self.assertIn("outbound(warp, geosite:youtube)", y)
        self.assertIn("reject(geosite:telegram)", y)
        self.assertIn("outbound(warp, geosite:netflix)", y)

    def test_rfc1918_private_ip_protections_always_present(self):
        """Private subnets are always rejected in ACL inline."""
        cfg = {"listen_port": 443}
        y = build_hysteria_yaml(cfg)
        subnets = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "fc00::/7"]
        for s in subnets:
            self.assertIn(f"reject({s})", y)

    def test_acl_rejection_rules_strictly_precede_outbound_rules(self):
        """Rejections (ads, spy, p2p, subnets) strictly precede routing outbounds."""
        cfg = {"listen_port": 443, "warp_enabled": True, "routing_openai": "warp"}
        y = build_hysteria_yaml(cfg)
        lines = y.splitlines()
        reject_idx = next(i for i, l in enumerate(lines) if "reject(" in l)
        outbound_idx = next(i for i, l in enumerate(lines) if "outbound(warp" in l)
        self.assertLess(reject_idx, outbound_idx, "All reject rules must appear before warp outbounds")

    def test_acl_rules_deduplication(self):
        """Duplicate ACL rules are filtered while preserving order."""
        cfg = {"listen_port": 443, "warp_enabled": True}
        y = build_hysteria_yaml(cfg)
        data = self.verify_valid_hysteria_yaml(y)
        rules = data["acl"]["inline"]
        self.assertEqual(len(rules), len(set(rules)), "No duplicate rules in acl.inline")

    def test_dynamic_sniff_block_parameters(self):
        """Sniffing configuration parameters dynamically generate matching YAML."""
        cfg = {
            "listen_port": 443,
            "sniff_enable": False,
            "sniff_timeout": "5s",
            "rewrite_domain": True
        }
        y = build_hysteria_yaml(cfg)
        data = self.verify_valid_hysteria_yaml(y)
        sniff = data["sniff"]
        self.assertFalse(sniff["enable"])
        self.assertEqual(sniff["timeout"], "5s")
        self.assertTrue(sniff["rewriteDomain"])


class TestM2_AtomicApplyAndRollback(OpaqueE2ETestCase):
    """M2.4: Safe apply_and_save_config with backup and rollback."""

    def test_successful_apply_creates_backup(self):
        """Applying valid configuration writes config.yaml and creates config.yaml.bak."""
        res = self.run_async(apply_and_save_config())
        self.assertTrue(res)
        self.assertIsInstance(res, ConfigApplyResult)
        self.assertTrue(res.success)

        cfg_path = Path(settings.HYSTERIA_CONFIG_PATH)
        self.assertTrue(cfg_path.exists())

        # Second apply creates backup of previous valid file
        res2 = self.run_async(apply_and_save_config())
        self.assertTrue(res2)
        bak_path = Path(str(settings.HYSTERIA_CONFIG_PATH) + ".bak")
        self.assertTrue(bak_path.exists())

    def test_invalid_custom_yaml_rolls_back_safely(self):
        """Applying corrupted YAML triggers rollback without destroying existing valid config."""
        # 1. Establish valid original file
        res1 = self.run_async(apply_and_save_config())
        self.assertTrue(res1)
        cfg_path = Path(settings.HYSTERIA_CONFIG_PATH)
        orig_content = cfg_path.read_text(encoding="utf-8")

        # 2. Attempt applying invalid YAML
        bad_yaml = "invalid: [broken yaml"
        res2 = self.run_async(apply_and_save_config(custom_yaml=bad_yaml))
        self.assertFalse(res2)
        self.assertFalse(res2.success)
        self.assertIn("validation failed", res2.message.lower())

        # 3. Confirm original file was preserved intact
        current_content = cfg_path.read_text(encoding="utf-8")
        self.assertEqual(current_content, orig_content)


class TestM2_RoutingAPIRoutes(OpaqueE2ETestCase):
    """M2.5: REST API endpoints GET /api/routing and POST /api/routing."""

    def test_get_routing_unauthorized(self):
        """Unauthenticated GET /api/routing returns 401."""
        resp = self.client.get("/api/routing")
        self.assertIn(resp.status_code, (401, 302, 307))

    def test_get_routing_authenticated(self):
        """Authenticated GET /api/routing returns all routing rules."""
        self.login_admin()
        resp = self.client.get("/api/routing")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get("ok"))
        self.assertEqual(data["routing_global_outbound"], "direct")
        self.assertEqual(data["routing_ru"], "direct")
        self.assertEqual(data["routing_openai"], "warp")
        self.assertEqual(data["routing_p2p"], "block")
        self.assertEqual(data["routing_ads"], "1")
        self.assertEqual(data["routing_win_spy"], "1")
        self.assertIn("warp_enabled", data)

    def test_post_routing_valid_updates(self):
        """Authenticated POST /api/routing updates settings, regenerates config, and restarts core."""
        self.login_admin()
        payload = {
            "routing_global_outbound": "warp",
            "routing_ru": "warp",
            "routing_openai": "direct",
            "routing_p2p": "allow",
            "routing_ads": "0",
            "routing_win_spy": "0"
        }
        resp = self.client.post("/api/routing", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["ok"])

        # Verify database reflection
        all_s = self.run_async(crud.get_all_settings())
        self.assertEqual(all_s["routing_global_outbound"], "warp")
        self.assertEqual(all_s["routing_ru"], "warp")
        self.assertEqual(all_s["routing_openai"], "direct")
        self.assertEqual(all_s["routing_p2p"], "allow")
        self.assertEqual(all_s["routing_ads"], "0")
        self.assertEqual(all_s["routing_win_spy"], "0")
        self.assertEqual(all_s["warp_enabled"], "1")

        # Verify config.yaml reflection
        cfg_path = Path(settings.HYSTERIA_CONFIG_PATH)
        cfg_yaml = cfg_path.read_text(encoding="utf-8")
        self.assertIn("outbound(warp, geosite:ru)", cfg_yaml)
        self.assertNotIn("reject(geosite:bittorrent)", cfg_yaml)
        self.assertNotIn("reject(geosite:category-ads-all)", cfg_yaml)

    def test_post_routing_invalid_global_outbound_rejected(self):
        """Invalid routing_global_outbound value returns 400 Bad Request."""
        self.login_admin()
        resp = self.client.post("/api/routing", json={"routing_global_outbound": "alien_vpn"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("routing_global_outbound", resp.json().get("detail", ""))

    def test_post_routing_invalid_ru_mode_rejected(self):
        """Invalid routing_ru mode returns 400 Bad Request."""
        self.login_admin()
        resp = self.client.post("/api/routing", json={"routing_ru": "tor_network"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("routing_ru", resp.json().get("detail", ""))

    def test_post_routing_invalid_service_mode_rejected(self):
        """Invalid service mode returns 400 Bad Request."""
        self.login_admin()
        resp = self.client.post("/api/routing", json={"routing_openai": "nordvpn"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("routing_openai", resp.json().get("detail", ""))

    def test_post_routing_invalid_p2p_mode_rejected(self):
        """Invalid routing_p2p mode returns 400 Bad Request."""
        self.login_admin()
        resp = self.client.post("/api/routing", json={"routing_p2p": "throttle"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("routing_p2p", resp.json().get("detail", ""))

    def test_post_settings_supports_routing_fields(self):
        """POST /api/settings handles extended routing parameters seamlessly."""
        self.login_admin()
        payload = {
            "routing_global_outbound": "direct",
            "routing_ru": "block",
            "routing_ads": True,
            "routing_win_spy": True
        }
        resp = self.client.post("/api/settings", json=payload)
        self.assertEqual(resp.status_code, 200)

        ru_val = self.run_async(crud.get_setting("routing_ru"))
        self.assertEqual(ru_val, "block")

    def test_raw_config_endpoint_validates_and_rejects_broken_yaml(self):
        """POST /api/settings/raw-config validates input and rejects malformed YAML."""
        self.login_admin()
        broken_yaml = "broken_key: [unclosed list"
        resp = self.client.post("/api/settings/raw-config", json={"content": broken_yaml})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertFalse(data.get("ok"))
        self.assertIn("validation failed", data.get("message", "").lower())
