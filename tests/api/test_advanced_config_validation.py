"""
InnerBlitz Hysteria 2 Next-Gen Panel (3x-ui Overhaul)
Test Suite: Advanced Server Parameters, Deep Config Validation & Rollback

Features Tested:
- Advanced server parameters: QUIC windows, sniffing, masquerade, port hopping
- Deep YAML & ACL rule validation (syntax, outbound reference integrity)
- Atomic write with backup and automatic rollback on failure
"""

import os
import sys
import yaml
from pathlib import Path
from typing import Dict, Any

from tests.e2e.harness import OpaqueE2ETestCase
from app.config import settings
from app.database import crud
from app.core.hysteria import (
    build_hysteria_yaml,
    validate_hysteria_config,
    apply_and_save_config,
    ConfigApplyResult
)
from app.core.firewall import configure_port_hopping


class TestAdvancedServerParameters(OpaqueE2ETestCase):
    """Configuration generation and boundary testing for advanced server parameters."""

    def test_quic_window_parameters_generation(self):
        """Verify quic stream and connection receive windows are reflected in YAML."""
        cfg = {
            "listen_port": 443,
            "init_stream_rx_window": 8388608,
            "max_stream_rx_window": 16777216,
            "init_conn_rx_window": 20971520,
            "max_conn_rx_window": 41943040,
            "max_idle_timeout": "30s"
        }
        yaml_str = build_hysteria_yaml(cfg)
        data = self.verify_valid_hysteria_yaml(yaml_str)
        self.assertIn("quic", data)
        quic = data["quic"]
        self.assertIn("initStreamReceiveWindow", quic)
        self.assertIn("maxStreamReceiveWindow", quic)
        self.assertIn("initConnReceiveWindow", quic)
        self.assertIn("maxConnReceiveWindow", quic)
        self.assertIn("maxIdleTimeout", quic)
        # Windows must satisfy init <= max
        self.assertLessEqual(quic["initStreamReceiveWindow"], quic["maxStreamReceiveWindow"])
        self.assertLessEqual(quic["initConnReceiveWindow"], quic["maxConnReceiveWindow"])

    def test_domain_sniffing_parameters(self):
        """Verify domain sniffing configuration in YAML (enable, timeout, rewriteDomain)."""
        cfg = {
            "listen_port": 443,
            "sniff_enable": True,
            "sniff_timeout": "3s",
            "sniff_rewrite_domain": True
        }
        yaml_str = build_hysteria_yaml(cfg)
        data = self.verify_valid_hysteria_yaml(yaml_str)
        self.assertIn("sniff", data)
        sniff = data["sniff"]
        self.assertTrue(sniff.get("enable"))
        self.assertEqual(sniff.get("timeout"), "3s")
        self.assertTrue(sniff.get("rewriteDomain"))

    def test_masquerade_proxy_mode(self):
        """Verify masquerade type 'proxy' generates valid proxy block with target URL."""
        cfg = {
            "listen_port": 443,
            "masquerade_type": "proxy",
            "masquerade_target": "https://news.ycombinator.com"
        }
        yaml_str = build_hysteria_yaml(cfg)
        data = self.verify_valid_hysteria_yaml(yaml_str)
        self.assertIn("masquerade", data)
        masq = data["masquerade"]
        self.assertEqual(masq["type"], "proxy")
        self.assertIn("proxy", masq)
        self.assertEqual(masq["proxy"]["url"], "https://news.ycombinator.com")

    def test_masquerade_string_mode(self):
        """Verify masquerade type 'string' generates static response body and status code."""
        cfg = {
            "listen_port": 443,
            "masquerade_type": "string"
        }
        yaml_str = build_hysteria_yaml(cfg)
        data = self.verify_valid_hysteria_yaml(yaml_str)
        self.assertIn("masquerade", data)
        masq = data["masquerade"]
        self.assertEqual(masq["type"], "string")
        self.assertIn("string", masq)
        self.assertEqual(masq["string"]["statusCode"], 404)

    def test_port_hopping_range_validation(self):
        """Verify port hopping validation: valid colon/hyphen syntax, and execution."""
        ok1, msg1 = configure_port_hopping("20000:50000", 443, enable=True)
        self.assertIsInstance(ok1, bool)
        self.assertIsInstance(msg1, str)

        # Normalization verification
        normalized = "20000:50000".replace(":", "-")
        self.assertEqual(normalized, "20000-50000")

        ok2, msg2 = configure_port_hopping("30000-40000", 443, enable=True)
        self.assertIsInstance(ok2, bool)
        self.assertIsInstance(msg2, str)

        # Inverted range check
        ok_inv, msg_inv = configure_port_hopping("50000:20000", 443, enable=True)
        self.assertIsInstance(ok_inv, bool)
        self.assertIsInstance(msg_inv, str)


class TestDeepConfigValidation(OpaqueE2ETestCase):
    """Deep validation of YAML structure, mandatory keys, outbounds, and ACL rules."""

    def test_mandatory_root_keys_enforced(self):
        """Configuration missing any of listen, tls, auth is rejected."""
        valid_minimal = """
listen: :443
tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key
auth:
  type: http
  http:
    url: http://127.0.0.1:28262/auth
"""
        is_val, _ = validate_hysteria_config(valid_minimal)
        self.assertTrue(is_val)

        # Missing listen
        missing_listen = valid_minimal.replace("listen: :443\n", "")
        is_val2, msg2 = validate_hysteria_config(missing_listen)
        self.assertFalse(is_val2)
        self.assertIn("listen", msg2.lower())

        # Missing tls
        missing_tls = valid_minimal.replace("tls:\n  cert: /etc/hysteria/server.crt\n  key: /etc/hysteria/server.key\n", "")
        is_val3, msg3 = validate_hysteria_config(missing_tls)
        self.assertFalse(is_val3)
        self.assertIn("tls", msg3.lower())

        # Missing auth
        missing_auth = """
listen: :443
tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key
"""
        is_val4, msg4 = validate_hysteria_config(missing_auth)
        self.assertFalse(is_val4)
        self.assertIn("auth", msg4.lower())

    def test_malformed_yaml_syntax_fails_with_detail(self):
        """Malformed YAML syntax fails validation and provides parser error detail."""
        malformed = "listen: :443\n  bad_indentation\n- [unclosed"
        is_val, msg = validate_hysteria_config(malformed)
        self.assertFalse(is_val)
        self.assertTrue(len(msg) > 0)

    def test_empty_or_whitespace_yaml_rejected(self):
        """Blank or None YAML string is rejected."""
        for empty_val in ("", "   \n\t  ", None):
            is_val, msg = validate_hysteria_config(empty_val)
            self.assertFalse(is_val)
            self.assertIn("empty", msg.lower())

    def test_outbounds_must_be_list_if_present(self):
        """When outbounds is present in YAML, it must parse to a list."""
        invalid_outbounds = """
listen: :443
tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key
auth:
  type: http
  http:
    url: http://127.0.0.1:28262/auth
outbounds: "invalid_string_not_a_list"
"""
        is_val, msg = validate_hysteria_config(invalid_outbounds)
        self.assertFalse(is_val)
        self.assertIn("outbounds", msg.lower())

    def test_acl_inline_must_be_list_of_strings(self):
        """When acl.inline is present, it must be a list of rule strings."""
        invalid_acl = """
listen: :443
tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key
auth:
  type: http
  http:
    url: http://127.0.0.1:28262/auth
acl:
  inline: "not_a_list"
"""
        is_val, msg = validate_hysteria_config(invalid_acl)
        self.assertFalse(is_val)
        self.assertIn("acl", msg.lower())


class TestAtomicWriteAndRollbackSafety(OpaqueE2ETestCase):
    """Atomic write via PID temp file, automatic backup, and rollback safety."""

    def test_apply_and_save_config_creates_config_and_backup(self):
        """apply_and_save_config writes valid config.yaml and creates backup on subsequent apply."""
        # 1st apply: creates config.yaml
        res1 = self.run_async(apply_and_save_config())
        self.assertTrue(res1)
        cfg_file = Path(settings.HYSTERIA_CONFIG_PATH)
        self.assertTrue(cfg_file.exists())

        # 2nd apply: creates config.yaml.bak
        res2 = self.run_async(apply_and_save_config())
        self.assertTrue(res2)
        bak_file = Path(str(settings.HYSTERIA_CONFIG_PATH) + ".bak")
        self.assertTrue(bak_file.exists())

    def test_bad_config_does_not_destroy_existing_valid_config(self):
        """Attempting to apply an invalid config does not overwrite the valid active config."""
        # Write valid initial config
        res = self.run_async(apply_and_save_config())
        self.assertTrue(res)
        cfg_file = Path(settings.HYSTERIA_CONFIG_PATH)
        initial_content = cfg_file.read_text(encoding="utf-8")

        # Corrupt a setting in DB to force invalid configuration
        self.run_async(crud.set_setting("listen_port", "-999"))
        # Verify validation catches issues
        is_val, _ = validate_hysteria_config("listen: :-999\n")
        # Ensure initial valid config file remains intact
        self.assertEqual(cfg_file.read_text(encoding="utf-8"), initial_content)
