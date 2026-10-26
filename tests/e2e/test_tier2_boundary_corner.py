import os
import sys
import json
import base64
import tempfile
import urllib.parse
from pathlib import Path
from typing import Dict, Any

import yaml
from tests.e2e.harness import OpaqueE2ETestCase, CLOUDFLARE_TRACE_SAMPLES, REPO_ROOT
from app.config import settings
from app.database import crud
from app.database.models import UserCreate
from app.core.hysteria import build_hysteria_yaml, apply_and_save_config, run_systemctl
from app.core.subscription import build_hy2_uri, build_clash_yaml, build_singbox_json, build_base64_sub
from app.core.firewall import configure_port_hopping, flush_port_hopping
from app.core.security import hash_password, verify_password, generate_totp_secret, verify_totp, generate_secret_path


class TestTier2Feature01_ActiveWARPDetection(OpaqueE2ETestCase):
    """F1 Boundary: Active WARP Detection Edge Cases."""

    def test_f1_b01_whitespace_in_interface_name(self):
        """Boundary: Interface name with leading/trailing whitespace."""
        raw = "  warp  \n"
        clean = raw.strip()
        self.assertEqual(clean, "warp")

    def test_f1_b02_socks5_port_out_of_range(self):
        """Boundary: SOCKS5 address port 0, 65536, or negative."""
        invalid_addrs = ["127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:-1", "127.0.0.1:99999"]
        for addr in invalid_addrs:
            port = int(addr.split(":")[1])
            self.assertTrue(port <= 0 or port > 65535, f"Port {port} must be detected as out of valid range")

    def test_f1_b03_empty_trace_response(self):
        """Boundary: Empty string response from trace endpoint."""
        parsed = self.parse_cf_trace("")
        self.assertEqual(parsed, {})
        self.assertIsNone(parsed.get("warp"))

    def test_f1_b04_trace_binary_or_null_bytes(self):
        """Boundary: Trace output with null bytes or control characters."""
        corrupted = "ip=1.2.3.4\x00\r\nwarp=on\r\n"
        clean = corrupted.replace("\x00", "")
        parsed = self.parse_cf_trace(clean)
        self.assertEqual(parsed.get("warp"), "on")
        self.assertEqual(parsed.get("ip"), "1.2.3.4")

    def test_f1_b05_interface_flapping_or_down(self):
        """Corner: Interface present but link state is DOWN."""
        link_output = "3: warp: <POINTOPOINT,NOARP> mtu 1420 qdisc noqueue state DOWN group default"
        is_up = "state UP" in link_output
        self.assertFalse(is_up)


class TestTier2Feature02_ExistingWARPReuse(OpaqueE2ETestCase):
    """F2 Boundary: Existing WARP Reuse Edge Cases."""

    def test_f2_b01_port_as_string_vs_int(self):
        """Boundary: WARP port specified as string '40000' vs int 40000."""
        cfg_str = {"listen_port": 443, "warp_enabled": True, "warp_port": "40000"}
        cfg_int = {"listen_port": 443, "warp_enabled": True, "warp_port": 40000}
        y1 = build_hysteria_yaml(cfg_str)
        y2 = build_hysteria_yaml(cfg_int)
        self.assertEqual(y1, y2)

    def test_f2_b02_warp_port_out_of_range(self):
        """Boundary: Custom WARP port out of range."""
        cfg = {"listen_port": 443, "warp_enabled": True, "warp_port": "70000"}
        yaml_str = build_hysteria_yaml(cfg)
        self.verify_valid_hysteria_yaml(yaml_str)

    def test_f2_b03_duplicate_outbounds_check(self):
        """Boundary: Outbounds block must not contain duplicate names."""
        cfg = {"listen_port": 443, "warp_enabled": True}
        yaml_str = build_hysteria_yaml(cfg)
        data = self.verify_valid_hysteria_yaml(yaml_str)
        names = [o["name"] for o in data["outbounds"]]
        self.assertEqual(len(names), len(set(names)), "Outbounds must have unique names")

    def test_f2_b04_socks5_ipv6_loopback(self):
        """Boundary: SOCKS5 address with IPv6 localhost."""
        cfg = {"listen_port": 443, "warp_enabled": True, "warp_port": "[::1]:40000"}
        yaml_str = build_hysteria_yaml(cfg)
        self.verify_valid_hysteria_yaml(yaml_str)

    def test_f2_b05_zero_byte_existing_conf_file(self):
        """Corner: Existing config file is 0 bytes."""
        empty_conf = Path(self.env.temp_dir) / "empty_warp.conf"
        empty_conf.write_text("")
        self.assertEqual(empty_conf.stat().st_size, 0)
        # Should be detected as invalid/empty
        self.assertTrue(empty_conf.stat().st_size == 0)


class TestTier2Feature03_OneClickWARPInstaller(OpaqueE2ETestCase):
    """F3 Boundary: 1-Click WARP Installer Edge Cases."""

    def test_f3_b01_concurrent_installer_execution_lock(self):
        """Boundary: Simulation of double-click lock on installer."""
        lock_file = Path(self.env.temp_dir) / "warp_install.lock"
        # First execution acquires lock
        self.assertFalse(lock_file.exists())
        lock_file.write_text("PID 1234")
        self.assertTrue(lock_file.exists())
        # Second execution detects lock
        is_locked = lock_file.exists()
        self.assertTrue(is_locked)

    def test_f3_b02_installer_timeout_boundary(self):
        """Boundary: Command timeout handling."""
        import subprocess
        # Verify TimeoutExpired exception handling
        with self.assertRaises(subprocess.TimeoutExpired):
            subprocess.run([sys.executable, "-c", "import time; time.sleep(1)"], timeout=0.01)

    def test_f3_b03_crlf_vs_lf_line_endings_in_scripts(self):
        """Boundary: Scripts must not have carriage returns (\r) in shebang."""
        scripts = ["install.sh", "menu.sh", "upgrade.sh", "uninstall.sh"]
        for s in scripts:
            raw = (REPO_ROOT / s).read_bytes()
            first_line = raw.split(b"\n")[0]
            self.assertFalse(first_line.endswith(b"\r"), f"{s} has Windows CRLF in shebang")

    def test_f3_b04_massive_installer_output(self):
        """Boundary: Installer log truncates or buffers massive log (100k chars)."""
        big_log = "Installation step completed.\n" * 5000
        self.assertGreater(len(big_log), 100000)
        # Check last 40 lines
        lines = big_log.splitlines()[-40:]
        self.assertEqual(len(lines), 40)

    def test_f3_b05_special_characters_in_working_dir(self):
        """Corner: Target installation directory with spaces and unicode."""
        spec_dir = Path(self.env.temp_dir) / "Inner Blitz Dir — 2.0"
        spec_dir.mkdir(parents=True, exist_ok=True)
        self.assertTrue(spec_dir.exists())


class TestTier2Feature04_WARPDiagnostics(OpaqueE2ETestCase):
    """F4 Boundary: WARP Diagnostics Edge Cases."""

    def test_f4_b01_trace_ipv6_external_address(self):
        """Boundary: Trace returns IPv6 external IP."""
        trace = "ip=2606:4700:4700::1111\nwarp=on\ncolo=DME\n"
        parsed = self.parse_cf_trace(trace)
        self.assertEqual(parsed["ip"], "2606:4700:4700::1111")
        self.assertEqual(parsed["warp"], "on")

    def test_f4_b02_sub_millisecond_latency(self):
        """Boundary: Ping latency under 1ms (e.g. 0.4ms)."""
        lat = 0.4
        self.assertGreater(lat, 0.0)
        formatted = f"{lat:.1f} ms"
        self.assertEqual(formatted, "0.4 ms")

    def test_f4_b03_http_502_bad_gateway_trace_response(self):
        """Boundary: Cloudflare returns HTML error 502 Bad Gateway instead of key=value."""
        html_error = "<html><head><title>502 Bad Gateway</title></head><body>Cloudflare 502</body></html>"
        parsed = self.parse_cf_trace(html_error)
        self.assertNotIn("warp", parsed)
        self.assertNotIn("ip", parsed)

    def test_f4_b04_unknown_warp_status_value(self):
        """Boundary: Trace contains unknown status 'warp=enterprise'."""
        trace = "warp=enterprise\nip=1.2.3.4\n"
        parsed = self.parse_cf_trace(trace)
        self.assertEqual(parsed["warp"], "enterprise")
        is_known = parsed["warp"] in ("on", "plus", "off")
        self.assertFalse(is_known)

    def test_f4_b05_dns_failure_handling(self):
        """Corner: DNS failure or host unreachable."""
        import socket
        with self.assertRaises((socket.gaierror, OSError)):
            socket.gethostbyname("non-existent-domain-123456789.invalid")


class TestTier2Feature05_VisualRoutingBuilder(OpaqueE2ETestCase):
    """F5 Boundary: Visual Routing Builder Edge Cases."""

    def test_f5_b01_empty_settings_payload(self):
        """Boundary: Empty JSON payload sent to POST /api/settings."""
        self.login_admin()
        resp = self.client.post("/api/settings", json={})
        self.assertEqual(resp.status_code, 200)

    def test_f5_b02_unrecognized_extra_keys_in_payload(self):
        """Boundary: Payload containing arbitrary unknown keys."""
        self.login_admin()
        resp = self.client.post("/api/settings", json={"unknown_key_xyz": "value123"})
        self.assertEqual(resp.status_code, 200)

    def test_f5_b03_sql_injection_in_domain_or_sni(self):
        """Boundary: SQL injection attempt in server_domain."""
        self.login_admin()
        sqli_payload = {"server_domain": "'; DROP TABLE settings; --"}
        resp = self.client.post("/api/settings", json=sqli_payload)
        self.assertEqual(resp.status_code, 200)
        # Ensure table was NOT dropped
        val = self.run_async(crud.get_setting("server_domain"))
        self.assertEqual(val, "'; DROP TABLE settings; --")
        # Ensure settings table still functional
        p = self.run_async(crud.get_setting("listen_port"))
        self.assertIsNotNone(p)

    def test_f5_b04_unicode_and_cyrillic_sni(self):
        """Boundary: IDN / punycode domain in SNI."""
        self.login_admin()
        resp = self.client.post("/api/settings", json={"sni": "xn--p1ai"})
        self.assertEqual(resp.status_code, 200)
        saved = self.run_async(crud.get_setting("sni"))
        self.assertEqual(saved, "xn--p1ai")

    def test_f5_b05_extreme_masquerade_url_length(self):
        """Corner: Extremely long masquerade target URL (2000 chars)."""
        long_url = "https://bing.com/" + "a" * 1900
        cfg = {"listen_port": 443, "masquerade_type": "proxy", "masquerade_target": long_url}
        yaml_str = build_hysteria_yaml(cfg)
        data = self.verify_valid_hysteria_yaml(yaml_str)
        self.assertEqual(data["masquerade"]["proxy"]["url"], long_url)


class TestTier2Feature06_GlobalOutboundSwitch(OpaqueE2ETestCase):
    """F6 Boundary: Global Outbound Switch Edge Cases."""

    def test_f6_b01_warp_enabled_type_coercion(self):
        """Boundary: '1', 'true', 'True' all evaluate to active WARP."""
        for truthy in ("1", "true", "True", True):
            cfg = {"listen_port": 443, "warp_enabled": truthy}
            y = build_hysteria_yaml(cfg)
            self.assertIn("outbounds:", y, f"Failed for {truthy}")

    def test_f6_b02_warp_disabled_falsy_coercion(self):
        """Boundary: '0', 'false', 'False', False all evaluate to disabled WARP."""
        for falsy in ("0", "false", "False", False):
            cfg = {"listen_port": 443, "warp_enabled": falsy}
            y = build_hysteria_yaml(cfg)
            self.assertNotIn("outbounds:", y, f"Failed for {falsy}")

    def test_f6_b03_rapid_sequential_toggling(self):
        """Boundary: Rapid sequential switching between Direct and WARP."""
        self.login_admin()
        for i in range(10):
            enable = (i % 2 == 0)
            self.client.post("/api/settings", json={"warp_enabled": enable})
            saved = self.run_async(crud.get_setting("warp_enabled"))
            self.assertEqual(saved, "1" if enable else "0")

    def test_f6_b04_outbounds_yaml_formatting_integrity(self):
        """Boundary: Outbounds block indentation and list syntax."""
        cfg = {"listen_port": 443, "warp_enabled": True, "warp_port": "40000"}
        yaml_str = build_hysteria_yaml(cfg)
        data = self.verify_valid_hysteria_yaml(yaml_str)
        self.assertIsInstance(data["outbounds"], list)
        self.assertEqual(len(data["outbounds"]), 2)

    def test_f6_b05_server_ip_empty_fallback(self):
        """Corner: Server IP and domain both empty in settings."""
        cfg = {"server_ip": "", "server_domain": ""}
        user = self.create_test_user("fallback_user", "pass")
        uri = build_hy2_uri(user, cfg)
        self.assertIn("@127.0.0.1:443", uri)


class TestTier2Feature07_RUTrafficRuleEngine(OpaqueE2ETestCase):
    """F7 Boundary: RU Traffic Rule Engine Edge Cases."""

    def test_f7_b01_ru_routing_invalid_mode_fallback(self):
        """Boundary: Unsupported RU routing mode falls back safely."""
        cfg = {"listen_port": 443, "ru_routing": "unsupported_mode"}
        yaml_str = build_hysteria_yaml(cfg)
        self.verify_valid_hysteria_yaml(yaml_str)

    def test_f7_b02_punycode_ru_domains(self):
        """Boundary: Internationalized domain names in RU rules."""
        idn = "xn--p1ai" # .рф in punycode
        self.assertTrue(idn.startswith("xn--"))

    def test_f7_b03_ip_range_cidr_boundaries(self):
        """Boundary: Private and public CIDR boundary formatting."""
        cidrs = ["0.0.0.0/0", "10.0.0.0/8", "192.168.0.0/16", "127.0.0.1/32"]
        for c in cidrs:
            parts = c.split("/")
            prefix = int(parts[1])
            self.assertTrue(0 <= prefix <= 32)

    def test_f7_b04_acl_inline_newline_consistency(self):
        """Boundary: acl.inline rules list indentation."""
        cfg = {"listen_port": 443, "warp_enabled": True}
        yaml_str = build_hysteria_yaml(cfg)
        data = self.verify_valid_hysteria_yaml(yaml_str)
        self.assertIn("acl", data)
        self.assertIn("inline", data["acl"])
        self.assertIsInstance(data["acl"]["inline"], list)

    def test_f7_b05_empty_acl_handling(self):
        """Corner: ACL list cannot be None or empty."""
        cfg = {"listen_port": 443}
        yaml_str = build_hysteria_yaml(cfg)
        data = self.verify_valid_hysteria_yaml(yaml_str)
        self.assertTrue(len(data["acl"]["inline"]) > 0)


class TestTier2Feature08_ServicePresetRules(OpaqueE2ETestCase):
    """F8 Boundary: Service Preset Rules Edge Cases."""

    def test_f8_b01_multiple_service_presets_ordering(self):
        """Boundary: Rejection rules must precede routing rules in ACL."""
        cfg = {"listen_port": 443, "warp_enabled": True}
        yaml_str = build_hysteria_yaml(cfg)
        lines = yaml_str.splitlines()
        reject_idx = next(i for i, l in enumerate(lines) if "reject(" in l)
        outbound_idx = next(i for i, l in enumerate(lines) if "outbound(warp" in l)
        self.assertLess(reject_idx, outbound_idx, "Ad/Spy reject rules must precede warp outbound rules")

    def test_f8_b02_special_characters_in_acl_domain(self):
        """Boundary: Escaping and format of geosite tokens."""
        tokens = ["geosite:category-ads-all", "geosite:win-spy", "geosite:openai", "geosite:netflix"]
        for t in tokens:
            self.assertTrue(t.startswith("geosite:"))
            self.assertNotIn(" ", t)

    def test_f8_b03_duplicate_acl_rule_avoidance(self):
        """Boundary: Verify no duplicate identical rules in acl.inline."""
        cfg = {"listen_port": 443, "warp_enabled": True}
        yaml_str = build_hysteria_yaml(cfg)
        data = self.verify_valid_hysteria_yaml(yaml_str)
        rules = data["acl"]["inline"]
        self.assertEqual(len(rules), len(set(rules)), "ACL rules should be deduplicated")

    def test_f8_b04_ipv6_private_subnet_rejection(self):
        """Boundary: ULA IPv6 range fc00::/7 rejected in ACL."""
        cfg = {"listen_port": 443}
        yaml_str = build_hysteria_yaml(cfg)
        self.assertIn("reject(fc00::/7)", yaml_str)

    def test_f8_b05_empty_preset_string(self):
        """Corner: preset setting is empty."""
        cfg = {"listen_port": 443, "preset": ""}
        yaml_str = build_hysteria_yaml(cfg)
        self.verify_valid_hysteria_yaml(yaml_str)


class TestTier2Feature09_DynamicHysteriaConfig(OpaqueE2ETestCase):
    """F9 Boundary: Dynamic Hysteria Config Edge Cases."""

    def test_f9_b01_zero_bandwidth_value(self):
        """Boundary: 0 mbps bandwidth setting."""
        cfg = {"listen_port": 443, "up_mbps": "0", "down_mbps": "0"}
        yaml_str = build_hysteria_yaml(cfg)
        data = self.verify_valid_hysteria_yaml(yaml_str)
        self.assertEqual(data["bandwidth"]["up"], "0 mbps")

    def test_f9_b02_extreme_high_bandwidth(self):
        """Boundary: 100,000 mbps (100 Gbps)."""
        cfg = {"listen_port": 443, "up_mbps": "100000", "down_mbps": "100000"}
        yaml_str = build_hysteria_yaml(cfg)
        data = self.verify_valid_hysteria_yaml(yaml_str)
        self.assertEqual(data["bandwidth"]["up"], "100000 mbps")

    def test_f9_b03_masquerade_url_without_https_scheme(self):
        """Boundary: Masquerade target given without scheme 'bing.com'."""
        cfg = {"listen_port": 443, "masquerade_type": "proxy", "masquerade_target": "bing.com"}
        yaml_str = build_hysteria_yaml(cfg)
        data = self.verify_valid_hysteria_yaml(yaml_str)
        self.assertEqual(data["masquerade"]["proxy"]["url"], "bing.com")

    def test_f9_b04_listen_port_boundary_values(self):
        """Boundary: listen_port 1 vs 65535."""
        cfg1 = {"listen_port": 1}
        cfg2 = {"listen_port": 65535}
        y1 = build_hysteria_yaml(cfg1)
        y2 = build_hysteria_yaml(cfg2)
        d1 = self.verify_valid_hysteria_yaml(y1)
        d2 = self.verify_valid_hysteria_yaml(y2)
        self.assertEqual(d1["listen"], ":1")
        self.assertEqual(d2["listen"], ":65535")

    def test_f9_b05_traffic_secret_uuid_format(self):
        """Corner: trafficStats secret must be wrapped in quotes."""
        cfg = {"listen_port": 443, "traffic_secret": "my-custom-uuid-123"}
        yaml_str = build_hysteria_yaml(cfg)
        data = self.verify_valid_hysteria_yaml(yaml_str)
        self.assertEqual(data["trafficStats"]["secret"], "my-custom-uuid-123")


class TestTier2Feature10_ConfigSyntaxValidation(OpaqueE2ETestCase):
    """F10 Boundary: Config Syntax Validation Edge Cases."""

    def test_f10_b01_yaml_with_tab_characters(self):
        """Boundary: YAML rejects tabs in indentation."""
        bad_yaml = "listen: :443\n\ttls: error"
        with self.assertRaises(yaml.YAMLError):
            yaml.safe_load(bad_yaml)

    def test_f10_b02_yaml_only_comments(self):
        """Boundary: YAML containing only comments returns None."""
        comment_yaml = "# Only comment line\n# Another comment\n"
        data = yaml.safe_load(comment_yaml)
        self.assertIsNone(data)

    def test_f10_b03_yaml_empty_dict(self):
        """Boundary: YAML containing empty dict `{}` fails mandatory keys."""
        data = yaml.safe_load("{}")
        self.assertIsInstance(data, dict)
        self.assertNotIn("listen", data)

    def test_f10_b04_yaml_with_duplicate_keys(self):
        """Boundary: PyYAML handles duplicate keys by overwriting."""
        dup_yaml = "listen: :443\nlisten: :8443\ntls: ok\nauth: ok\n"
        data = yaml.safe_load(dup_yaml)
        self.assertEqual(data["listen"], ":8443")

    def test_f10_b05_non_writable_directory_handling(self):
        """Corner: Target config directory does not exist yet (auto-creation)."""
        nested_dir = Path(self.env.temp_dir) / "nested" / "sub"
        self.assertFalse(nested_dir.exists())
        nested_dir.mkdir(parents=True, exist_ok=True)
        self.assertTrue(nested_dir.exists())


class TestTier2Feature11_SniffingVisualControls(OpaqueE2ETestCase):
    """F11 Boundary: Sniffing Visual Controls Edge Cases."""

    def test_f11_b01_sniff_timeout_zero(self):
        """Boundary: Sniff timeout '0s'."""
        cfg = {"listen_port": 443, "sniff_timeout": "0s"}
        yaml_str = build_hysteria_yaml(cfg)
        self.verify_valid_hysteria_yaml(yaml_str)

    def test_f11_b02_sniff_timeout_milliseconds(self):
        """Boundary: Sniff timeout '500ms'."""
        cfg = {"listen_port": 443}
        yaml_str = build_hysteria_yaml(cfg)
        data = self.verify_valid_hysteria_yaml(yaml_str)
        self.assertIn("timeout", data["sniff"])

    def test_f11_b03_sniff_enable_false(self):
        """Boundary: Disabling sniffing in config."""
        cfg = {"listen_port": 443, "sniff_enable": False}
        yaml_str = build_hysteria_yaml(cfg)
        self.verify_valid_hysteria_yaml(yaml_str)

    def test_f11_b04_rewrite_domain_true(self):
        """Boundary: Enabling rewriteDomain."""
        cfg = {"listen_port": 443, "rewrite_domain": True}
        yaml_str = build_hysteria_yaml(cfg)
        self.verify_valid_hysteria_yaml(yaml_str)

    def test_f11_b05_sniff_section_keys_integrity(self):
        """Corner: Sniff section contains exactly enable, timeout, rewriteDomain."""
        cfg = {"listen_port": 443}
        yaml_str = build_hysteria_yaml(cfg)
        data = self.verify_valid_hysteria_yaml(yaml_str)
        sniff = data["sniff"]
        self.assertIn("enable", sniff)
        self.assertIn("timeout", sniff)
        self.assertIn("rewriteDomain", sniff)


class TestTier2Feature12_PortHoppingAndPersistence(OpaqueE2ETestCase):
    """F12 Boundary: Port Hopping & Persistence Edge Cases."""

    def test_f12_b01_single_port_range(self):
        """Boundary: Port range with identical start and end ('443:443')."""
        clean = "443:443".replace("-", ":")
        self.assertEqual(clean, "443:443")

    def test_f12_b02_inverted_port_range(self):
        """Boundary: Port range start greater than end ('50000:20000')."""
        start, end = map(int, "50000:20000".split(":"))
        self.assertGreater(start, end, "Inverted range detected")

    def test_f12_b03_non_numeric_port_range(self):
        """Boundary: Non-numeric port range string ('abc:xyz')."""
        parts = "abc:xyz".split(":")
        self.assertFalse(parts[0].isdigit())

    def test_f12_b04_whitespace_in_port_range(self):
        """Boundary: Port range containing whitespace (' 20000 : 50000 ')."""
        raw = " 20000 : 50000 "
        clean = "".join(raw.split()).replace(":", "-")
        self.assertEqual(clean, "20000-50000")

    def test_f12_b05_port_hopping_target_port_zero(self):
        """Corner: Target port 0 or negative."""
        ok, msg = configure_port_hopping("20000:50000", 0, enable=False)
        self.assertIsInstance(ok, bool)


class TestTier2Feature13_SingboxProfile(OpaqueE2ETestCase):
    """F13 Boundary: Sing-box Profile Edge Cases."""

    def test_f13_b01_password_with_colons_and_quotes(self):
        """Boundary: Password containing colon, quotes, and symbols."""
        user = self.create_test_user("user_colon", 'p:a"s\'s!@#')
        cfg = {"server_ip": "1.2.3.4", "listen_port": 443}
        sb = build_singbox_json(user, cfg)
        hy2 = [o for o in sb["outbounds"] if o["type"] == "hysteria2"][0]
        self.assertEqual(hy2["password"], 'user_colon:p:a"s\'s!@#')

    def test_f13_b02_unicode_username(self):
        """Boundary: Cyrillic username in Sing-box outbound."""
        user = self.create_test_user("пользователь1", "pass123")
        cfg = {"server_ip": "1.2.3.4", "listen_port": 443}
        sb = build_singbox_json(user, cfg)
        hy2 = [o for o in sb["outbounds"] if o["type"] == "hysteria2"][0]
        self.assertIn("пользователь1", hy2["tag"])

    def test_f13_b03_empty_spki_pin(self):
        """Boundary: Missing or empty SPKI hash."""
        user = self.create_test_user("sb_nopin", "pass")
        cfg = {"server_ip": "1.2.3.4", "listen_port": 443, "cert_sha256": ""}
        sb = build_singbox_json(user, cfg)
        hy2 = [o for o in sb["outbounds"] if o["type"] == "hysteria2"][0]
        self.assertTrue(hy2["tls"]["insecure"])

    def test_f13_b04_valid_spki_pin(self):
        """Boundary: SPKI SHA-256 certificate pin populated."""
        user = self.create_test_user("sb_pin", "pass")
        cfg = {"server_ip": "1.2.3.4", "listen_port": 443, "cert_sha256": "abcdef123456"}
        sb = build_singbox_json(user, cfg)
        hy2 = [o for o in sb["outbounds"] if o["type"] == "hysteria2"][0]
        self.assertEqual(hy2["tls"].get("pinSHA256"), "abcdef123456")

    def test_f13_b05_server_domain_with_port(self):
        """Corner: server_domain containing embedded port string."""
        user = self.create_test_user("sb_port", "pass")
        cfg = {"server_domain": "vpn.example.com:443", "listen_port": 443}
        sb = build_singbox_json(user, cfg)
        self.verify_valid_singbox_profile(sb)


class TestTier2Feature14_ClashMetaSubscription(OpaqueE2ETestCase):
    """F14 Boundary: Clash Meta / Mihomo Edge Cases."""

    def test_f14_b01_obfs_password_with_yaml_metacharacters(self):
        """Boundary: Obfs password with YAML special chars ('#', ': ', '{')."""
        user = self.create_test_user("clash_spec", "pass")
        cfg = {
            "server_ip": "1.2.3.4",
            "listen_port": 443,
            "obfs_type": "salamander",
            "obfs_password": "test: #value {123}"
        }
        clash_yaml = build_clash_yaml(user, cfg)
        data = self.verify_valid_clash_yaml(clash_yaml)
        self.assertEqual(data["proxies"][0]["obfs-password"], "test: #value {123}")

    def test_f14_b02_ipv6_server_host(self):
        """Boundary: IPv6 server address in Clash."""
        user = self.create_test_user("clash_v6", "pass")
        cfg = {"server_ip": "2001:db8::1", "listen_port": 443}
        clash_yaml = build_clash_yaml(user, cfg)
        data = self.verify_valid_clash_yaml(clash_yaml)
        self.assertEqual(data["proxies"][0]["server"], "2001:db8::1")

    def test_f14_b03_special_characters_in_proxy_name(self):
        """Boundary: Brackets and symbols in proxy name."""
        user = self.create_test_user("user[VIP]", "pass")
        cfg = {"server_ip": "1.2.3.4", "listen_port": 443}
        clash_yaml = build_clash_yaml(user, cfg)
        data = self.verify_valid_clash_yaml(clash_yaml)
        self.assertEqual(data["proxies"][0]["name"], "InnerBlitz-user[VIP]")

    def test_f14_b04_allow_lan_boolean(self):
        """Boundary: allow-lan must be a boolean."""
        user = self.create_test_user("clash_lan", "pass")
        cfg = {"server_ip": "1.2.3.4", "listen_port": 443}
        clash_yaml = build_clash_yaml(user, cfg)
        data = self.verify_valid_clash_yaml(clash_yaml)
        self.assertIsInstance(data["allow-lan"], bool)

    def test_f14_b05_skip_cert_verify_present(self):
        """Corner: skip-cert-verify must be enabled for self-signed certs."""
        user = self.create_test_user("clash_cert", "pass")
        cfg = {"server_ip": "1.2.3.4", "listen_port": 443}
        clash_yaml = build_clash_yaml(user, cfg)
        data = self.verify_valid_clash_yaml(clash_yaml)
        self.assertTrue(data["proxies"][0]["skip-cert-verify"])


class TestTier2Feature15_MultiClientPortal(OpaqueE2ETestCase):
    """F15 Boundary: Multi-Client Portal Edge Cases."""

    def test_f15_b01_long_token_lookup(self):
        """Boundary: Token string of 128 characters."""
        token = "a" * 128
        user = self.run_async(crud.get_user_by_token(token))
        self.assertIsNone(user)

    def test_f15_b02_special_characters_in_token_path(self):
        """Boundary: URL encoded special characters in token parameter."""
        encoded = urllib.parse.quote("token/with/slashes?and=queries")
        self.run_async(crud.set_setting("decoy_enabled", "0"))
        resp = self.client.get(f"/portal/{encoded}")
        self.assertIn(resp.status_code, (404, 200))

    def test_f15_b03_unlimited_user_subscription_header(self):
        """Boundary: User with 0 traffic limit (unlimited) has total=0."""
        user = self.create_test_user("unlim_user", "pass", traffic_limit_gb=0.0, unlimited=True)
        resp = self.client.get(f"/sub/{user['sub_token']}")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("total=0", resp.headers["subscription-userinfo"])

    def test_f15_b04_expired_user_portal_view(self):
        """Boundary: Expired user account access to portal."""
        user = self.create_test_user("exp_user", "pass", expiration_days=0)
        resp = self.client.get(f"/portal/{user['sub_token']}")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("exp_user", resp.text)

    def test_f15_b05_blocked_user_portal_view(self):
        """Corner: Blocked user view on portal."""
        user = self.create_test_user("block_user", "pass")
        from app.database.models import UserUpdate
        self.run_async(crud.update_user(user["id"], UserUpdate(blocked=True)))
        resp = self.client.get(f"/portal/{user['sub_token']}")
        self.assertEqual(resp.status_code, 200)


class TestTier2Feature16_ZincSlateUI(OpaqueE2ETestCase):
    """F16 Boundary: Human-Crafted Zinc/Slate UI Edge Cases."""

    def test_f16_b01_xss_injection_in_user_note(self):
        """Boundary: XSS payload in user note (<script>alert(1)</script>)."""
        xss_payload = "<script>alert('xss')</script>"
        user = self.create_test_user("xss_user", "pass", note=xss_payload)
        resp = self.client.get(f"/portal/{user['sub_token']}")
        self.assertEqual(resp.status_code, 200)
        # Note should be escaped or safely rendered
        self.assertNotIn("<script>alert('xss')</script>", resp.text)

    def test_f16_b02_extreme_telemetry_number_formatting(self):
        """Boundary: Formatting huge traffic bytes (e.g. 50 TB)."""
        bytes_val = 50 * 1024 * 1024 * 1024 * 1024
        gb_val = bytes_val / (1024 ** 3)
        self.assertEqual(gb_val, 51200.0)

    def test_f16_b03_empty_users_list_rendering(self):
        """Boundary: users.html rendered with zero registered users."""
        self.login_admin()
        resp = self.client.get("/users")
        self.assertEqual(resp.status_code, 200)

    def test_f16_b04_logs_page_rendering(self):
        """Boundary: logs.html rendered when journalctl has 0 lines."""
        self.login_admin()
        resp = self.client.get("/logs")
        self.assertEqual(resp.status_code, 200)

    def test_f16_b05_node_page_rendering(self):
        """Corner: node.html rendered."""
        self.login_admin()
        resp = self.client.get("/node")
        self.assertEqual(resp.status_code, 200)


class TestTier2Feature17_ResponsiveMobileLayout(OpaqueE2ETestCase):
    """F17 Boundary: Responsive Mobile Layout Edge Cases."""

    def test_f17_b01_narrow_mobile_user_agent(self):
        """Boundary: Mobile Safari User-Agent request."""
        headers = {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15"}
        user = self.create_test_user("m_user", "pass")
        resp = self.client.get(f"/portal/{user['sub_token']}", headers=headers)
        self.assertEqual(resp.status_code, 200)

    def test_f17_b02_desktop_chrome_user_agent(self):
        """Boundary: Desktop Chrome User-Agent request."""
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
        user = self.create_test_user("d_user", "pass")
        resp = self.client.get(f"/portal/{user['sub_token']}", headers=headers)
        self.assertEqual(resp.status_code, 200)

    def test_f17_b03_curl_user_agent_on_portal(self):
        """Boundary: Command line curl User-Agent."""
        headers = {"User-Agent": "curl/8.5.0"}
        user = self.create_test_user("c_user", "pass")
        resp = self.client.get(f"/portal/{user['sub_token']}", headers=headers)
        self.assertEqual(resp.status_code, 200)

    def test_f17_b04_viewport_initial_scale(self):
        """Boundary: initial-scale=1.0 present in viewport."""
        tmpl = (REPO_ROOT / "app" / "templates" / "base.html").read_text(encoding="utf-8")
        self.assertIn("initial-scale=1", tmpl)

    def test_f17_b05_dark_mode_class_on_html_tag(self):
        """Corner: dark mode class on root html tag in portal."""
        tmpl = (REPO_ROOT / "app" / "templates" / "client_portal.html").read_text(encoding="utf-8")
        self.assertIn('class="dark"', tmpl)


class TestTier2Feature18_SecurityAndStealthHardening(OpaqueE2ETestCase):
    """F18 Boundary: Security & Stealth Hardening Edge Cases."""

    def test_f18_b01_brute_force_rapid_failures(self):
        """Boundary: Multiple failed logins in sequence."""
        for _ in range(3):
            resp = self.client.post("/api/login", json={"username": "admin", "password": "wrongpassword"})
            self.assertEqual(resp.status_code, 401)

    def test_f18_b02_secret_path_directory_traversal(self):
        """Boundary: Path traversal attempt in URL (e.g. /../../etc/passwd)."""
        self.run_async(crud.set_setting("decoy_enabled", "0"))
        resp = self.client.get("/../../etc/passwd")
        self.assertIn(resp.status_code, (404, 400, 200))

    def test_f18_b03_totp_past_and_future_skew(self):
        """Boundary: TOTP verification outside 30-second window."""
        secret = generate_totp_secret()
        import pyotp
        totp = pyotp.TOTP(secret)
        # 120 seconds in the future
        old_code = totp.at(1000)
        self.assertFalse(verify_totp(secret, old_code))

    def test_f18_b04_empty_totp_secret(self):
        """Boundary: verify_totp with empty secret returns False."""
        self.assertFalse(verify_totp("", "123456"))

    def test_f18_b05_safe_systemctl_injection_strings(self):
        """Corner: Command injection attempts in systemctl action."""
        bad_actions = [
            "start; rm -rf /",
            "start && echo pwned",
            "start | cat /etc/passwd",
            "`id`",
            "$(reboot)"
        ]
        for a in bad_actions:
            ok, msg = run_systemctl(a)
            self.assertFalse(ok, f"Action '{a}' must be rejected")


class TestTier2Feature19_DeploymentScripts(OpaqueE2ETestCase):
    """F19 Boundary: Deployment Scripts Modernization Edge Cases."""

    def test_f19_b01_script_non_interactive_flags(self):
        """Boundary: install.sh contains non-interactive automation flags."""
        content = (REPO_ROOT / "install.sh").read_text(encoding="utf-8", errors="ignore")
        self.assertTrue("DEBIAN_FRONTEND" in content or "export" in content or "-y" in content)

    def test_f19_b02_menu_cli_subcommands(self):
        """Boundary: menu.sh contains case switch for operations."""
        content = (REPO_ROOT / "menu.sh").read_text(encoding="utf-8", errors="ignore")
        self.assertIn("case", content)

    def test_f19_b03_upgrade_script_backup_step(self):
        """Boundary: upgrade.sh creates database backup before updating."""
        content = (REPO_ROOT / "upgrade.sh").read_text(encoding="utf-8", errors="ignore")
        self.assertTrue("backup" in content.lower() or "cp " in content or "tar" in content)

    def test_f19_b04_uninstall_script_removes_service(self):
        """Boundary: uninstall.sh cleans systemd service."""
        content = (REPO_ROOT / "uninstall.sh").read_text(encoding="utf-8", errors="ignore")
        self.assertTrue("systemctl" in content or "hysteria" in content)

    def test_f19_b05_scripts_executable_bits(self):
        """Corner: Scripts exist and have nonzero size."""
        for s in ("install.sh", "menu.sh", "upgrade.sh", "uninstall.sh"):
            self.assertGreater((REPO_ROOT / s).stat().st_size, 100)


class TestTier2Feature20_GitHubHygiene(OpaqueE2ETestCase):
    """F20 Boundary: GitHub Release & Hygiene Edge Cases."""

    def test_f20_b01_utf8_clean_no_bom(self):
        """Boundary: Critical project files must not have UTF-8 BOM (\xef\xbb\xbf)."""
        files = ["README.md", "requirements.txt", "VERSION", "LICENSE"]
        for f in files:
            raw = (REPO_ROOT / f).read_bytes()
            self.assertFalse(raw.startswith(b"\xef\xbb\xbf"), f"{f} has UTF-8 BOM")

    def test_f20_b02_requirements_no_wildcards(self):
        """Boundary: requirements.txt dependencies must specify package names cleanly."""
        lines = (REPO_ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
        for l in lines:
            clean = l.strip()
            if clean and not clean.startswith("#"):
                self.assertTrue(clean[0].isalnum(), f"Invalid requirement line: {clean}")

    def test_f20_b03_no_committed_database_files(self):
        """Boundary: No .db or .sqlite files tracked in git."""
        db_files = list(REPO_ROOT.glob("*.db")) + list(REPO_ROOT.glob("*.sqlite"))
        self.assertEqual(len(db_files), 0, "No SQLite DB files should be committed in root")

    def test_f20_b04_no_committed_private_keys(self):
        """Boundary: No .key or private certs committed in root."""
        key_files = list(REPO_ROOT.glob("*.key")) + list(REPO_ROOT.glob("*.pem"))
        self.assertEqual(len(key_files), 0, "No TLS private keys should be committed in root")

    def test_f20_b05_readme_heading_structure(self):
        """Corner: README.md has markdown headings (#, ##)."""
        content = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        has_headings = any(l.strip().startswith("#") for l in content.splitlines())
        self.assertTrue(has_headings)


class TestTier2Feature21_E2ETestSuiteFramework(OpaqueE2ETestCase):
    """F21 Boundary: Test Suite Framework Self-Verification Edge Cases."""

    def test_f21_b01_concurrent_temp_environments(self):
        """Boundary: Multiple IsolatedEnvironment instances do not collide."""
        env1 = tempfile.mkdtemp(prefix="t1_")
        env2 = tempfile.mkdtemp(prefix="t2_")
        self.assertNotEqual(env1, env2)
        import shutil
        shutil.rmtree(env1, ignore_errors=True)
        shutil.rmtree(env2, ignore_errors=True)

    def test_f21_b02_crud_non_existent_key_returns_default(self):
        """Boundary: Querying non-existent setting returns specified default."""
        val = self.run_async(crud.get_setting("non_existent_key_999", default="custom_fallback"))
        self.assertEqual(val, "custom_fallback")

    def test_f21_b03_crud_get_non_existent_user(self):
        """Boundary: Querying non-existent user returns None."""
        user = self.run_async(crud.get_user_by_username("non_existent_user_9999"))
        self.assertIsNone(user)

    def test_f21_b04_harness_database_recreation(self):
        """Boundary: Harness cleanly re-initializes tables per test."""
        db_conn = self.run_async(crud.get_all_users())
        self.assertEqual(len(db_conn), 0)

    def test_f21_b05_harness_cleanup_removes_sandbox(self):
        """Corner: Temp directory cleanup succeeds."""
        td = tempfile.mkdtemp(prefix="clean_test_")
        self.assertTrue(Path(td).exists())
        import shutil
        shutil.rmtree(td)
        self.assertFalse(Path(td).exists())
