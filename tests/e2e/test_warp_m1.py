"""
InnerBlitz Milestone M1: WARP Lifecycle & Diagnostics Test Suite
Hermetic opaque-box test suite verifying:
- Active WARP detection (WireGuard & SOCKS5 RFC 1928)
- Cloudflare trace parsing & HTML protection
- Connection reuse & database synchronization
- Dual-path trace diagnostics (Direct vs WARP, IP masking, latency delta)
- Asynchronous WarpProcessManager (ring-buffer logs, cancellation, timeout, concurrency)
- REST API endpoints on /api/warp
"""

import asyncio
import os
import unittest
from unittest.mock import patch, MagicMock

from tests.e2e.harness import OpaqueE2ETestCase, CLOUDFLARE_TRACE_SAMPLES
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
    WarpProcessManager,
    run_warp_installer,
    get_warp_service_name,
    restart_warp_service,
    repair_warp_service
)
from app.database import crud


class TestWARPCoreUnit(unittest.TestCase):
    """Unit tests for app.core.warp pure logic and protocol functions."""

    def test_parse_cloudflare_trace_valid(self):
        """Test parsing valid Cloudflare trace plaintext response."""
        sample = CLOUDFLARE_TRACE_SAMPLES["warp_on"]
        parsed = parse_cloudflare_trace(sample)
        self.assertEqual(parsed["warp"], "on")
        self.assertEqual(parsed["ip"], "104.28.194.5")
        self.assertEqual(parsed["colo"], "DME")
        self.assertEqual(parsed["loc"], "RU")
        self.assertEqual(parsed["tls"], "TLSv1.3")

    def test_parse_cloudflare_trace_warp_plus(self):
        """Test parsing trace with warp=plus."""
        sample = CLOUDFLARE_TRACE_SAMPLES["warp_plus"]
        parsed = parse_cloudflare_trace(sample)
        self.assertEqual(parsed["warp"], "plus")
        self.assertEqual(parsed["colo"], "FRA")

    def test_parse_cloudflare_trace_warp_off(self):
        """Test parsing trace with warp=off."""
        sample = CLOUDFLARE_TRACE_SAMPLES["warp_off"]
        parsed = parse_cloudflare_trace(sample)
        self.assertEqual(parsed["warp"], "off")
        self.assertEqual(parsed["ip"], "185.220.101.5")

    def test_parse_cloudflare_trace_html_rejection(self):
        """Test that HTML challenge / error pages raise ValueError."""
        html_sample = "<!DOCTYPE html><html><head><title>Cloudflare 502</title></head><body>Bad Gateway</body></html>"
        with self.assertRaises(ValueError):
            parse_cloudflare_trace(html_sample)

        html_short = "<html><head><title>Just a moment...</title></head></html>"
        with self.assertRaises(ValueError):
            parse_cloudflare_trace(html_short)

    def test_parse_cloudflare_trace_empty_or_corrupted(self):
        """Test empty string and lines without '='."""
        with self.assertRaises(ValueError):
            parse_cloudflare_trace("")

        corrupted = "random line\nanother line\nwarp=on\nfoo=bar"
        parsed = parse_cloudflare_trace(corrupted)
        self.assertEqual(parsed.get("warp"), "on")
        self.assertEqual(parsed.get("foo"), "bar")

    def test_check_socks5_alive_mock_success(self):
        """Test RFC 1928 SOCKS5 handshake against mock async server."""
        async def run_test():
            server = None
            async def mock_handler(reader, writer):
                data = await reader.read(3)
                if data == b"\x05\x01\x00":
                    writer.write(b"\x05\x00")
                    await writer.drain()
                writer.close()
                await writer.wait_closed()

            server = await asyncio.start_server(mock_handler, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            try:
                ok, latency = await check_socks5_alive("127.0.0.1", port, timeout=1.0)
                self.assertTrue(ok)
                self.assertIsNotNone(latency)
                self.assertGreaterEqual(latency, 0.0)
            finally:
                server.close()
                await server.wait_closed()

        asyncio.run(run_test())

    def test_check_socks5_alive_mock_non_socks_rejection(self):
        """Test that non-SOCKS service (e.g. HTTP) is rejected."""
        async def run_test():
            async def mock_handler(reader, writer):
                await reader.read(3)
                # HTTP error response
                writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                await writer.drain()
                writer.close()
                await writer.wait_closed()

            server = await asyncio.start_server(mock_handler, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            try:
                ok, latency = await check_socks5_alive("127.0.0.1", port, timeout=1.0)
                self.assertFalse(ok)
                self.assertIsNone(latency)
            finally:
                server.close()
                await server.wait_closed()

        asyncio.run(run_test())

    def test_check_socks5_alive_closed_port(self):
        """Test connection refused on unused local port."""
        async def run_test():
            # Use an unlikely port
            ok, latency = await check_socks5_alive("127.0.0.1", 49151, timeout=0.2)
            self.assertFalse(ok)
            self.assertIsNone(latency)

        asyncio.run(run_test())

    def test_wireguard_priority_resolution(self):
        """Test that native WireGuard interface takes precedence over SOCKS5 proxy."""
        async def run_test():
            with patch("app.core.warp.check_wireguard_interface", return_value="warp"), \
                 patch("app.core.warp.check_socks5_alive", return_value=(True, 2.5)), \
                 patch("app.core.warp.query_cloudflare_trace", return_value={
                     "reachable": True, "ip": "104.28.1.1", "warp": "on", "colo": "DME"
                 }):
                res = await detect_warp(force_refresh=True)
                self.assertTrue(res["active"])
                self.assertEqual(res["mode"], WarpMode.WIREGUARD.value)
                self.assertEqual(res["interface"], "warp")
                self.assertIsNone(res["socks5_addr"])

        asyncio.run(run_test())

    def test_socks5_fallback_when_no_wireguard(self):
        """Test fallback to SOCKS5 when no WireGuard interface exists."""
        async def run_test():
            with patch("app.core.warp.check_wireguard_interface", return_value=None), \
                 patch("app.core.warp.check_socks5_alive", return_value=(True, 3.2)), \
                 patch("app.core.warp.query_cloudflare_trace", return_value={
                     "reachable": True, "ip": "104.28.2.2", "warp": "plus", "colo": "FRA"
                 }):
                res = await detect_warp(force_refresh=True)
                self.assertTrue(res["active"])
                self.assertEqual(res["mode"], WarpMode.SOCKS5.value)
                self.assertIn("127.0.0.1:", res["socks5_addr"])
                self.assertIsNone(res["interface"])
                self.assertEqual(res["warp_status"], "plus")
                self.assertEqual(res["status_level"], WarpStatusLevel.ACTIVE.value)

        asyncio.run(run_test())

    def test_offline_state_when_neither_present(self):
        """Test detection when neither WireGuard nor SOCKS5 is present."""
        async def run_test():
            with patch("app.core.warp.check_wireguard_interface", return_value=None), \
                 patch("app.core.warp.check_socks5_alive", return_value=(False, None)):
                res = await detect_warp(force_refresh=True)
                self.assertFalse(res["active"])
                self.assertEqual(res["mode"], WarpMode.NONE.value)
                self.assertEqual(res["status_level"], WarpStatusLevel.OFFLINE.value)
                self.assertEqual(res["warp_status"], "off")

        asyncio.run(run_test())

    def test_warp_diagnostics_computation(self):
        """Test dual-path diagnostics metrics and IP masking evaluation."""
        async def run_test():
            direct_mock = {"reachable": True, "ip": "1.2.3.4", "warp": "off", "colo": "FRA", "latency_ms": 10.0}
            warp_mock = {"reachable": True, "ip": "104.28.5.6", "warp": "on", "colo": "DME", "loc": "RU", "latency_ms": 25.5}

            with patch("app.core.warp.detect_warp", return_value={
                "active": True,
                "mode": "socks5",
                "socks5_addr": "127.0.0.1:40000",
                "interface": None,
                "status_level": "active"
            }), patch("app.core.warp.query_cloudflare_trace", side_effect=[direct_mock, warp_mock]):
                diag = await query_warp_diagnostics(timeout=3.0)
                self.assertTrue(diag["warp_active"])
                self.assertTrue(diag["summary"]["ip_masked"])
                self.assertEqual(diag["summary"]["direct_ip"], "1.2.3.4")
                self.assertEqual(diag["summary"]["warp_ip"], "104.28.5.6")
                self.assertEqual(diag["summary"]["latency_delta_ms"], 15.5)
                self.assertEqual(diag["summary"]["warp_status"], "on")

        asyncio.run(run_test())


class TestWarpProcessManager(unittest.TestCase):
    """Test background installation manager state transitions and ring buffer."""

    def test_initial_state(self):
        mgr = WarpProcessManager(max_log_lines=50)
        self.assertEqual(mgr.status, WarpInstallStatus.IDLE)
        self.assertFalse(mgr.is_installing())
        logs = mgr.get_logs()
        self.assertEqual(logs["status"], "idle")
        self.assertEqual(logs["total_lines"], 0)

    def test_argument_validation(self):
        async def run_test():
            mgr = WarpProcessManager()
            # Invalid mode
            ok, msg = await mgr.start_install(mode="invalid_mode")
            self.assertFalse(ok)
            self.assertIn("Invalid mode", msg)

            # Invalid port
            ok, msg = await mgr.start_install(port=80)
            self.assertFalse(ok)
            self.assertIn("Invalid port", msg)

        asyncio.run(run_test())

    def test_log_ring_buffer_bounds(self):
        mgr = WarpProcessManager(max_log_lines=5)
        for i in range(10):
            mgr._append_log(f"line {i}")
        logs = mgr.get_logs()
        self.assertEqual(logs["total_lines"], 10)
        self.assertEqual(len(logs["logs"]), 5)
        # Should contain latest 5 lines: 5, 6, 7, 8, 9
        self.assertEqual(logs["logs"], ["line 5", "line 6", "line 7", "line 8", "line 9"])

    def test_log_pagination_offset(self):
        mgr = WarpProcessManager(max_log_lines=10)
        for i in range(10):
            mgr._append_log(f"msg {i}")

        p1 = mgr.get_logs(offset=0, limit=4)
        self.assertEqual(len(p1["logs"]), 4)
        self.assertEqual(p1["next_offset"], 4)
        self.assertTrue(p1["has_more"])

        p2 = mgr.get_logs(offset=4, limit=4)
        self.assertEqual(len(p2["logs"]), 4)
        self.assertEqual(p2["next_offset"], 8)
        self.assertTrue(p2["has_more"])

        p3 = mgr.get_logs(offset=8, limit=4)
        self.assertEqual(len(p3["logs"]), 2)
        self.assertEqual(p3["next_offset"], 10)
        self.assertFalse(p3["has_more"])

    def test_cancel_install_when_idle(self):
        async def run_test():
            mgr = WarpProcessManager()
            ok, msg = await mgr.cancel_install()
            self.assertFalse(ok)
            self.assertIn("No installation currently in progress", msg)

        asyncio.run(run_test())


class TestWARPRoutesIntegration(OpaqueE2ETestCase):
    """Hermetic API integration tests for /api/warp endpoints."""

    def test_status_endpoint_requires_auth(self):
        """GET /api/warp/status without credentials returns 401."""
        resp = self.client.get("/api/warp/status")
        self.assertEqual(resp.status_code, 401)

    def test_status_endpoint_authenticated(self):
        """GET /api/warp/status returns valid WarpStatusResponse."""
        self.login_admin()
        with patch("app.core.warp.detect_warp", return_value={
            "active": True,
            "mode": "socks5",
            "interface": None,
            "socks5_addr": "127.0.0.1:40000",
            "external_ip": "104.28.1.1",
            "warp_status": "on",
            "status_level": "active",
            "latency_ms": 12.3,
            "colo": "DME",
            "timestamp": "2026-10-26T16:00:00Z"
        }):
            resp = self.client.get("/api/warp/status")
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertTrue(data["active"])
            self.assertEqual(data["mode"], "socks5")
            self.assertEqual(data["external_ip"], "104.28.1.1")
            self.assertEqual(data["warp_status"], "on")
            self.assertEqual(data["status_level"], "active")

    def test_diagnostics_endpoint_authenticated(self):
        """GET /api/warp/diagnostics returns valid WarpDiagnosticsResponse."""
        self.login_admin()
        mock_diag = {
            "timestamp": "2026-10-26T16:00:00Z",
            "warp_active": True,
            "mode": "socks5",
            "status_level": "active",
            "direct": {"reachable": True, "ip": "1.2.3.4", "warp": "off", "colo": "FRA", "loc": "DE", "latency_ms": 15.0},
            "warp": {"reachable": True, "ip": "104.28.1.1", "warp": "on", "colo": "DME", "loc": "RU", "latency_ms": 30.0},
            "summary": {
                "ip_masked": True,
                "direct_ip": "1.2.3.4",
                "warp_ip": "104.28.1.1",
                "latency_delta_ms": 15.0,
                "warp_status": "on",
                "colo": "DME",
                "loc": "RU"
            }
        }
        with patch("app.core.warp.query_warp_diagnostics", return_value=mock_diag):
            resp = self.client.get("/api/warp/diagnostics")
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertTrue(data["warp_active"])
            self.assertTrue(data["summary"]["ip_masked"])
            self.assertEqual(data["summary"]["direct_ip"], "1.2.3.4")
            self.assertEqual(data["summary"]["warp_ip"], "104.28.1.1")

    def test_check_endpoint_syncs_settings(self):
        """POST /api/warp/check refreshes detection and saves to database."""
        self.login_admin()
        mock_detected = {
            "active": True,
            "mode": "socks5",
            "interface": None,
            "socks5_addr": "127.0.0.1:40000",
            "external_ip": "104.28.10.10",
            "warp_status": "on",
            "status_level": "active",
            "latency_ms": 18.2,
            "colo": "HEL",
            "timestamp": "2026-10-26T16:00:00Z"
        }
        with patch("app.core.warp.detect_warp", return_value=mock_detected):
            resp = self.client.post("/api/warp/check")
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertTrue(data["active"])

            # Verify saved in SQLite database
            saved_mode = self.run_async(crud.get_setting("warp_mode"))
            self.assertEqual(saved_mode, "socks5")
            saved_port = self.run_async(crud.get_setting("warp_port"))
            self.assertEqual(saved_port, "40000")

    def test_toggle_endpoint_updates_config(self):
        """POST /api/warp/toggle updates settings and restarts Hysteria."""
        self.login_admin()
        payload = {"enabled": True, "port": 40000, "mode": "socks5"}
        resp = self.client.post("/api/warp/toggle", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["ok"])
        self.assertTrue(data["warp_enabled"])

        # Check DB
        enabled = self.run_async(crud.get_setting("warp_enabled"))
        self.assertEqual(enabled, "1")

        # Now disable
        resp_off = self.client.post("/api/warp/toggle", json={"enabled": False})
        self.assertEqual(resp_off.status_code, 200)
        self.assertFalse(resp_off.json()["warp_enabled"])
        enabled_off = self.run_async(crud.get_setting("warp_enabled"))
        self.assertEqual(enabled_off, "0")

    def test_install_conflict_guard_when_active(self):
        """POST /api/warp/install returns 409 Conflict if WARP is already active and force=False."""
        self.login_admin()
        mock_active = {
            "active": True,
            "mode": "wireguard",
            "interface": "warp",
            "socks5_addr": None,
            "external_ip": "104.28.5.5",
            "warp_status": "on",
            "status_level": "active",
            "latency_ms": 20.0,
            "colo": "DME",
            "timestamp": "2026-10-26T16:00:00Z"
        }
        with patch("app.core.warp.detect_warp", return_value=mock_active):
            resp = self.client.post("/api/warp/install", json={"mode": "auto", "port": 40000, "force": False})
            self.assertEqual(resp.status_code, 409)
            self.assertIn("Active WARP connection already detected", resp.json()["detail"])

    def test_install_force_override_starts_install(self):
        """POST /api/warp/install with force=True bypasses 409 active guard."""
        self.login_admin()
        mock_active = {
            "active": True,
            "mode": "socks5",
            "interface": None,
            "socks5_addr": "127.0.0.1:40000",
            "external_ip": "104.28.5.5",
            "warp_status": "on",
            "status_level": "active",
            "latency_ms": 20.0,
            "colo": "DME",
            "timestamp": "2026-10-26T16:00:00Z"
        }
        with patch("app.core.warp.detect_warp", return_value=mock_active), \
             patch.object(warp.warp_installer, "start_install", return_value=(True, "Installation started in background.")):
            resp = self.client.post("/api/warp/install", json={"mode": "auto", "port": 40000, "force": True})
            self.assertEqual(resp.status_code, 202)
            data = resp.json()
            self.assertTrue(data["ok"])
            self.assertEqual(data["status"], "installing")

    def test_install_log_endpoint(self):
        """GET /api/warp/install-log returns logs with pagination."""
        self.login_admin()
        warp.warp_installer._logs.clear()
        warp.warp_installer._append_log("Line 1: Starting")
        warp.warp_installer._append_log("Line 2: Working")

        resp = self.client.get("/api/warp/install-log?offset=0&limit=10")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total_lines"], 2)
        self.assertEqual(len(data["logs"]), 2)
        self.assertIn("Line 1: Starting", data["logs"][0])

    def test_install_cancel_endpoint(self):
        """POST /api/warp/install-cancel terminates installation or reports idle."""
        self.login_admin()
        with patch.object(warp.warp_installer, "cancel_install", return_value=(True, "Installation cancelled.")):
            resp = self.client.post("/api/warp/install-cancel")
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(resp.json()["ok"])

        with patch.object(warp.warp_installer, "cancel_install", return_value=(False, "No installation currently in progress.")):
            resp_err = self.client.post("/api/warp/install-cancel")
            self.assertEqual(resp_err.status_code, 400)
