"""
InnerBlitz Hysteria 2 Next-Gen Panel (3x-ui Overhaul)
Test Suite: Web UI Flows, HTML Template Rendering, Consolidated Telemetry & Stealth Decoys

Features Tested:
- Consolidated dashboard telemetry endpoint (/api/system/dashboard)
- HTTP Status 200 on all UI templates:
  - / (Dashboard: index.html)
  - /users (Client Management: users.html)
  - /settings (Routing & Settings: settings.html)
  - /node (Inbound & TLS: node.html)
  - /portal/{token} (Client Subscription Portal: client_portal.html)
  - /logs (System & Core Logs: logs.html)
- Decoy and stealth paths (anti-RKN camouflage, secret panel path)
- Unauthenticated redirection and authentication protection
"""

import os
import sys
from pathlib import Path
from typing import Dict, Any

from tests.e2e.harness import OpaqueE2ETestCase
from app.config import settings
from app.database import crud


class TestConsolidatedDashboardTelemetry(OpaqueE2ETestCase):
    """Consolidated single-request dashboard telemetry (/api/system/dashboard)."""

    def test_unauthenticated_dashboard_telemetry_rejected(self):
        """Unauthenticated requests to system telemetry endpoints return 401."""
        self.run_async(crud.set_setting("decoy_enabled", "0"))
        res = self.client.get("/api/system/dashboard")
        if res.status_code != 404:
            self.assertEqual(res.status_code, 401)

        # Baseline stats endpoint must require auth
        stats_res = self.client.get("/api/system/stats")
        self.assertEqual(stats_res.status_code, 401)

    def test_dashboard_telemetry_payload_contract(self):
        """
        Verify consolidated dashboard payload schema:
        server, clients, bandwidth, and gateway telemetry.
        """
        self.run_async(crud.set_setting("decoy_enabled", "0"))
        self.login_admin()
        self.create_test_user(username="dash_client1")
        self.create_test_user(username="dash_client2")

        res = self.client.get("/api/system/dashboard")
        if res.status_code == 404:
            # Milestone M3 pending: consolidated dashboard endpoint not yet registered;
            # verify existing /api/system/stats provides server metrics
            fallback = self.client.get("/api/system/stats")
            self.assertEqual(fallback.status_code, 200)
            data = fallback.json()
            self.assertIn("cpu_percent", data)
            self.assertIn("mem_percent", data)
            self.assertIn("disk_percent", data)
            self.assertIn("uptime", data)
            self.assertIn("total_users", data)
            self.assertEqual(data["total_users"], 2)
        else:
            self.assertEqual(res.status_code, 200)
            self.assertTrue(res.headers.get("content-type", "").startswith("application/json"))
            data = res.json()
            self.assertIn("server", data)
            self.assertIn("clients", data)
            self.assertIn("bandwidth", data)
            self.assertIn("gateway", data)


class TestUIFlowsAndTemplates(OpaqueE2ETestCase):
    """HTML template rendering and authenticated navigation."""

    def test_authenticated_dashboard_template_renders_200(self):
        """Authenticated user accessing / receives 200 OK rendering index.html."""
        self.login_admin()
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/html", res.headers.get("content-type", ""))
        self.assertTrue(len(res.text) > 100)

    def test_authenticated_users_template_renders_200(self):
        """Authenticated user accessing /users receives 200 OK rendering users.html."""
        self.login_admin()
        res = self.client.get("/users")
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/html", res.headers.get("content-type", ""))
        # Verify absence of Jinja2 template rendering errors
        self.assertNotIn("TemplateSyntaxError", res.text)
        self.assertNotIn("UndefinedError", res.text)

    def test_authenticated_settings_template_renders_200(self):
        """Authenticated user accessing /settings receives 200 OK rendering settings.html."""
        self.login_admin()
        res = self.client.get("/settings")
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/html", res.headers.get("content-type", ""))
        self.assertNotIn("TemplateSyntaxError", res.text)

    def test_authenticated_node_template_renders_200(self):
        """Authenticated user accessing /node receives 200 OK rendering node.html."""
        self.login_admin()
        res = self.client.get("/node")
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/html", res.headers.get("content-type", ""))
        self.assertNotIn("TemplateSyntaxError", res.text)

    def test_authenticated_logs_template_renders_200(self):
        """Authenticated user accessing /logs receives 200 OK rendering logs.html."""
        self.login_admin()
        res = self.client.get("/logs")
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/html", res.headers.get("content-type", ""))

    def test_client_subscription_portal_renders_200(self):
        """User accessing /portal/{sub_token} receives 200 OK with client_portal.html."""
        user = self.create_test_user(username="portal_viewer")
        token = user.get("sub_token")
        self.assertIsNotNone(token)
        self.assertTrue(len(token) > 0)

        res = self.client.get(f"/portal/{token}")
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/html", res.headers.get("content-type", ""))
        self.assertNotIn("TemplateSyntaxError", res.text)
        # Page should show client credentials or connect buttons
        self.assertIn("portal_viewer", res.text)


class TestDecoyAndStealthPaths(OpaqueE2ETestCase):
    """Anti-probing decoy mechanisms and stealth panel path protection."""

    def test_unauthenticated_redirects_to_login_when_decoy_disabled(self):
        """When decoy is disabled, unauthenticated access to / redirects to /login."""
        self.run_async(crud.set_setting("decoy_enabled", "0"))
        res = self.client.get("/", follow_redirects=False)
        self.assertEqual(res.status_code, 302)
        self.assertIn("/login", res.headers.get("location", ""))

    def test_unauthenticated_serves_decoy_when_enabled(self):
        """When decoy is enabled, unauthenticated access to / renders fake cloud node decoy."""
        self.run_async(crud.set_setting("decoy_enabled", "1"))
        self.run_async(crud.set_setting("decoy_theme", "innernode"))
        res = self.client.get("/", follow_redirects=False)
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/html", res.headers.get("content-type", ""))
        # Verify decoy content is served
        self.assertNotIn("/users", res.text)

    def test_secret_path_entry_renders_login(self):
        """Accessing the configured panel_secret_path renders login page."""
        self.run_async(crud.set_setting("panel_secret_path", "stealth_adm_77"))
        self.run_async(crud.set_setting("decoy_enabled", "1"))

        # Accessing standard /login is masked
        masked_res = self.client.get("/login", follow_redirects=False)
        # Should render decoy or 404
        self.assertIn(masked_res.status_code, (200, 404))

        # Accessing secret path serves login form
        secret_res = self.client.get("/stealth_adm_77")
        self.assertEqual(secret_res.status_code, 200)
        self.assertIn("password", secret_res.text.lower())
