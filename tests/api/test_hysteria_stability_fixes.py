"""
Regression tests for Hysteria 2 stability, ping/latency, dropouts, firewall,
cert pinning, limiter, backup restore, routing validation, and 2FA fixes.
"""

import io
import tarfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import yaml

from app.config import settings
from app.core.firewall import configure_port_hopping
from app.core.hysteria import (
    DEFAULT_QUIC_MAX_IDLE_TIMEOUT,
    DEFAULT_SNIFF_TCP_PORTS,
    DEFAULT_SNIFF_UDP_PORTS,
    apply_and_save_config,
    build_hysteria_yaml,
    validate_hysteria_config,
)
from app.core.limiter import _count_online_devices, limiter_daemon
from app.core.subscription import build_singbox_json
from app.database import crud
from app.database.models import ClientCreate
from tests.e2e.harness import OpaqueE2ETestCase


class TestHysteriaStabilityAndConfigFixes(OpaqueE2ETestCase):
    """Verify Hysteria 2 YAML fixes that eliminate stalls, ping spikes, and dropouts."""

    def test_sniff_ports_restricted_to_web_and_quic_not_all(self):
        yaml_str = build_hysteria_yaml({"listen_port": 8443})
        data = yaml.safe_load(yaml_str)
        self.assertEqual(str(data["sniff"]["tcpPorts"]), DEFAULT_SNIFF_TCP_PORTS)
        self.assertEqual(str(data["sniff"]["udpPorts"]), DEFAULT_SNIFF_UDP_PORTS)
        self.assertNotEqual(str(data["sniff"]["tcpPorts"]).lower(), "all")
        self.assertNotEqual(str(data["sniff"]["udpPorts"]).lower(), "all")

    def test_quic_idle_timeout_60s_and_direct_ipv4_first_mode_46(self):
        yaml_str = build_hysteria_yaml({"listen_port": 8443, "warp_enabled": False})
        data = yaml.safe_load(yaml_str)
        self.assertEqual(data["quic"]["maxIdleTimeout"], DEFAULT_QUIC_MAX_IDLE_TIMEOUT)
        self.assertEqual(data["quic"]["maxIdleTimeout"], "60s")
        direct_obs = [o for o in data["outbounds"] if o["name"] == "direct"]
        self.assertEqual(len(direct_obs), 1)
        self.assertEqual(str(direct_obs[0]["direct"]["mode"]), "46")
        self.assertFalse(direct_obs[0]["direct"]["fastOpen"])

    def test_acme_top_level_key_valid_and_legacy_nested_tls_acme_rejected(self):
        yaml_str = build_hysteria_yaml({
            "listen_port": 443,
            "tls_type": "acme",
            "server_domain": "vpn.example.org",
        })
        ok, msg = validate_hysteria_config(yaml_str)
        self.assertTrue(ok, f"Valid top-level acme YAML must pass validation: {msg}")
        data = yaml.safe_load(yaml_str)
        self.assertIn("acme", data)
        self.assertNotIn("tls", data)
        self.assertEqual(data["acme"]["domains"], ["vpn.example.org"])

        broken_legacy = """
listen: :443
tls:
  type: acme
  acme:
    domains:
      - vpn.example.org
auth:
  type: http
  http:
    url: http://127.0.0.1:28262/auth
"""
        ok_bad, msg_bad = validate_hysteria_config(broken_legacy)
        self.assertFalse(ok_bad, "Invalid nested tls.type=acme must be rejected")
        self.assertIn("top-level", msg_bad.lower())

    def test_yaml_special_chars_in_secrets_escaped_cleanly(self):
        tricky_pwd = 'p@ss"with\\quotes:and#hash'
        tricky_secret = 'sec"ret\\123'
        yaml_str = build_hysteria_yaml({
            "listen_port": 8443,
            "obfs_type": "salamander",
            "obfs_password": tricky_pwd,
            "traffic_secret": tricky_secret,
        })
        ok, msg = validate_hysteria_config(yaml_str)
        self.assertTrue(ok, f"Escaped YAML failed validation: {msg}")
        data = yaml.safe_load(yaml_str)
        self.assertEqual(data["obfs"]["salamander"]["password"], tricky_pwd)
        self.assertEqual(data["trafficStats"]["secret"], tricky_secret)

    def test_apply_and_save_auto_generates_missing_self_signed_cert(self):
        cert_p = Path(settings.CERT_PATH)
        key_p = Path(settings.KEY_PATH)
        cert_p.unlink(missing_ok=True)
        key_p.unlink(missing_ok=True)

        res = self.run_async(apply_and_save_config())
        self.assertTrue(res.success, res.message)
        self.assertTrue(cert_p.exists())
        self.assertTrue(key_p.exists())


class TestSettingsCertPinAndPresetSync(OpaqueE2ETestCase):
    """Ensure saving unrelated settings never breaks client pinSHA256 and presets sync firewall."""

    def test_unchanged_sni_preserves_cert_pin_while_changed_sni_rotates(self):
        self.login_admin()
        # Trigger initial cert generation with known SNI
        resp_init = self.client.post("/api/settings/generate-ip-cert")
        self.assertEqual(resp_init.status_code, 200)
        original_pin = resp_init.json()["cert_sha256"]
        self.assertTrue(len(original_pin) == 64)

        # Saving unrelated fields alongside the SAME SNI must NOT rotate cert_sha256
        cur_sni = self.run_async(crud.get_setting("sni", "bing.com"))
        resp_same = self.client.post("/api/settings", json={
            "sni": cur_sni,
            "up_mbps": "500",
            "down_mbps": "500",
        })
        self.assertEqual(resp_same.status_code, 200)
        pin_after_same = self.run_async(crud.get_setting("cert_sha256", ""))
        self.assertEqual(pin_after_same, original_pin, "Cert pin must NOT rotate when SNI did not change")

        # Actually changing SNI MUST regenerate cert and rotate pinSHA256
        resp_diff = self.client.post("/api/settings", json={"sni": "apple.com"})
        self.assertEqual(resp_diff.status_code, 200)
        pin_after_diff = self.run_async(crud.get_setting("cert_sha256", ""))
        self.assertNotEqual(pin_after_diff, original_pin)

    def test_obfs_password_clears_and_restores_obfs_type(self):
        self.login_admin()
        resp_clear = self.client.post("/api/settings", json={"obfs_password": ""})
        self.assertEqual(resp_clear.status_code, 200)
        self.assertEqual(self.run_async(crud.get_setting("obfs_type")), "none")

        resp_restore = self.client.post("/api/settings", json={"obfs_password": "new-salamander-pass"})
        self.assertEqual(resp_restore.status_code, 200)
        self.assertEqual(self.run_async(crud.get_setting("obfs_type")), "salamander")

    def test_apply_preset_syncs_firewall_and_disables_obfs_on_speed(self):
        self.login_admin()
        with patch("app.api.settings_routes.flush_port_hopping", return_value=(True, "ok")) as mock_flush, \
             patch("app.api.settings_routes.configure_port_hopping", return_value=(True, "ok")) as mock_conf:
            r_speed = self.client.post("/api/settings/apply-preset", json={"preset": "speed"})
            self.assertEqual(r_speed.status_code, 200)
            self.assertTrue(mock_flush.called)
            self.assertEqual(self.run_async(crud.get_setting("obfs_type")), "none")
            self.assertEqual(self.run_async(crud.get_setting("obfs_password")), "")

            r_dpi = self.client.post("/api/settings/apply-preset", json={"preset": "anti-dpi"})
            self.assertEqual(r_dpi.status_code, 200)
            self.assertTrue(mock_conf.called)


class TestFirewallMultiRangeAndLimiterFixes(OpaqueE2ETestCase):
    """Verify multi-range port hopping iptables split and Hysteria 2 integer /online enforcement."""

    def test_firewall_multi_range_splits_into_separate_iptables_rules(self):
        recorded_cmds = []

        def fake_run(cmd, *args, **kwargs):
            recorded_cmds.append(cmd)
            m = MagicMock()
            m.returncode = 0
            m.stdout = ""
            m.stderr = ""
            return m

        with patch("app.core.firewall.subprocess.run", side_effect=fake_run):
            ok, msg = configure_port_hopping("443, 20000-30000", 8443, enable=True)
            self.assertTrue(ok, msg)

        dport_args = [
            cmd[cmd.index("--dport") + 1]
            for cmd in recorded_cmds
            if cmd and cmd[0] == "iptables" and "--dport" in cmd
        ]
        self.assertEqual(dport_args, ["443", "20000:30000"])

    def test_limiter_handles_hysteria2_int_online_and_ipv6_list(self):
        self.assertEqual(_count_online_devices(3), 3)
        self.assertEqual(_count_online_devices(0), 0)
        self.assertEqual(_count_online_devices(["[2001:db8::1]:1111", "[2001:db8::2]:2222"]), 2)
        self.assertEqual(_count_online_devices(["[2001:db8::1]:1111", "[2001:db8::1]:2222"]), 1)

        # Create active user with max_ips=1 and disabled offline user
        self.run_async(crud.create_client(ClientCreate(username="over_dev", password="p", max_ips=1)))
        self.run_async(crud.create_client(ClientCreate(username="offline_disabled", password="p", enable=False)))

        fake_resp = AsyncMock()
        fake_resp.status = 200
        fake_resp.json = AsyncMock(return_value={"over_dev": 2})
        fake_resp.__aenter__ = AsyncMock(return_value=fake_resp)
        fake_resp.__aexit__ = AsyncMock(return_value=False)

        fake_session = AsyncMock()
        fake_session.get = MagicMock(return_value=fake_resp)
        fake_session.__aenter__ = AsyncMock(return_value=fake_session)
        fake_session.__aexit__ = AsyncMock(return_value=False)

        with patch("app.core.limiter.aiohttp.ClientSession", return_value=fake_session), \
             patch("app.core.limiter.kick_users_api", new_callable=AsyncMock) as mock_kick:
            self.run_async(limiter_daemon.check_and_enforce())
            self.assertTrue(mock_kick.called)
            kicked = mock_kick.call_args[0][0]
            self.assertIn("over_dev", kicked)
            self.assertNotIn("offline_disabled", kicked)


class TestSecurityBackupRoutingAnd2FAFixes(OpaqueE2ETestCase):
    """Verify backup restore safety, routing rule validation, and Telegram OTP expiration."""

    def test_backup_upload_rejects_symlink_and_does_not_stop_innerblitz_before_extract(self):
        self.login_admin()

        # 1. Malicious archive with symlink must be rejected with HTTP 400
        buf_sym = io.BytesIO()
        with tarfile.open(fileobj=buf_sym, mode="w:gz") as tar:
            ti = tarfile.TarInfo("evil_link")
            ti.type = tarfile.SYMTYPE
            ti.linkname = "/etc/passwd"
            tar.addfile(ti)
        buf_sym.seek(0)

        resp_sym = self.client.post(
            "/api/settings/backup/upload",
            files={"file": ("backup.tar.gz", buf_sym.getvalue(), "application/gzip")},
        )
        self.assertEqual(resp_sym.status_code, 400)

        # 2. Valid archive must NOT stop innerblitz.service synchronously
        buf_ok = io.BytesIO()
        with tarfile.open(fileobj=buf_ok, mode="w:gz") as tar:
            payload = b"ok-marker"
            ti = tarfile.TarInfo("restore_test.txt")
            ti.size = len(payload)
            tar.addfile(ti, io.BytesIO(payload))
        buf_ok.seek(0)

        stopped_services = []

        async def fake_systemctl(action, service="hysteria-server.service"):
            stopped_services.append((action, service))
            return True, "ok"

        with patch("app.api.settings_routes.async_run_systemctl", side_effect=fake_systemctl), \
             patch("app.api.settings_routes.subprocess.Popen"):
            resp_ok = self.client.post(
                "/api/settings/backup/upload",
                files={"file": ("backup.tar.gz", buf_ok.getvalue(), "application/gzip")},
            )
            self.assertEqual(resp_ok.status_code, 200)

        self.assertNotIn(("stop", "innerblitz.service"), stopped_services)
        self.assertTrue((Path(settings.DATA_DIR) / "restore_test.txt").exists())

    def test_create_routing_rule_rejects_invalid_ip_and_invalid_geosite(self):
        self.login_admin()
        r_bad_ip = self.client.post("/api/routing/rules", json={
            "name": "Bad IP",
            "action": "warp",
            "rule_type": "ip_cidr",
            "rule_values": ["999.999.999.999/99"],
        })
        self.assertEqual(r_bad_ip.status_code, 400)

        r_bad_gs = self.client.post("/api/routing/rules", json={
            "name": "Invalid Ru Tag",
            "action": "warp",
            "rule_type": "geosite",
            "rule_values": ["ru"],
        })
        self.assertEqual(r_bad_gs.status_code, 400)

    def test_telegram_2fa_otp_expires_after_5_minutes(self):
        self.run_async(crud.set_settings({
            "tg_2fa_enabled": "1",
            "_current_tg_otp": "123456",
            "_current_tg_otp_expires": (datetime.now() - timedelta(minutes=1)).isoformat(),
        }))
        resp = self.client.post("/api/login", json={
            "username": "admin",
            "password": "admin",
            "tg_code": "123456",
        })
        self.assertEqual(resp.status_code, 401)
        self.assertIn("expired", resp.json()["detail"].lower())

    def test_singbox_profile_valid_v111_schema(self):
        user = self.create_test_user("sb_valid_user", "pw123")
        sb = build_singbox_json(user, {
            "server_ip": "1.2.3.4",
            "listen_port": 8443,
            "tls_type": "self_signed_ip",
            "cert_sha256": "deadbeef" * 8,
            "port_hopping_enabled": "1",
            "port_hopping_range": "20000:50000",
        })
        self.assertNotIn("version", sb)
        hy2 = [o for o in sb["outbounds"] if o["type"] == "hysteria2"][0]
        self.assertEqual(hy2["server_ports"], ["20000:50000"])
        self.assertEqual(hy2["hop_interval"], "30s")
        self.assertNotIn("pinSHA256", hy2["tls"])
