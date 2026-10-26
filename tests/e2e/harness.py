import os
import sys
import shutil
import tempfile
import asyncio
import secrets
import unittest
from pathlib import Path
from typing import Dict, Any, Optional

import yaml
from starlette.testclient import TestClient

# Ensure Blitz-main is on Python path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.config import settings
from app.database.connection import init_db, get_db_connection
from app.database import crud
from app.database.models import UserCreate
from app.core.security import hash_password


CLOUDFLARE_TRACE_SAMPLES = {
    "warp_on": """fl=548f12
h=cloudflare.com
ip=104.28.194.5
ts=1730000000.123
visit_scheme=https
uag=curl/8.5.0
colo=DME
http=http/2
loc=RU
tls=TLSv1.3
sni=plaintext
warp=on
gateway=off
rbi=off
kex=X25519
""",
    "warp_plus": """fl=123f45
h=cloudflare.com
ip=104.28.200.8
ts=1730000005.456
visit_scheme=https
uag=curl/8.5.0
colo=FRA
http=http/2
loc=DE
tls=TLSv1.3
sni=plaintext
warp=plus
gateway=off
rbi=off
kex=X25519
""",
    "warp_off": """fl=987f65
h=cloudflare.com
ip=185.220.101.5
ts=1730000010.789
visit_scheme=https
uag=curl/8.5.0
colo=AMS
http=http/2
loc=NL
tls=TLSv1.3
sni=plaintext
warp=off
gateway=off
rbi=off
kex=X25519
""",
}


class IsolatedEnvironment:
    """Manages an isolated temporary sandbox for database, certs, and config files."""

    def __init__(self):
        self.temp_dir = tempfile.mkdtemp(prefix="innerblitz_test_")
        self.old_base_dir = settings.BASE_DIR
        settings.BASE_DIR = self.temp_dir
        os.environ["INNERBLITZ_DIR"] = self.temp_dir

    def setup(self):
        Path(self.temp_dir).mkdir(parents=True, exist_ok=True)
        asyncio.run(init_db())

    def cleanup(self):
        settings.BASE_DIR = self.old_base_dir
        if "INNERBLITZ_DIR" in os.environ:
            del os.environ["INNERBLITZ_DIR"]
        try:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception:
            pass


class OpaqueE2ETestCase(unittest.TestCase):
    """
    Base test case for all InnerBlitz E2E tests.
    Guarantees hermetic execution in isolated sandbox.
    """

    def setUp(self):
        super().setUp()
        self.env = IsolatedEnvironment()
        self.env.setup()
        
        # Lazy import app so lifespan and config use overridden settings
        from app.main import app
        self.app = app
        self.client = TestClient(app, raise_server_exceptions=False)

    def tearDown(self):
        self.env.cleanup()
        super().tearDown()

    def run_async(self, coro):
        """Helper to run async database and core operations synchronously in tests."""
        return asyncio.run(coro)

    def login_admin(self, username: str = "admin", password: str = "admin") -> str:
        """
        Creates an authenticated session in the isolated database
        and configures the session cookie on self.client.
        """
        async def _setup_session():
            session_id = secrets.token_hex(32)
            from datetime import datetime, timedelta
            expires = datetime.utcnow() + timedelta(hours=24)
            db = await get_db_connection()
            try:
                await db.execute(
                    "INSERT INTO admin_sessions (session_id, username, expires_at) VALUES (?, ?, ?);",
                    (session_id, username, expires.isoformat())
                )
                await db.commit()
            finally:
                await db.close()
            return session_id

        session_id = self.run_async(_setup_session())
        self.client.cookies.set(settings.COOKIE_NAME, session_id)
        return session_id

    def create_test_user(
        self,
        username: str = "testuser",
        password: Optional[str] = "secretpass123",
        traffic_limit_gb: float = 10.0,
        expiration_days: int = 30,
        unlimited: bool = False,
        max_ips: int = 2,
        note: str = "Test client user"
    ) -> Dict[str, Any]:
        """Create a user record in the isolated database."""
        async def _create():
            u = UserCreate(
                username=username,
                password=password,
                traffic_limit_gb=traffic_limit_gb,
                expiration_days=expiration_days,
                unlimited_user=unlimited,
                max_ips=max_ips,
                note=note
            )
            return await crud.create_user(u)
        return self.run_async(_create())

    # --- Verification & Oracle Assertions ---

    def verify_valid_hysteria_yaml(self, yaml_str: str) -> Dict[str, Any]:
        """Assert that yaml_str is valid YAML containing required Hysteria 2 keys."""
        self.assertIsInstance(yaml_str, str)
        self.assertTrue(len(yaml_str) > 0, "Generated Hysteria YAML is empty")
        try:
            data = yaml.safe_load(yaml_str)
        except Exception as e:
            self.fail(f"Hysteria config failed YAML parsing: {e}\nYAML:\n{yaml_str}")

        self.assertIsInstance(data, dict, "Hysteria YAML must parse to a dict")
        self.assertIn("listen", data, "Missing mandatory 'listen' key in Hysteria config")
        self.assertIn("tls", data, "Missing mandatory 'tls' key in Hysteria config")
        self.assertIn("auth", data, "Missing mandatory 'auth' key in Hysteria config")
        return data

    def verify_valid_singbox_profile(self, data: Dict[str, Any]):
        """Assert that data follows the Sing-box v1.10+ schema specification."""
        self.assertIsInstance(data, dict, "Sing-box profile must be a dict")
        self.assertIn("outbounds", data, "Sing-box profile must contain 'outbounds'")
        self.assertIsInstance(data["outbounds"], list)
        self.assertTrue(len(data["outbounds"]) > 0, "Sing-box outbounds cannot be empty")

        # Find hysteria2 outbound
        hy2_outbounds = [o for o in data["outbounds"] if o.get("type") == "hysteria2"]
        self.assertTrue(len(hy2_outbounds) >= 1, "Sing-box profile missing hysteria2 outbound")
        hy2 = hy2_outbounds[0]
        self.assertIn("server", hy2)
        self.assertIn("server_port", hy2)
        self.assertIn("password", hy2)
        self.assertIn("tls", hy2)

    def verify_valid_clash_yaml(self, yaml_str: str) -> Dict[str, Any]:
        """Assert that yaml_str is valid Clash Meta YAML with proxies, proxy-groups, and rules."""
        self.assertIsInstance(yaml_str, str)
        try:
            data = yaml.safe_load(yaml_str)
        except Exception as e:
            self.fail(f"Clash config failed YAML parsing: {e}\nYAML:\n{yaml_str}")

        self.assertIsInstance(data, dict)
        self.assertIn("proxies", data, "Clash config missing 'proxies'")
        self.assertIn("proxy-groups", data, "Clash config missing 'proxy-groups'")
        self.assertIn("rules", data, "Clash config missing 'rules'")

        # Ensure hysteria2 proxy is defined
        hy2_proxies = [p for p in data["proxies"] if p.get("type") == "hysteria2"]
        self.assertTrue(len(hy2_proxies) >= 1, "Clash config missing hysteria2 proxy")
        return data

    def parse_cf_trace(self, trace_text: str) -> Dict[str, str]:
        """Parse key=value pairs from cloudflare.com/cdn-cgi/trace output."""
        result = {}
        for line in trace_text.strip().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                result[k.strip()] = v.strip()
        return result
