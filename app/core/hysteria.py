import os
import subprocess
import logging
import json
from pathlib import Path
from typing import Dict, Any, Tuple
from app.config import settings
from app.database import crud

logger = logging.getLogger("innerblitz.hysteria")

def build_hysteria_yaml(config_data: Dict[str, Any]) -> str:
    """Build a complete, optimized Hysteria 2 YAML configuration string."""
    listen_port = config_data.get("listen_port", 443)
    port_hop = config_data.get("port_hopping_enabled", True)
    port_range = config_data.get("port_hopping_range", "20000:50000").replace(":", "-")

    # In Hysteria 2 Linux, listen can be a port or range: e.g. :20000-50000 or :443
    if port_hop and port_range and "-" in port_range:
        listen_str = f":{port_range}"
    else:
        listen_str = f":{listen_port}"

    tls_type = config_data.get("tls_type", "self_signed_ip")
    server_domain = config_data.get("server_domain", "").strip()

    tls_block = ""
    if tls_type == "acme" and server_domain:
        tls_block = f"""tls:
  type: acme
  acme:
    domains:
      - {server_domain}
    email: admin@{server_domain}"""
    else:
        tls_block = f"""tls:
  cert: {settings.CERT_PATH}
  key: {settings.KEY_PATH}"""

    # Obfuscation
    obfs_type = config_data.get("obfs_type", "salamander")
    obfs_pwd = config_data.get("obfs_password", "")
    obfs_block = ""
    if obfs_type == "salamander" and obfs_pwd:
        obfs_block = f"""obfs:
  type: salamander
  salamander:
    password: "{obfs_pwd}"
"""

    # Masquerade
    masq_type = config_data.get("masquerade_type", "proxy")
    masq_target = config_data.get("masquerade_target", "https://bing.com")
    if masq_type == "proxy":
        masq_block = f"""masquerade:
  type: proxy
  proxy:
    url: {masq_target}
    rewriteHost: true"""
    elif masq_type == "file":
        masq_block = f"""masquerade:
  type: file
  file:
    dir: {settings.DATA_DIR}/masquerade"""
    else:
        masq_block = f"""masquerade:
  type: string
  string:
    content: "404 Not Found"
    statusCode: 404"""

    # Bandwidth
    up_mbps = config_data.get("up_mbps", "200")
    down_mbps = config_data.get("down_mbps", "200")
    ignore_bw = "true" if str(config_data.get("ignore_client_bandwidth", "0")).lower() in ("1", "true") else "false"

    traffic_secret = config_data.get("traffic_secret", "secret-uuid")

    # Outbounds & WARP support
    warp_enabled = str(config_data.get("warp_enabled", "0")).lower() in ("1", "true")
    warp_port = config_data.get("warp_port", "40000")
    outbounds_block = ""
    warp_acl = ""
    if warp_enabled:
        outbounds_block = f"""outbounds:
  - name: direct
    type: direct
  - name: warp
    type: socks5
    socks5:
      addr: 127.0.0.1:{warp_port}
"""
        warp_acl = """    - outbound(warp, geosite:openai)
    - outbound(warp, geosite:netflix)
"""

    yaml_content = f"""# InnerBlitz Auto-Generated Hysteria 2 Config
listen: {listen_str}

{tls_block}

{obfs_block}auth:
  type: http
  http:
    url: http://127.0.0.1:{settings.HYSTERIA_AUTH_PORT}/auth
    insecure: true

quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 30s
  maxIncomingStreams: 2048

bandwidth:
  up: {up_mbps} mbps
  down: {down_mbps} mbps

ignoreClientBandwidth: {ignore_bw}
disableUDP: false
speedTest: false

sniff:
  enable: true
  timeout: 2s
  rewriteDomain: false

trafficStats:
  listen: 127.0.0.1:{settings.HYSTERIA_TRAFFIC_STATS_PORT}
  secret: "{traffic_secret}"

{masq_block}

{outbounds_block}acl:
  inline:
    - reject(geosite:category-ads-all)
    - reject(geosite:win-spy)
{warp_acl}    - reject(10.0.0.0/8)
    - reject(172.16.0.0/12)
    - reject(192.168.0.0/16)
    - reject(127.0.0.0/8)
    - reject(fc00::/7)
"""
    return yaml_content

async def apply_and_save_config() -> bool:
    """Read settings from SQLite, generate config.yaml and write to disk."""
    try:
        current_settings = await crud.get_all_settings()
        yaml_text = build_hysteria_yaml(current_settings)
        
        config_path = Path(settings.HYSTERIA_CONFIG_PATH)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(yaml_text)
        
        logger.info(f"Hysteria 2 configuration saved to {config_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to generate Hysteria config: {e}")
        return False

def run_systemctl(action: str, service: str = "hysteria-server.service") -> Tuple[bool, str]:
    """Execute systemctl safely without shell=True."""
    if action not in ("start", "stop", "restart", "status", "is-active", "enable", "disable"):
        return False, "Invalid systemctl action"
    try:
        cmd = ["systemctl", action, service]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return res.returncode == 0, res.stdout or res.stderr
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except FileNotFoundError:
        return False, "systemctl not found (non-systemd environment)"
    except Exception as e:
        return False, str(e)

def is_hysteria_running() -> bool:
    """Check if Hysteria 2 service is running."""
    ok, out = run_systemctl("is-active", "hysteria-server.service")
    return ok and "active" in out

def restart_hysteria() -> Tuple[bool, str]:
    """Restart Hysteria 2 server service."""
    return run_systemctl("restart", "hysteria-server.service")

def get_hysteria_version() -> str:
    """Get installed Hysteria version string."""
    try:
        res = subprocess.run(["hysteria", "version"], capture_output=True, text=True, timeout=5)
        for line in res.stdout.splitlines():
            if "Version:" in line:
                return line.split(":", 1)[1].strip()
        return res.stdout.strip()[:30] or "Unknown"
    except Exception:
        return "Not installed / Unknown"

def get_hysteria_logs(lines: int = 40) -> str:
    """Safely get recent journalctl logs for hysteria-server."""
    try:
        cmd = ["journalctl", "-u", "hysteria-server.service", "-n", str(lines), "--no-pager"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return res.stdout or "No logs available."
    except Exception as e:
        return f"Error fetching logs: {e}"
