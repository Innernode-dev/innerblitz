import os
import subprocess
import logging
import json
from pathlib import Path
from typing import Dict, Any, Tuple
from app.config import settings
from app.database import crud

import yaml
import shutil
from typing import Dict, Any, Tuple, Optional, List

logger = logging.getLogger("innerblitz.hysteria")

class ConfigApplyResult(tuple):
    """
    Tuple subclass (success: bool, message: str) that evaluates truthiness
    based on success flag. Guarantees backwards compatibility with both
    Tuple[bool, str] return types and boolean if-checks.
    """
    def __new__(cls, success: bool, message: str):
        return super().__new__(cls, (success, message))

    @property
    def success(self) -> bool:
        return self[0]

    @property
    def message(self) -> str:
        return self[1]

    def __bool__(self) -> bool:
        return bool(self[0])

def validate_hysteria_config(content: str) -> Tuple[bool, str]:
    """
    Validates YAML syntax and critical Hysteria 2 keys (listen, tls, auth).
    Returns (is_valid: bool, error_message: str).
    """
    if not content or not str(content).strip():
        return False, "Configuration content is empty"

    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as e:
        return False, f"YAML syntax error: {e}"
    except Exception as e:
        return False, f"YAML parse error: {e}"

    if not isinstance(data, dict):
        return False, "Configuration root must be a YAML mapping (dictionary)"

    mandatory_keys = ["listen", "tls", "auth"]
    missing = [k for k in mandatory_keys if k not in data]
    if missing:
        return False, f"Missing required Hysteria 2 keys: {', '.join(missing)}"

    # Check tls structure
    if not isinstance(data.get("tls"), (dict, str)):
        return False, "Key 'tls' must be a mapping"

    # Check auth structure
    if not isinstance(data.get("auth"), (dict, str)):
        return False, "Key 'auth' must be a mapping"

    # Check outbounds if present
    if "outbounds" in data and data["outbounds"] is not None:
        if not isinstance(data["outbounds"], list):
            return False, "Key 'outbounds' must be a list"
        for ob in data["outbounds"]:
            if not isinstance(ob, dict) or "name" not in ob or "type" not in ob:
                return False, "Each outbound must be a mapping with 'name' and 'type'"

    # Check acl if present
    if "acl" in data and data["acl"] is not None:
        if not isinstance(data["acl"], dict):
            return False, "Key 'acl' must be a mapping"
        if "inline" in data["acl"] and data["acl"]["inline"] is not None:
            if not isinstance(data["acl"]["inline"], list):
                return False, "Key 'acl.inline' must be a list of rule strings"

    return True, "Configuration is valid"

def build_hysteria_yaml(config_data: Dict[str, Any]) -> str:
    """Build a complete, optimized Hysteria 2 YAML configuration string."""
    listen_port = config_data.get("listen_port", 443)
    port_hop = config_data.get("port_hopping_enabled", True)
    port_range = str(config_data.get("port_hopping_range", "20000:50000")).replace(":", "-")

    # Hysteria 2 core listens directly on listen_port.
    # Dynamic port hopping is handled seamlessly by iptables NAT REDIRECT rules in firewall.py.
    listen_str = f":{listen_port}"

    tls_type = config_data.get("tls_type", "self_signed_ip")
    server_domain = str(config_data.get("server_domain", "") or "").strip()

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

    # Dynamic Sniff block
    sniff_enable_raw = config_data.get("sniff_enable") if "sniff_enable" in config_data else config_data.get("sniff_enabled")
    if sniff_enable_raw is None:
        sniff_enable = True
    else:
        sniff_enable = str(sniff_enable_raw).lower() in ("1", "true")

    sniff_timeout = str(config_data.get("sniff_timeout", "2s") or "2s").strip()

    rewrite_domain_raw = config_data.get("rewrite_domain") if "rewrite_domain" in config_data else config_data.get("sniff_rewrite_domain")
    if rewrite_domain_raw is None:
        rewrite_domain = False
    else:
        rewrite_domain = str(rewrite_domain_raw).lower() in ("1", "true")

    sniff_block = f"""sniff:
  enable: {"true" if sniff_enable else "false"}
  timeout: {sniff_timeout}
  rewriteDomain: {"true" if rewrite_domain else "false"}"""

    # Outbounds & Routing Policy
    global_outbound = str(config_data.get("routing_global_outbound", "direct") or "direct").strip().lower()
    warp_port = config_data.get("warp_port", "40000")

    warp_enabled_raw = config_data.get("warp_enabled")
    if warp_enabled_raw is not None:
        warp_is_active = str(warp_enabled_raw).lower() in ("1", "true")
    else:
        warp_is_active = (global_outbound == "warp")

    outbounds_block = ""
    if warp_is_active:
        outbounds_block = f"""outbounds:
  - name: direct
    type: direct
  - name: warp
    type: socks5
    socks5:
      addr: 127.0.0.1:{warp_port}
"""

    # ACL Rules Generation
    # Rule Ordering: Rejections (ads, spy, p2p, private IPs, blocked services/RU) strictly precede outbounds
    reject_rules: List[str] = []
    routing_rules: List[str] = []

    # 1. Ad-blocking
    ads_val = config_data.get("routing_ads", "1")
    if str(ads_val).lower() in ("1", "true"):
        reject_rules.append("reject(geosite:category-ads-all)")

    # 2. Windows telemetry / spyware blocking
    win_spy_val = config_data.get("routing_win_spy", "1")
    if str(win_spy_val).lower() in ("1", "true"):
        reject_rules.append("reject(geosite:win-spy)")

    # 3. P2P / BitTorrent blocking
    p2p_mode = str(config_data.get("routing_p2p", "block") or "block").strip().lower()
    if p2p_mode == "block":
        reject_rules.append("reject(geosite:bittorrent)")

    # 4. RFC 1918 & RFC 4193 private subnet protection
    reject_rules.append("reject(10.0.0.0/8)")
    reject_rules.append("reject(172.16.0.0/12)")
    reject_rules.append("reject(192.168.0.0/16)")
    reject_rules.append("reject(127.0.0.0/8)")
    reject_rules.append("reject(fc00::/7)")

    # 5. Service preset definitions (OpenAI, Discord, YouTube, Telegram, Netflix)
    services = [
        ("routing_openai", "geosite:openai", "warp"),
        ("routing_discord", "geosite:discord", "warp"),
        ("routing_youtube", "geosite:youtube", "warp"),
        ("routing_telegram", "geosite:telegram", "direct"),
        ("routing_netflix", "geosite:netflix", "warp"),
    ]

    for key, geosite, default_target in services:
        mode = str(config_data.get(key, default_target) or default_target).strip().lower()
        if mode == "block":
            reject_rules.append(f"reject({geosite})")
        elif mode == "warp" and warp_is_active:
            routing_rules.append(f"outbound(warp, {geosite})")
        elif mode == "direct" and warp_is_active and global_outbound == "warp":
            routing_rules.append(f"direct({geosite})")

    # 6. RU Traffic routing rules (geosite:ru, geoip:ru)
    ru_mode = str(config_data.get("routing_ru") or config_data.get("ru_routing", "direct") or "direct").strip().lower()
    if ru_mode not in ("direct", "warp", "block"):
        ru_mode = "direct"

    if ru_mode == "block":
        reject_rules.append("reject(geosite:ru)")
        reject_rules.append("reject(geoip:ru)")
    elif ru_mode == "warp" and warp_is_active:
        routing_rules.append("outbound(warp, geosite:ru)")
        routing_rules.append("outbound(warp, geoip:ru)")
    elif ru_mode == "direct" and warp_is_active and global_outbound == "warp":
        routing_rules.append("direct(geosite:ru)")
        routing_rules.append("direct(geoip:ru)")

    # 7. Global outbound fallback
    if global_outbound == "warp" and warp_is_active:
        routing_rules.append("outbound(warp, all)")
    elif warp_is_active:
        routing_rules.append("direct(all)")

    # Deduplicate rules while strictly preserving insertion order
    all_acl_rules: List[str] = []
    seen = set()
    for rule in reject_rules + routing_rules:
        if rule not in seen:
            seen.add(rule)
            all_acl_rules.append(rule)

    acl_lines = "\n".join(f"    - {r}" for r in all_acl_rules)
    acl_block = f"""acl:
  inline:
{acl_lines}
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

{sniff_block}

trafficStats:
  listen: 127.0.0.1:{settings.HYSTERIA_TRAFFIC_STATS_PORT}
  secret: "{traffic_secret}"

{masq_block}

{outbounds_block}{acl_block}"""
    return yaml_content

async def apply_and_save_config(custom_yaml: Optional[str] = None) -> ConfigApplyResult:
    """
    Read settings from SQLite, generate config.yaml, validate syntax and keys,
    backup existing config to config.yaml.bak, write atomically, and roll back
    if validation or writing fails.
    Returns ConfigApplyResult(success: bool, message: str).
    """
    config_path = Path(settings.HYSTERIA_CONFIG_PATH)
    backup_path = Path(str(settings.HYSTERIA_CONFIG_PATH) + ".bak")

    try:
        if custom_yaml is not None:
            yaml_text = custom_yaml
        else:
            current_settings = await crud.get_all_settings()
            yaml_text = build_hysteria_yaml(current_settings)

        # 1. Pre-validation before writing
        is_valid, val_err = validate_hysteria_config(yaml_text)
        if not is_valid:
            logger.error(f"Hysteria config pre-write validation failed: {val_err}")
            return ConfigApplyResult(False, f"Pre-validation failed: {val_err}")

        # 2. Backup existing valid configuration
        if config_path.exists():
            try:
                backup_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(config_path, backup_path)
                logger.info(f"Backed up current config to {backup_path}")
            except Exception as be:
                logger.warning(f"Failed to create config backup: {be}")

        # 3. Write atomically to temporary file first
        config_path.parent.mkdir(parents=True, exist_ok=True)
        temp_target = config_path.parent / f"{config_path.name}.tmp.{os.getpid()}"
        with open(temp_target, "w", encoding="utf-8") as f:
            f.write(yaml_text)

        # 4. Verify written temp file
        written_content = temp_target.read_text(encoding="utf-8")
        is_valid_written, written_err = validate_hysteria_config(written_content)
        if not is_valid_written:
            temp_target.unlink(missing_ok=True)
            logger.error(f"Written temp config failed validation: {written_err}")
            return ConfigApplyResult(False, f"Post-validation failed: {written_err}")

        # 5. Atomic replacement
        temp_target.replace(config_path)
        logger.info(f"Hysteria 2 configuration saved to {config_path}")
        return ConfigApplyResult(True, f"Hysteria 2 configuration saved to {config_path}")

    except Exception as e:
        logger.error(f"Failed to generate or write Hysteria config: {e}")
        # Rollback from backup if backup exists
        if backup_path.exists():
            try:
                shutil.copy2(backup_path, config_path)
                logger.info(f"Restored previous config from {backup_path} after failure")
            except Exception as re:
                logger.error(f"Rollback failed: {re}")
        return ConfigApplyResult(False, f"Failed to save config: {e}")

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

def clear_service_logs() -> Tuple[bool, str]:
    """Rotate and vacuum journalctl logs to immediately clear on-disk logs."""
    try:
        subprocess.run(["journalctl", "--rotate"], capture_output=True, timeout=5)
        subprocess.run(["journalctl", "--vacuum-time=1s"], capture_output=True, text=True, timeout=5)
        return True, "Системные логи успешно очищены"
    except Exception as e:
        return False, str(e)

def configure_service_logging(level: str = "info", zero_logs: bool = False) -> Tuple[bool, str]:
    """
    Update systemd service configuration to control Hysteria log level
    or completely disable log collection (Zero Logs privacy mode).
    """
    try:
        service_file = Path("/etc/systemd/system/hysteria-server.service")
        if not service_file.exists():
            return True, "Настройка сохранена (systemd файл вне Linux)"

        out_dest = "null" if zero_logs else "journal"
        lvl = "error" if zero_logs else level.lower()

        content = f"""[Unit]
Description=Hysteria 2 Server
After=network.target

[Service]
Type=simple
User=root
Environment=HYSTERIA_LOG_LEVEL={lvl}
StandardOutput={out_dest}
StandardError={out_dest}
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.yaml
Restart=always
RestartSec=3s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
"""
        with open(service_file, "w", encoding="utf-8") as f:
            f.write(content)

        subprocess.run(["systemctl", "daemon-reload"], capture_output=True, timeout=5)
        restart_hysteria()
        return True, "Конфигурация логирования успешно применена"
    except Exception as e:
        return False, str(e)

