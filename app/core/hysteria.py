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
from app.core.firewall import validate_port_hopping_string

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
    Validates YAML syntax, required top-level keys, outbound definitions,
    and individual acl.inline rule formats.
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

    # Check listen
    listen_val = data.get("listen")
    if not isinstance(listen_val, (str, int)):
        return False, "Key 'listen' must be a port string or integer"

    # Check tls structure
    if not isinstance(data.get("tls"), (dict, str)):
        return False, "Key 'tls' must be a mapping"

    # Check auth structure
    if not isinstance(data.get("auth"), (dict, str)):
        return False, "Key 'auth' must be a mapping"

    known_outbounds = set()
    # Check outbounds if present
    if "outbounds" in data and data["outbounds"] is not None:
        if not isinstance(data["outbounds"], list):
            return False, "Key 'outbounds' must be a list"
        for ob in data["outbounds"]:
            if not isinstance(ob, dict) or "name" not in ob or "type" not in ob:
                return False, "Each outbound must be a mapping with 'name' and 'type'"
            known_outbounds.add(ob["name"])

    # Check acl if present
    if "acl" in data and data["acl"] is not None:
        if not isinstance(data["acl"], dict):
            return False, "Key 'acl' must be a mapping"
        if "inline" in data["acl"] and data["acl"]["inline"] is not None:
            if not isinstance(data["acl"]["inline"], list):
                return False, "Key 'acl.inline' must be a list of rule strings"
            for rule in data["acl"]["inline"]:
                if not isinstance(rule, str):
                    return False, f"Each rule in acl.inline must be a string, got {type(rule)}"
                rule_str = rule.strip()
                if not rule_str:
                    return False, "Empty rule in acl.inline"
                # Validate rule format: action(matcher) or outbound(name, matcher)
                if not (rule_str.endswith(")") and "(" in rule_str):
                    return False, f"Malformed ACL rule syntax: '{rule_str}'. Missing parentheses."

                paren_open = rule_str.find("(")
                action_name = rule_str[:paren_open].strip().lower()
                arg = rule_str[paren_open + 1 : -1].strip()

                if not action_name:
                    return False, f"Malformed ACL rule syntax: '{rule_str}'. Missing action name."
                if not arg:
                    return False, f"Malformed ACL rule syntax: '{rule_str}'. Empty rule body."

                # If rule is outbound(name, pattern)
                if action_name == "outbound":
                    parts = [p.strip() for p in arg.split(",", 1)]
                    if len(parts) < 2:
                        return False, f"Invalid outbound ACL rule format: '{rule_str}'. Expected: outbound(name, pattern)"
                    target_ob = parts[0]
                    if known_outbounds and target_ob not in known_outbounds and target_ob not in ("direct", "warp"):
                        return False, f"ACL rule references unknown outbound '{target_ob}': '{rule_str}'"
                elif action_name not in ("direct", "reject"):
                    # Custom outbound direct action, e.g. warp(...)
                    if known_outbounds and action_name not in known_outbounds and action_name != "warp":
                        return False, f"ACL rule references unknown action/outbound '{action_name}': '{rule_str}'"

    return True, "Configuration is valid"

def compile_acl_rules(
    rules: Optional[List[Dict[str, Any]]] = None,
    global_outbound: str = "direct",
    presets: Optional[Dict[str, Any]] = None
) -> List[str]:
    """
    Dynamic Hysteria 2 ACL Compiler.
    Merges ACL rules in strict precedence order:
    1. Built-in Security / Private RFC 1918 subnets (reject)
    2. Threat / Ad rejections (ads, win-spy, p2p)
    3. Service presets (OpenAI, Discord, YouTube, Telegram, Netflix)
    4. RU regional rules
    5. User-defined custom routing rules (sorted by priority ASC, id ASC)
    6. Global outbound fallback rule (all)
    """
    if presets is None:
        presets = {}
    if rules is None:
        rules = []

    global_out = str(global_outbound or presets.get("routing_global_outbound", "direct") or "direct").strip().lower()

    # Check if any custom rule or service preset requires WARP outbound
    any_rule_needs_warp = any(
        (isinstance(r, dict) and str(r.get("action", "")).strip().lower() == "warp")
        for r in (rules or [])
    ) or any(
        str(presets.get(k, "")).strip().lower() == "warp"
        for k in ["routing_openai", "routing_discord", "routing_youtube", "routing_netflix", "routing_ru"]
    ) or (global_out == "warp")

    warp_enabled_raw = presets.get("warp_enabled")
    if warp_enabled_raw is not None:
        warp_is_active = str(warp_enabled_raw).lower() in ("1", "true")
    else:
        warp_is_active = (global_out == "warp")

    if any_rule_needs_warp:
        warp_is_active = True

    reject_rules: List[str] = []
    routing_rules: List[str] = []
    custom_rules_acl: List[str] = []

    # 1. Built-in Security / Private RFC 1918 & RFC 4193 protections
    reject_rules.append("reject(10.0.0.0/8)")
    reject_rules.append("reject(172.16.0.0/12)")
    reject_rules.append("reject(192.168.0.0/16)")
    reject_rules.append("reject(127.0.0.0/8)")
    reject_rules.append("reject(fc00::/7)")

    # 2. Threat / Ad rejections
    ads_val = presets.get("routing_ads", "1")
    if str(ads_val).lower() in ("1", "true"):
        reject_rules.append("reject(geosite:category-ads-all)")

    win_spy_val = presets.get("routing_win_spy", "1")
    if str(win_spy_val).lower() in ("1", "true"):
        reject_rules.append("reject(geosite:win-spy)")

    # P2P / BitTorrent is not a GeoSite domain list in standard geosite.dat.
    # Emitting reject(geosite:bittorrent) crashes Hysteria 2 with FATAL "GeoSite name bittorrent not found".
    # Torrent/P2P filtering is handled via custom domain/IP ACL rules.

    # 3. Service presets (OpenAI, Discord, YouTube, Telegram, Netflix)
    services = [
        ("routing_openai", "geosite:openai", "warp"),
        ("routing_discord", "geosite:discord", "warp"),
        ("routing_youtube", "geosite:youtube", "warp"),
        ("routing_telegram", "geosite:telegram", "direct"),
        ("routing_netflix", "geosite:netflix", "warp"),
    ]

    for key, geosite, default_val in services:
        raw_val = presets.get(key)
        if raw_val is None:
            raw_val = default_val
        if not raw_val or str(raw_val).lower() in ("off", "none", "", "disabled"):
            continue
        mode = str(raw_val).strip().lower()
        if mode == "block":
            reject_rules.append(f"reject({geosite})")
        elif mode == "warp" and warp_is_active:
            routing_rules.append(f"outbound(warp, {geosite})")
        elif mode == "direct" and warp_is_active and global_out == "warp":
            routing_rules.append(f"direct({geosite})")

    # 4. RU Traffic routing rules (geosite:ru, geoip:ru)
    ru_mode = str(presets.get("routing_ru") or presets.get("ru_routing", "direct") or "direct").strip().lower()
    if ru_mode not in ("direct", "warp", "block"):
        ru_mode = "direct"

    if ru_mode == "block":
        reject_rules.append("reject(geosite:ru)")
        reject_rules.append("reject(geoip:ru)")
    elif ru_mode == "warp" and warp_is_active:
        routing_rules.append("outbound(warp, geosite:ru)")
        routing_rules.append("outbound(warp, geoip:ru)")
    elif ru_mode == "direct" and warp_is_active and global_out == "warp":
        routing_rules.append("direct(geosite:ru)")
        routing_rules.append("direct(geoip:ru)")

    # 5. User-defined custom routing rules sorted by priority ASC, id ASC
    enabled_rules = [r for r in rules if r.get("enabled", True)]
    sorted_rules = sorted(enabled_rules, key=lambda r: (r.get("priority", 100), r.get("id", 0)))

    for rule in sorted_rules:
        action = str(rule.get("action", "direct")).strip().lower()
        rule_type = str(rule.get("rule_type", "domain")).strip().lower()
        raw_vals = rule.get("rule_values", [])
        if isinstance(raw_vals, str):
            try:
                raw_vals = json.loads(raw_vals)
            except Exception:
                raw_vals = [raw_vals]

        for rv in raw_vals:
            val = str(rv).strip()
            if not val:
                continue

            matchers: List[str] = []
            if rule_type == "domain":
                clean = val.removeprefix("domain:").strip()
                if clean.startswith("*."):
                    clean = clean[2:]
                matchers = [clean, f"suffix:{clean}", f"domain:{clean}"]
            elif rule_type == "suffix":
                clean = val.removeprefix("suffix:").removeprefix("domain-suffix:").strip()
                if clean.startswith("*."):
                    clean = clean[2:]
                elif clean.startswith("."):
                    clean = clean[1:]
                matchers = [f"suffix:{clean}", f"*.{clean}"]
            elif rule_type == "keyword":
                clean = val.strip("*").removeprefix("keyword:").removeprefix("domain-keyword:").strip()
                matchers = [f"*{clean}*"]
            elif rule_type == "ip_cidr":
                clean = val.removeprefix("cidr:").strip()
                matchers = [clean]
            elif rule_type == "geoip":
                clean = val.removeprefix("geoip:").strip().lower()
                matchers = [f"geoip:{clean}"]
            elif rule_type == "geosite":
                clean = val.removeprefix("geosite:").strip().lower()
                if clean in ("bittorrent", "torrent", "p2p"):
                    continue
                matchers = [f"geosite:{clean}"]
            else:
                matchers = [val]

            for matcher in matchers:
                if action == "block":
                    custom_rules_acl.append(f"reject({matcher})")
                elif action == "warp":
                    if warp_is_active:
                        custom_rules_acl.append(f"outbound(warp, {matcher})")
                    else:
                        custom_rules_acl.append(f"direct({matcher})")
                else:  # direct
                    custom_rules_acl.append(f"direct({matcher})")

    # 6. Global outbound fallback rule
    fallback_rule = None
    if global_out == "warp" and warp_is_active:
        fallback_rule = "outbound(warp, all)"
    elif warp_is_active:
        fallback_rule = "direct(all)"

    # Deduplicate rules while strictly preserving insertion order
    all_acl: List[str] = []
    seen = set()
    for rule in reject_rules + routing_rules + custom_rules_acl:
        if rule not in seen:
            seen.add(rule)
            all_acl.append(rule)

    if fallback_rule and fallback_rule not in seen:
        all_acl.append(fallback_rule)

    return all_acl

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

    rewrite_domain_raw = (
        config_data.get("sniff_rewrite_domain")
        if "sniff_rewrite_domain" in config_data
        else config_data.get("rewrite_domain")
        if "rewrite_domain" in config_data
        else config_data.get("rewriteDomain")
    )
    if rewrite_domain_raw is None:
        rewrite_domain = True
    else:
        rewrite_domain = str(rewrite_domain_raw).lower() in ("1", "true")

    sniff_block = f"""sniff:
  enable: {"true" if sniff_enable else "false"}
  timeout: {sniff_timeout}
  rewriteDomain: {"true" if rewrite_domain else "false"}
  tcpPorts: all
  udpPorts: all"""

    # Outbounds & Routing Policy
    global_outbound = str(config_data.get("routing_global_outbound", "direct") or "direct").strip().lower()
    warp_port = config_data.get("warp_port", "40000")

    custom_rules = config_data.get("custom_routing_rules") or config_data.get("routing_rules") or []
    any_rule_needs_warp = any(
        (isinstance(r, dict) and str(r.get("action", "")).strip().lower() == "warp")
        for r in custom_rules
    ) or any(
        str(config_data.get(k, "")).strip().lower() == "warp"
        for k in ["routing_openai", "routing_discord", "routing_youtube", "routing_netflix", "routing_ru"]
    ) or (global_outbound == "warp")

    warp_enabled_raw = config_data.get("warp_enabled")
    if warp_enabled_raw is not None:
        warp_is_active = str(warp_enabled_raw).lower() in ("1", "true")
    else:
        warp_is_active = (global_outbound == "warp")

    if any_rule_needs_warp:
        warp_is_active = True

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

    # Advanced Server Parameters: Configurable QUIC window sizes / idle timeouts
    init_stream_rx = config_data.get("init_stream_rx_window") or config_data.get("init_stream_receive_window") or 8388608
    max_stream_rx = config_data.get("max_stream_rx_window") or config_data.get("max_stream_receive_window") or 8388608
    init_conn_rx = config_data.get("init_conn_rx_window") or config_data.get("init_conn_receive_window") or 20971520
    max_conn_rx = config_data.get("max_conn_rx_window") or config_data.get("max_conn_receive_window") or 20971520
    max_idle = str(config_data.get("max_idle_timeout", "30s") or "30s").strip()
    max_streams = config_data.get("max_incoming_streams", 2048)
    keep_alive = config_data.get("keep_alive_period")
    keep_alive_line = f"\n  keepAlivePeriod: {keep_alive}" if keep_alive else ""

    quic_block = f"""quic:
  initStreamReceiveWindow: {int(init_stream_rx)}
  maxStreamReceiveWindow: {int(max_stream_rx)}
  initConnReceiveWindow: {int(init_conn_rx)}
  maxConnReceiveWindow: {int(max_conn_rx)}
  maxIdleTimeout: {max_idle}
  maxIncomingStreams: {int(max_streams)}{keep_alive_line}"""

    # Compile ACL rules merging security, service presets, custom rules, and fallback
    custom_rules = config_data.get("custom_routing_rules") or config_data.get("routing_rules") or []
    all_acl_rules = compile_acl_rules(custom_rules, global_outbound=global_outbound, presets=config_data)

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

{quic_block}

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
            try:
                custom_rules = await crud.get_routing_rules(enabled_only=True)
                current_settings["custom_routing_rules"] = custom_rules
            except Exception as re:
                logger.warning(f"Could not load custom routing rules for config: {re}")
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

