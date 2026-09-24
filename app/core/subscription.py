import base64
import json
import urllib.parse
from typing import Dict, Any, List

def build_hy2_uri(user: Dict[str, Any], settings_dict: Dict[str, Any]) -> str:
    """Generate standard hy2:// URI compatible with all modern clients."""
    server_host = settings_dict.get("server_domain") or settings_dict.get("server_ip") or "127.0.0.1"
    port = settings_dict.get("listen_port", 443)
    username = user.get("username", "user")
    password = user.get("password", "")

    params = {}
    
    # Port Hopping / mport
    if str(settings_dict.get("port_hopping_enabled", "1")).lower() in ("1", "true"):
        mport = settings_dict.get("port_hopping_range", "20000:50000").replace(":", "-")
        if mport and "-" in mport:
            params["mport"] = mport

    # Obfs
    if settings_dict.get("obfs_type") == "salamander" and settings_dict.get("obfs_password"):
        params["obfs"] = "salamander"
        params["obfs-password"] = settings_dict.get("obfs_password")

    # TLS
    tls_type = settings_dict.get("tls_type", "self_signed_ip")
    if tls_type == "self_signed_ip":
        params["insecure"] = "1"
        cert_sha256 = settings_dict.get("cert_sha256", "")
        if cert_sha256:
            params["pinSHA256"] = cert_sha256
    elif settings_dict.get("server_domain"):
        params["sni"] = settings_dict.get("server_domain")

    query_str = urllib.parse.urlencode(params)
    tag = f"InnerBlitz-{username}"
    tag_encoded = urllib.parse.quote(tag)

    return f"hy2://{username}:{password}@{server_host}:{port}?{query_str}#{tag_encoded}"

def build_clash_yaml(user: Dict[str, Any], settings_dict: Dict[str, Any]) -> str:
    """Generate Clash Meta / Mihomo configuration for user."""
    server_host = settings_dict.get("server_domain") or settings_dict.get("server_ip") or "127.0.0.1"
    port = int(settings_dict.get("listen_port", 443))
    username = user.get("username", "user")
    password = user.get("password", "")

    clash_proxy = {
        "name": f"InnerBlitz-{username}",
        "type": "hysteria2",
        "server": server_host,
        "port": port,
        "password": f"{username}:{password}",
        "skip-cert-verify": True,
    }

    if settings_dict.get("server_domain"):
        clash_proxy["sni"] = settings_dict.get("server_domain")

    if str(settings_dict.get("port_hopping_enabled", "1")).lower() in ("1", "true"):
        mport = settings_dict.get("port_hopping_range", "20000:50000").replace(":", "-")
        if mport:
            clash_proxy["ports"] = mport

    if settings_dict.get("obfs_type") == "salamander" and settings_dict.get("obfs_password"):
        clash_proxy["obfs"] = "salamander"
        clash_proxy["obfs-password"] = settings_dict.get("obfs_password")

    doc = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": [clash_proxy],
        "proxy-groups": [
            {
                "name": "PROXY",
                "type": "select",
                "proxies": [f"InnerBlitz-{username}", "DIRECT"]
            }
        ],
        "rules": [
            "GEOIP,LAN,DIRECT",
            "MATCH,PROXY"
        ]
    }
    import yaml
    return yaml.dump(doc, sort_keys=False, allow_unicode=True)

def build_singbox_json(user: Dict[str, Any], settings_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Generate Sing-box outbound configuration."""
    server_host = settings_dict.get("server_domain") or settings_dict.get("server_ip") or "127.0.0.1"
    port = int(settings_dict.get("listen_port", 443))
    username = user.get("username", "user")
    password = user.get("password", "")

    outbound = {
        "type": "hysteria2",
        "tag": f"InnerBlitz-{username}",
        "server": server_host,
        "server_port": port,
        "password": f"{username}:{password}",
        "tls": {
            "enabled": True,
            "insecure": True
        }
    }
    if settings_dict.get("server_domain"):
        outbound["tls"]["server_name"] = settings_dict.get("server_domain")

    if settings_dict.get("obfs_type") == "salamander" and settings_dict.get("obfs_password"):
        outbound["obfs"] = {
            "type": "salamander",
            "password": settings_dict.get("obfs_password")
        }

    return {
        "version": 1,
        "outbounds": [
            outbound,
            {"type": "direct", "tag": "direct"},
            {"type": "dns", "tag": "dns-out"}
        ]
    }

def build_base64_sub(user: Dict[str, Any], settings_dict: Dict[str, Any]) -> str:
    """Return Base64-encoded subscription string containing hy2:// link."""
    uri = build_hy2_uri(user, settings_dict)
    return base64.b64encode(uri.encode("utf-8")).decode("utf-8")
