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

    # TLS & SNI
    tls_type = settings_dict.get("tls_type", "self_signed_ip")
    custom_sni = (settings_dict.get("sni") or settings_dict.get("custom_sni") or "").strip()
    domain = (settings_dict.get("server_domain") or "").strip()

    if custom_sni:
        params["sni"] = custom_sni
    elif domain:
        params["sni"] = domain

    if tls_type == "self_signed_ip":
        cert_sha256 = settings_dict.get("cert_sha256", "")
        if cert_sha256:
            params["pinSHA256"] = cert_sha256
        else:
            params["insecure"] = "1"

    query_str = urllib.parse.urlencode(params)
    tag = f"InnerBlitz-{username}"
    tag_encoded = urllib.parse.quote(tag)

    return f"hy2://{username}:{password}@{server_host}:{port}?{query_str}#{tag_encoded}"

def build_clash_yaml(user: Dict[str, Any], settings_dict: Dict[str, Any]) -> str:
    """Generate Clash Meta / Mihomo configuration for user with split routing."""
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

    custom_sni = (settings_dict.get("sni") or settings_dict.get("custom_sni") or settings_dict.get("server_domain") or "").strip()
    if custom_sni:
        clash_proxy["sni"] = custom_sni

    if str(settings_dict.get("port_hopping_enabled", "1")).lower() in ("1", "true"):
        mport = settings_dict.get("port_hopping_range", "20000:50000").replace(":", "-")
        if mport:
            clash_proxy["ports"] = mport

    if settings_dict.get("obfs_type") == "salamander" and settings_dict.get("obfs_password"):
        clash_proxy["obfs"] = "salamander"
        clash_proxy["obfs-password"] = settings_dict.get("obfs_password")

    ru_routing = str(settings_dict.get("routing_ru") or settings_dict.get("ru_routing") or "direct").lower()

    if ru_routing == "block":
        ru_default_proxies = ["REJECT", "DIRECT", "PROXY"]
    elif ru_routing == "warp":
        ru_default_proxies = ["PROXY", "DIRECT", "REJECT"]
    else:  # direct
        ru_default_proxies = ["DIRECT", "PROXY", "REJECT"]

    proxy_groups = [
        {
            "name": "PROXY",
            "type": "select",
            "proxies": [f"InnerBlitz-{username}", "DIRECT"]
        },
        {
            "name": "RU-Traffic",
            "type": "select",
            "proxies": ru_default_proxies
        },
        {
            "name": "Services",
            "type": "select",
            "proxies": ["PROXY", "DIRECT"]
        }
    ]

    rules = [
        "DOMAIN-SUFFIX,local,DIRECT",
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "GEOIP,LAN,DIRECT",
        "GEOSITE,category-ads-all,REJECT",
    ]

    if ru_routing == "block":
        rules.extend([
            "GEOSITE,ru,REJECT",
            "GEOIP,RU,REJECT"
        ])
    elif ru_routing == "warp":
        rules.extend([
            "GEOSITE,ru,PROXY",
            "GEOIP,RU,PROXY"
        ])
    else:  # direct
        rules.extend([
            "GEOSITE,ru,RU-Traffic",
            "GEOIP,RU,RU-Traffic"
        ])

    rules.extend([
        "GEOSITE,openai,Services",
        "GEOSITE,netflix,Services",
        "MATCH,PROXY"
    ])

    doc = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": [clash_proxy],
        "proxy-groups": proxy_groups,
        "rules": rules
    }
    import yaml
    return yaml.dump(doc, sort_keys=False, allow_unicode=True)

def build_singbox_json(user: Dict[str, Any], settings_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Generate complete Sing-box v1.10+ client JSON profile with inbounds, dns, outbounds, and route."""
    server_host = settings_dict.get("server_domain") or settings_dict.get("server_ip") or "127.0.0.1"
    port = int(settings_dict.get("listen_port", 443))
    username = user.get("username", "user")
    password = user.get("password", "")
    proxy_tag = f"InnerBlitz-{username}"

    outbound = {
        "type": "hysteria2",
        "tag": proxy_tag,
        "server": server_host,
        "server_port": port,
        "password": f"{username}:{password}",
        "tls": {
            "enabled": True,
            "insecure": True
        }
    }
    custom_sni = (settings_dict.get("sni") or settings_dict.get("custom_sni") or settings_dict.get("server_domain") or "").strip()
    if custom_sni:
        outbound["tls"]["server_name"] = custom_sni

    from app.core.cert import get_certificate_spki_sha256
    spki_hash = get_certificate_spki_sha256()
    if spki_hash:
        outbound["tls"]["certificate_public_key_sha256"] = spki_hash

    cert_sha256 = settings_dict.get("cert_sha256", "")
    if cert_sha256:
        outbound["tls"]["pinSHA256"] = cert_sha256

    if str(settings_dict.get("port_hopping_enabled", "1")).lower() in ("1", "true"):
        mport = settings_dict.get("port_hopping_range", "20000:50000").replace(":", "-")
        if mport:
            outbound["server_ports"] = mport

    if settings_dict.get("obfs_type") == "salamander" and settings_dict.get("obfs_password"):
        outbound["obfs"] = {
            "type": "salamander",
            "password": settings_dict.get("obfs_password")
        }

    ru_routing = str(settings_dict.get("routing_ru") or settings_dict.get("ru_routing") or "direct").lower()

    route_rules = [
        {"protocol": "dns", "outbound": "dns-out"},
        {"ip_is_private": True, "outbound": "direct"},
        {"geosite": ["category-ads-all"], "outbound": "block"}
    ]

    if ru_routing == "block":
        route_rules.append({"geosite": ["ru"], "outbound": "block"})
        route_rules.append({"geoip": ["ru"], "outbound": "block"})
    elif ru_routing == "warp":
        route_rules.append({"geosite": ["ru"], "outbound": proxy_tag})
        route_rules.append({"geoip": ["ru"], "outbound": proxy_tag})
    else:  # direct
        route_rules.append({"geosite": ["ru"], "outbound": "direct"})
        route_rules.append({"geoip": ["ru"], "outbound": "direct"})

    return {
        "version": 1,
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "tun0",
                "inet4_address": "172.19.0.1/30",
                "auto_route": True,
                "strict_route": True,
                "sniff": True,
                "sniff_override_destination": False
            },
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 2080,
                "sniff": True
            }
        ],
        "dns": {
            "servers": [
                {
                    "tag": "dns-remote",
                    "address": "https://1.1.1.1/dns-query",
                    "address_resolver": "dns-direct",
                    "strategy": "prefer_ipv4",
                    "detour": proxy_tag
                },
                {
                    "tag": "dns-direct",
                    "address": "https://77.88.8.8/dns-query",
                    "strategy": "prefer_ipv4",
                    "detour": "direct"
                },
                {
                    "tag": "dns-block",
                    "address": "rcode://success"
                }
            ],
            "rules": [
                {"outbound": "any", "server": "dns-direct"},
                {"geosite": ["category-ads-all"], "server": "dns-block"}
            ],
            "strategy": "prefer_ipv4"
        },
        "outbounds": [
            outbound,
            {"type": "direct", "tag": "direct"},
            {"type": "dns", "tag": "dns-out"},
            {"type": "block", "tag": "block"}
        ],
        "route": {
            "auto_detect_interface": True,
            "final": proxy_tag,
            "rules": route_rules
        }
    }

def build_base64_sub(user: Dict[str, Any], settings_dict: Dict[str, Any]) -> str:
    """Return Base64-encoded subscription string containing hy2:// link."""
    uri = build_hy2_uri(user, settings_dict)
    return base64.b64encode(uri.encode("utf-8")).decode("utf-8")
