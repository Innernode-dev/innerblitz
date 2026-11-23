#!/usr/bin/env bash
# ==============================================================================
#  ⚡ InnerBlitz - Automated 1-Click WARP Installer for Bare Metal
#  Supports: Cloudflare WARP SOCKS5 (127.0.0.1:40000) & WireGuard (wgcf)
# ==============================================================================
set -eo pipefail

PORT=40000
MODE="auto" # auto | socks5 | wgcf
CLEAN=0

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --mode=*) MODE="${1#*=}" ;;
        --port=*) PORT="${1#*=}" ;;
        --clean) CLEAN=1 ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

log() { echo -e "[$(date -u +'%Y-%m-%d %H:%M:%SZ')] [$1] $2"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log "ERROR" "This script must be executed as root."
        exit 1
    fi
}

detect_system() {
    OS="unknown"
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        OS=$ID
    fi
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) ARCH_WARP="amd64" ;;
        aarch64|arm64) ARCH_WARP="arm64" ;;
        *) log "ERROR" "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    log "INFO" "Detected System: OS=$OS, Arch=$ARCH ($ARCH_WARP)"
}

cleanup_existing_warp() {
    log "INFO" "Cleaning up previous WARP daemons/interfaces before fresh install..."
    systemctl stop warp-svc 2>/dev/null || true
    systemctl stop wg-quick@warp 2>/dev/null || true
    ip link del warp 2>/dev/null || true
}

check_port_available() {
    local listener=""
    if command -v ss &>/dev/null; then
        listener=$(ss -tlnp "sport = :$PORT" 2>/dev/null | grep ":$PORT\b" || true)
    elif command -v netstat &>/dev/null; then
        listener=$(netstat -tlnp 2>/dev/null | grep ":$PORT\b" || true)
    fi
    if [[ -n "$listener" ]]; then
        # Allow overwrite if warp-svc itself owns the port
        if echo "$listener" | grep -qi "warp-svc"; then
            log "INFO" "Port $PORT is currently held by warp-svc; will reconfigure in place."
            return 0
        fi
        log "ERROR" "Port $PORT is already in use by another process."
        exit 2
    fi
}

install_cloudflare_warp_socks5() {
    log "INFO" "[PHASE 1/5] Installing official Cloudflare WARP repository..."
    if [[ "$OS" =~ ^(ubuntu|debian)$ ]]; then
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl gnupg lsb-release
        curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
        echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/cloudflare-client.list >/dev/null
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq cloudflare-warp
    elif [[ "$OS" =~ ^(centos|rhel|almalinux|rocky)$ ]]; then
        curl -fsSL -o /etc/yum.repos.d/cloudflare-warp.repo https://pkg.cloudflareclient.com/cloudflare-warp-ascii.repo
        yum install -y -q cloudflare-warp
    else
        log "WARN" "Distro $OS not directly supported by Cloudflare apt/yum repository. Falling back to wgcf."
        return 1
    fi

    log "INFO" "[PHASE 2/5] Starting and enabling warp-svc systemd unit..."
    systemctl enable --now warp-svc
    for _ in {1..10}; do
        if warp-cli --accept-tos status >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done

    log "INFO" "[PHASE 3/5] Registering WARP client account..."
    # Support both newer (v2024+) and legacy warp-cli syntax
    warp-cli --accept-tos registration new 2>/dev/null || warp-cli --accept-tos register 2>/dev/null || true

    log "INFO" "[PHASE 4/5] Configuring SOCKS5 Proxy Mode on 127.0.0.1:$PORT..."
    warp-cli --accept-tos mode proxy 2>/dev/null || warp-cli --accept-tos set-mode proxy
    warp-cli --accept-tos proxy port "$PORT" 2>/dev/null || warp-cli --accept-tos set-proxy-port "$PORT"
    warp-cli --accept-tos connect || true

    log "INFO" "[PHASE 5/5] Verifying Cloudflare SOCKS5 connectivity..."
    local ok=0
    for _ in {1..10}; do
        sleep 1
        TRACE=$(curl -s4 -m 5 -x "socks5h://127.0.0.1:$PORT" https://cloudflare.com/cdn-cgi/trace 2>/dev/null || true)
        if echo "$TRACE" | grep -qE "warp=(on|plus)"; then
            COLO=$(echo "$TRACE" | grep "colo=" | cut -d= -f2)
            IP=$(echo "$TRACE" | grep "ip=" | cut -d= -f2)
            log "SUCCESS" "WARP SOCKS5 verified active on 127.0.0.1:$PORT (IP: $IP, Colo: $COLO)"
            ok=1
            break
        fi
    done

    if [[ $ok -eq 0 ]]; then
        log "ERROR" "WARP SOCKS5 connection verification failed after 10 attempts."
        return 1
    fi
    return 0
}

install_wgcf_wireguard() {
    log "INFO" "[PHASE 1/5] Installing WireGuard packages and wgcf..."
    if [[ "$OS" =~ ^(ubuntu|debian)$ ]]; then
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard-tools curl jq
    elif [[ "$OS" =~ ^(centos|rhel|almalinux|rocky)$ ]]; then
        yum install -y -q epel-release || true
        yum install -y -q wireguard-tools curl jq
    fi

    mkdir -p /etc/wireguard
    cd /etc/wireguard

    if [[ ! -f /usr/local/bin/wgcf ]]; then
        WGCF_VER="2.2.23"
        log "INFO" "Downloading wgcf v${WGCF_VER} for $ARCH_WARP..."
        curl -fsSL -o /usr/local/bin/wgcf "https://github.com/ViRb3/wgcf/releases/download/v${WGCF_VER}/wgcf_${WGCF_VER}_linux_${ARCH_WARP}"
        chmod +x /usr/local/bin/wgcf
    fi

    log "INFO" "[PHASE 2/5] Generating WireGuard WARP account..."
    if [[ ! -f /etc/wireguard/wgcf-account.toml ]]; then
        /usr/local/bin/wgcf register --accept-tos
    fi

    log "INFO" "[PHASE 3/5] Generating WireGuard WARP configuration profile..."
    /usr/local/bin/wgcf generate

    log "INFO" "[PHASE 4/5] Tuning /etc/wireguard/warp.conf (Table = 51820, MTU = 1280, PersistentKeepalive = 25, policy routing & TCPMSS)..."
    python3 - << 'PYEOF'
from pathlib import Path

src = Path("/etc/wireguard/wgcf-profile.conf").read_text(encoding="utf-8")
out_lines = []
section = ""
has_keepalive = False

for raw_line in src.splitlines():
    stripped = raw_line.strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        if section == "[Peer]" and not has_keepalive:
            out_lines.append("PersistentKeepalive = 25")
            has_keepalive = True
        section = stripped
        out_lines.append(raw_line)
        if section == "[Interface]":
            out_lines.extend([
                "Table = 51820",
                "MTU = 1280",
                "PostUp = sysctl -w net.ipv4.conf.all.rp_filter=2 net.ipv4.conf.%i.rp_filter=2 || true",
                'PostUp = WG_IP=$(ip -4 -o addr show dev %i | head -n1 | tr -s " " | cut -d" " -f4 | cut -d/ -f1); [ -n "$WG_IP" ] && ip -4 rule add from "$WG_IP/32" lookup 51820 prio 30000 || true',
                "PostUp = ip -4 rule add oif %i lookup 51820 prio 30001 || true",
                "PostUp = iptables -t nat -C POSTROUTING -o %i -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o %i -j MASQUERADE",
                "PostUp = iptables -t mangle -C POSTROUTING -o %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1220 2>/dev/null || iptables -t mangle -A POSTROUTING -o %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1220",
                "PostDown = ip -4 rule del lookup 51820 prio 30000 2>/dev/null || true",
                "PostDown = ip -4 rule del oif %i lookup 51820 prio 30001 || true",
                "PostDown = iptables -t nat -D POSTROUTING -o %i -j MASQUERADE 2>/dev/null || true",
                "PostDown = iptables -t mangle -D POSTROUTING -o %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1220 2>/dev/null || true",
            ])
        continue
    if section == "[Interface]" and any(stripped.startswith(k) for k in ("Table", "MTU", "DNS", "PostUp", "PostDown")):
        continue
    if section == "[Peer]" and stripped.startswith("PersistentKeepalive"):
        has_keepalive = True
        out_lines.append("PersistentKeepalive = 25")
        continue
    out_lines.append(raw_line)

if section == "[Peer]" and not has_keepalive:
    out_lines.append("PersistentKeepalive = 25")

Path("/etc/wireguard/warp.conf").write_text("\n".join(out_lines) + "\n", encoding="utf-8")
PYEOF
    chmod 600 /etc/wireguard/warp.conf

    systemctl restart wg-quick@warp 2>/dev/null || systemctl enable --now wg-quick@warp
    sleep 2

    log "INFO" "[PHASE 5/5] Verifying WireGuard interface connectivity..."
    local ok=0
    for _ in {1..10}; do
        sleep 1
        TRACE=$(curl -s4 -m 5 --interface warp https://cloudflare.com/cdn-cgi/trace 2>/dev/null || true)
        if echo "$TRACE" | grep -qE "warp=(on|plus)"; then
            COLO=$(echo "$TRACE" | grep "colo=" | cut -d= -f2)
            IP=$(echo "$TRACE" | grep "ip=" | cut -d= -f2)
            log "SUCCESS" "WARP WireGuard verified active on interface 'warp' (IP: $IP, Colo: $COLO)"
            ok=1
            break
        fi
    done

    if [[ $ok -eq 0 ]]; then
        log "ERROR" "WireGuard WARP verification failed."
        return 1
    fi
    return 0
}

main() {
    check_root
    detect_system

    if [[ "$CLEAN" -eq 1 ]]; then
        cleanup_existing_warp
    fi

    if [[ "$MODE" == "socks5" ]]; then
        check_port_available
        install_cloudflare_warp_socks5
    elif [[ "$MODE" == "wgcf" ]]; then
        install_wgcf_wireguard
    else
        # Auto Mode: Try Cloudflare official SOCKS5 first, fallback to WireGuard
        check_port_available
        if ! install_cloudflare_warp_socks5; then
            log "WARN" "Official Cloudflare WARP installation failed. Falling back to WireGuard wgcf..."
            install_wgcf_wireguard
        fi
    fi

    log "SUCCESS" "1-Click WARP Installation Completed Successfully."
    exit 0
}

main
