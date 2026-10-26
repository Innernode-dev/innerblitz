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

check_port_available() {
    if command -v ss &>/dev/null; then
        if ss -tln "sport = :$PORT" | grep -q ":$PORT\b"; then
            log "ERROR" "Port $PORT is already in use by another process."
            exit 2
        fi
    elif command -v netstat &>/dev/null; then
        if netstat -tln | grep -q ":$PORT\b"; then
            log "ERROR" "Port $PORT is already in use by another process."
            exit 2
        fi
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
    sleep 2

    log "INFO" "[PHASE 3/5] Registering WARP client account..."
    # Support both newer (v2024+) and legacy warp-cli syntax
    warp-cli --accept-tos registration new 2>/dev/null || warp-cli --accept-tos register 2>/dev/null || true

    log "INFO" "[PHASE 4/5] Configuring SOCKS5 Proxy Mode on 127.0.0.1:$PORT..."
    warp-cli --accept-tos mode proxy
    warp-cli --accept-tos proxy port "$PORT"
    warp-cli --accept-tos connect

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

    log "INFO" "[PHASE 4/5] Tuning /etc/wireguard/warp.conf (Table = off to prevent routing conflicts)..."
    cp -f wgcf-profile.conf /etc/wireguard/warp.conf
    # Ensure Table = off is present in [Interface] to prevent overriding server default route
    if ! grep -q "Table = off" /etc/wireguard/warp.conf; then
        sed -i '/\[Interface\]/a Table = off' /etc/wireguard/warp.conf
    fi

    systemctl enable --now wg-quick@warp
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
    check_port_available

    if [[ "$MODE" == "socks5" ]]; then
        install_cloudflare_warp_socks5
    elif [[ "$MODE" == "wgcf" ]]; then
        install_wgcf_wireguard
    else
        # Auto Mode: Try Cloudflare official SOCKS5 first, fallback to WireGuard
        if ! install_cloudflare_warp_socks5; then
            log "WARN" "Official Cloudflare WARP installation failed. Falling back to WireGuard wgcf..."
            install_wgcf_wireguard
        fi
    fi

    log "SUCCESS" "1-Click WARP Installation Completed Successfully."
    exit 0
}

main
