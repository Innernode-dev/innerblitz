#!/usr/bin/env bash

# ==============================================================================
#  ⚡ InnerBlitz Upgrade Script — Next-Gen Hysteria 2 Management Panel
#  Repository: https://github.com/Innernode-dev/innerblitz.git
# ==============================================================================

set -e

INSTALL_DIR="/etc/hysteria"
REPO_URL="https://github.com/Innernode-dev/innerblitz.git"

# Colors
C_RESET='\033[0m'
C_BOLD='\033[1m'
C_GREEN='\033[0;32m'
C_CYAN='\033[0;36m'
C_YELLOW='\033[0;33m'
C_RED='\033[0;31m'
C_GRAY='\033[0;90m'

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${C_RED}Ошибка: Запустите скрипт с правами root!${C_RESET}"
    exit 1
fi

detect_ip() {
    local ip=""
    for url in "https://api.ipify.org" "https://icanhazip.com" "https://ip.sb" "https://ifconfig.me" "https://checkip.amazonaws.com"; do
        ip=$(curl -s4 -m 3 "$url" 2>/dev/null | tr -d '[:space:]')
        if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            SERVER_IP="$ip"
            return 0
        fi
    done
    ip=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' | tr -d '[:space:]')
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        SERVER_IP="$ip"
        return 0
    fi
    SERVER_IP="127.0.0.1"
}

echo -e "\n${C_CYAN}${C_BOLD}=== ⚡ Обновление InnerBlitz и ядра Hysteria 2 ===${C_RESET}\n"

# 1. Update Hysteria 2 core
echo -e "${C_YELLOW}[1/5] Обновление ядра Hysteria 2...${C_RESET}"
bash <(curl -fsSL https://get.hy2.sh/) >/dev/null 2>&1 || true
if command -v hysteria &>/dev/null; then
    HYS_VER=$(hysteria version 2>/dev/null | grep "Version:" | awk '{print $2}' || echo "v2")
    echo -e "${C_GREEN}✔ Ядро Hysteria 2 обновлено (${HYS_VER}).${C_RESET}"
fi

# 2. Stop old legacy service if still running
systemctl stop blitz.service 2>/dev/null || true
systemctl disable blitz.service 2>/dev/null || true

# 3. Update InnerBlitz code
echo -e "${C_YELLOW}[2/5] Синхронизация файлов панели InnerBlitz...${C_RESET}"
mkdir -p "${INSTALL_DIR}"

if [ -d "${INSTALL_DIR}/.git" ]; then
    cd "${INSTALL_DIR}"
    git remote set-url origin "${REPO_URL}" 2>/dev/null || true
    git fetch origin main --quiet
    git reset --hard origin/main --quiet
else
    cd /tmp
    rm -rf innerblitz_tmp
    git clone --depth 1 "${REPO_URL}" innerblitz_tmp --quiet
    cp -r innerblitz_tmp/app "${INSTALL_DIR}/"
    cp -r innerblitz_tmp/systemd "${INSTALL_DIR}/"
    cp innerblitz_tmp/cli.py innerblitz_tmp/menu.sh innerblitz_tmp/upgrade.sh innerblitz_tmp/uninstall.sh innerblitz_tmp/requirements.txt "${INSTALL_DIR}/"
    rm -rf innerblitz_tmp
fi

chmod +x "${INSTALL_DIR}/menu.sh" "${INSTALL_DIR}/cli.py" "${INSTALL_DIR}/upgrade.sh" "${INSTALL_DIR}/uninstall.sh" 2>/dev/null || true

# 4. Update Python dependencies in venv
echo -e "${C_YELLOW}[3/5] Обновление модулей Python в виртуальном окружении...${C_RESET}"
if [ ! -d "${INSTALL_DIR}/venv" ]; then
    python3 -m venv "${INSTALL_DIR}/venv"
fi
"${INSTALL_DIR}/venv/bin/pip" install --upgrade pip --quiet
"${INSTALL_DIR}/venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt" --upgrade --quiet
echo -e "${C_GREEN}✔ Зависимости Python актуализированы.${C_RESET}"

# 5. Check and migrate stealth mode (port, secret directory, decoy)
echo -e "${C_YELLOW}[4/5] Проверка защиты от РКН и параметров доступа...${C_RESET}"
detect_ip

PYTHON_BIN="${INSTALL_DIR}/venv/bin/python3"
PANEL_INFO=$($PYTHON_BIN - << 'EOF'
import asyncio
from app.database.connection import init_db
from app.database import crud

async def check():
    await init_db()
    port = await crud.get_setting("panel_port", "")
    path = await crud.get_setting("panel_secret_path", "")
    decoy = await crud.get_setting("decoy_enabled", "1")
    theme = await crud.get_setting("decoy_theme", "nginx")
    user = await crud.get_setting("admin_username", "admin")
    ssl_m = await crud.get_setting("panel_ssl_mode", "http")
    print(f"{port}|{path}|{decoy}|{theme}|{user}|{ssl_m}")

asyncio.run(check())
EOF
)

IFS='|' read -r CUR_PORT CUR_PATH CUR_DECOY CUR_THEME CUR_USER CUR_SSL <<< "$PANEL_INFO"
CUR_PORT=${CUR_PORT:-"8080"}
CUR_PATH=${CUR_PATH:-"panel"}
CUR_SSL=${CUR_SSL:-"http"}

# Check if using legacy insecure port 8080 or default path
if [ "$CUR_PORT" == "8080" ] || [ "$CUR_PATH" == "panel" ] || [ -z "$CUR_PATH" ]; then
    echo -e "\n${C_RED}${C_BOLD}[!] ВНИМАНИЕ: Панель использует стандартный порт 8080 или путь /panel.${C_RESET}"
    echo -e "${C_YELLOW}    Такая панель легко обнаруживается автоматическими сканерами РКН и провайдеров!${C_RESET}"
    
    DO_STEALTH="y"
    if [ -t 0 ]; then
        read -rp "    Перевести панель в Стелс-режим (случайный порт 20000–60000 + секретная директория + Anti-RKN Decoy)? [Y/n]: " ask_stealth
        ask_stealth=${ask_stealth:-Y}
        if [[ ! "$ask_stealth" =~ ^[Yy]$ ]]; then
            DO_STEALTH="n"
        fi
    fi

    if [ "$DO_STEALTH" == "y" ]; then
        RANDOM_PORT=$(( 20000 + RANDOM % 40000 ))
        RANDOM_LEN=$(( 12 + RANDOM % 5 ))
        RANDOM_PATH=$(tr -dc 'a-z0-9' < /dev/urandom 2>/dev/null | head -c "$RANDOM_LEN" || openssl rand -hex 8 | cut -c 1-"$RANDOM_LEN")
        $PYTHON_BIN -c "import asyncio; from app.database.connection import init_db; from app.database import crud; asyncio.run(init_db()); asyncio.run(crud.set_settings({'panel_port': '$RANDOM_PORT', 'panel_secret_path': '$RANDOM_PATH', 'decoy_enabled': '1', 'decoy_theme': 'nginx'}))"
        CUR_PORT=$RANDOM_PORT
        CUR_PATH=$RANDOM_PATH
        CUR_DECOY="1"
        echo -e "${C_GREEN}✔ Стелс-режим успешно активирован! (Порт: ${CUR_PORT}, Путь: /${CUR_PATH})${C_RESET}"
    fi
else
    # Ensure decoy_theme is set to nginx for existing setups if empty
    $PYTHON_BIN -c "import asyncio; from app.database.connection import init_db; from app.database import crud; asyncio.run(init_db()); t = asyncio.run(crud.get_setting('decoy_theme', '')); asyncio.run(crud.set_setting('decoy_theme', 'nginx')) if not t else None"
fi

# 6. Service setup and shortcuts
echo -e "${C_YELLOW}[5/5] Перезапуск системных служб...${C_RESET}"
cp "${INSTALL_DIR}/systemd/innerblitz.service" /etc/systemd/system/innerblitz.service
systemctl daemon-reload
systemctl enable hysteria-server.service innerblitz.service --quiet
systemctl restart hysteria-server.service || true
systemctl restart innerblitz.service || true

# Shortcuts
ln -sf "${INSTALL_DIR}/menu.sh" /usr/local/bin/blitz
ln -sf "${INSTALL_DIR}/menu.sh" /usr/local/bin/inb
ln -sf "${INSTALL_DIR}/menu.sh" /usr/local/bin/hys2
chmod +x /usr/local/bin/blitz /usr/local/bin/inb /usr/local/bin/hys2

# Daily certificate renewal cron
mkdir -p /etc/cron.daily
cat << 'EOF' > /etc/cron.daily/innerblitz-cert
#!/bin/bash
/etc/hysteria/venv/bin/python3 /etc/hysteria/cli.py renew-panel-cert --check-only >/dev/null 2>&1
EOF
chmod +x /etc/cron.daily/innerblitz-cert 2>/dev/null || true

PANEL_PROTO="http"
if [ "$CUR_SSL" == "self_signed_ip" ] || [ "$CUR_SSL" == "domain" ] || [ "$CUR_SSL" == "https" ]; then
    PANEL_PROTO="https"
fi

echo ""
echo -e "${C_GREEN}${C_BOLD}================================================================${C_RESET}"
echo -e "${C_GREEN}${C_BOLD}        🎉 InnerBlitz успешно обновлен до версии 2.0! 🎉        ${C_RESET}"
echo -e "${C_GREEN}${C_BOLD}================================================================${C_RESET}"
echo ""
echo -e " ${C_BOLD}🌐 Секретная ссылка на панель:${C_RESET} ${C_CYAN}${C_BOLD}${PANEL_PROTO}://${SERVER_IP}:${CUR_PORT}/${CUR_PATH}${C_RESET}"
echo -e " ${C_BOLD}🔒 SSL режим веб-панели:${C_RESET}       ${C_GREEN}${CUR_SSL} (${PANEL_PROTO^^})${C_RESET}"
echo -e " ${C_BOLD}👤 Логин администратора:${C_RESET}       ${C_WHITE}${CUR_USER}${C_RESET}"
echo ""
echo -e " ${C_BOLD}🛡️ Маскировка от РКН/сканеров:${C_RESET} ${C_GREEN}АКТИВНА (Decoy Nginx/Cloud Node)${C_RESET}"
echo -e "   ${C_GRAY}(Корень ${PANEL_PROTO}://${SERVER_IP}:${CUR_PORT}/ и сторонние запросы маскируются под Nginx)${C_RESET}"
echo ""
echo -e " ${C_BOLD}Команда управления в терминале:${C_RESET} ${C_PURPLE}${C_BOLD}blitz${C_RESET} (или ${C_CYAN}inb${C_RESET}, ${C_CYAN}hys2${C_RESET})"
echo -e "${C_GREEN}${C_BOLD}================================================================${C_RESET}\n"