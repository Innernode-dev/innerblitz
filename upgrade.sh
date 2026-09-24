#!/usr/bin/env bash

# InnerBlitz Upgrade Script
# Upgrades InnerBlitz panel and Hysteria 2 to the latest releases

set -e

INSTALL_DIR="/etc/hysteria"

# Colors
C_RESET='\033[0m'
C_GREEN='\033[0;32m'
C_CYAN='\033[0;36m'
C_YELLOW='\033[0;33m'
C_RED='\033[0;31m'

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${C_RED}Ошибка: Запустите скрипт с правами root!${C_RESET}"
    exit 1
fi

echo -e "\n${C_CYAN}=== Обновление InnerBlitz и Hysteria 2 ===${C_RESET}\n"

# 1. Update Hysteria 2 core
echo -e "${C_YELLOW}[1/3] Обновление ядра Hysteria 2...${C_RESET}"
bash <(curl -fsSL https://get.hy2.sh/)
systemctl restart hysteria-server.service || true
echo -e "${C_GREEN}✔ Ядро Hysteria 2 обновлено.${C_RESET}"

# 2. Update InnerBlitz code
echo -e "${C_YELLOW}[2/3] Обновление панели InnerBlitz...${C_RESET}"
if [ -d "${INSTALL_DIR}/.git" ]; then
    cd "${INSTALL_DIR}"
    git pull origin main
else
    echo -e "${C_YELLOW}Клонирование свежей версии в ${INSTALL_DIR}...${C_RESET}"
    cd /tmp
    rm -rf innerblitz_tmp
    git clone https://github.com/Innernode-dev/innerblitz.git innerblitz_tmp
    cp -r innerblitz_tmp/app "${INSTALL_DIR}/"
    cp -r innerblitz_tmp/cli.py innerblitz_tmp/menu.sh innerblitz_tmp/requirements.txt "${INSTALL_DIR}/"
    rm -rf innerblitz_tmp
fi

# 3. Update Python packages
echo -e "${C_YELLOW}[3/3] Проверка зависимостей Python...${C_RESET}"
"${INSTALL_DIR}/venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt" --upgrade --quiet
systemctl restart innerblitz.service || true

echo -e "\n${C_GREEN}✔ InnerBlitz успешно обновлен до последней версии!${C_RESET}\n"