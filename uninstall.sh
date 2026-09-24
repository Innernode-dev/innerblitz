#!/usr/bin/env bash

# ==============================================================================
#  ⚡ InnerBlitz Clean Uninstaller — Hysteria 2 Management Suite
#  Repository: https://github.com/Innernode-dev/innerblitz
# ==============================================================================

set -e

C_RESET='\033[0m'
C_BOLD='\033[1m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_CYAN='\033[0;36m'

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${C_RED}Ошибка: Запустите скрипт с правами root!${C_RESET}"
    exit 1
fi

echo -e "\n${C_RED}${C_BOLD}================================================================${C_RESET}"
echo -e "${C_RED}${C_BOLD}        ⚠️  Полное удаление InnerBlitz и Hysteria 2  ⚠️        ${C_RESET}"
echo -e "${C_RED}${C_BOLD}================================================================${C_RESET}"
echo -e "${C_YELLOW}Будут остановлены и удалены службы, база данных и файлы конфигурации.${C_RESET}\n"

read -rp "Вы уверены, что хотите полностью удалить панель? (y/N): " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo -e "${C_GREEN}Удаление отменено.${C_RESET}"
    exit 0
fi

echo -e "\n${C_YELLOW}[1/6] Остановка и отключение системных служб...${C_RESET}"
systemctl stop innerblitz.service hysteria-server.service 2>/dev/null || true
systemctl disable innerblitz.service hysteria-server.service 2>/dev/null || true

echo -e "${C_YELLOW}[2/6] Удаление юнитов systemd...${C_RESET}"
rm -f /etc/systemd/system/innerblitz.service
rm -f /etc/systemd/system/hysteria-server.service
systemctl daemon-reload

echo -e "${C_YELLOW}[3/6] Очистка правил iptables для Port Hopping...${C_RESET}"
iptables -t nat -D PREROUTING -p udp -j HYSTERIA_HOPPING 2>/dev/null || true
iptables -t nat -F HYSTERIA_HOPPING 2>/dev/null || true
iptables -t nat -X HYSTERIA_HOPPING 2>/dev/null || true
ip6tables -t nat -D PREROUTING -p udp -j HYSTERIA_HOPPING 2>/dev/null || true
ip6tables -t nat -F HYSTERIA_HOPPING 2>/dev/null || true
ip6tables -t nat -X HYSTERIA_HOPPING 2>/dev/null || true

echo -e "${C_YELLOW}[4/6] Удаление ярлыков команд blitz, inb, hys2...${C_RESET}"
rm -f /usr/local/bin/blitz /usr/local/bin/inb /usr/local/bin/hys2
rm -f /etc/sysctl.d/99-innerblitz.conf

echo -e "${C_YELLOW}[5/6] Резервная копия базы данных перед удалением...${C_RESET}"
read -rp "Сохранить резервную копию базы данных пользователей SQLite? (Y/n): " keep_db
keep_db=${keep_db:-Y}
if [[ "$keep_db" =~ ^[Yy]$ ]] && [ -f "/etc/hysteria/innerblitz.db" ]; then
    mkdir -p /root/innerblitz_backup
    cp /etc/hysteria/innerblitz.db /root/innerblitz_backup/
    if [ -f "/etc/hysteria/server.crt" ]; then
        cp /etc/hysteria/server.crt /etc/hysteria/server.key /root/innerblitz_backup/ 2>/dev/null || true
    fi
    echo -e "${C_GREEN}✔ Резервная копия сохранена в /root/innerblitz_backup/${C_RESET}"
fi

read -rp "Удалить сам бинарник ядра Hysteria 2 (/usr/local/bin/hysteria)? (y/N): " del_hy_bin
if [[ "$del_hy_bin" =~ ^[Yy]$ ]]; then
    rm -f /usr/local/bin/hysteria
    echo -e "${C_GREEN}✔ Бинарник Hysteria 2 удален.${C_RESET}"
fi

echo -e "${C_YELLOW}[6/6] Очистка каталога /etc/hysteria...${C_RESET}"
rm -rf /etc/hysteria

echo -e "\n${C_GREEN}${C_BOLD}================================================================${C_RESET}"
echo -e "${C_GREEN}${C_BOLD}  ✔ InnerBlitz и сопутствующие службы полностью удалены.       ${C_RESET}"
echo -e "${C_GREEN}${C_BOLD}================================================================${C_RESET}\n"
