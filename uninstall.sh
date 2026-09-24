#!/usr/bin/env bash

# InnerBlitz Clean Uninstaller

set -e

C_RESET='\033[0m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${C_RED}Ошибка: Запустите скрипт с правами root!${C_RESET}"
    exit 1
fi

echo -e "${C_RED}Внимание! Вы собираетесь полностью удалить InnerBlitz и Hysteria 2.${C_RESET}"
read -rp "Вы уверены, что хотите продолжить? (y/N): " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Удаление отменено."
    exit 0
fi

echo -e "\n${C_YELLOW}Остановка и отключение служб...${C_RESET}"
systemctl stop innerblitz.service hysteria-server.service || true
systemctl disable innerblitz.service hysteria-server.service || true

rm -f /etc/systemd/system/innerblitz.service
rm -f /etc/systemd/system/hysteria-server.service
systemctl daemon-reload

echo -e "${C_YELLOW}Удаление ярлыков команд...${C_RESET}"
rm -f /usr/local/bin/blitz /usr/local/bin/inb /usr/local/bin/hys2

read -rp "Сохранить резервную копию базы данных SQLite? (Y/n): " keep_db
if [[ ! "$keep_db" =~ ^[Nn]$ ]] && [ -f "/etc/hysteria/innerblitz.db" ]; then
    mkdir -p /root/innerblitz_backup
    cp /etc/hysteria/innerblitz.db /root/innerblitz_backup/
    echo -e "${C_GREEN}База данных сохранена в /root/innerblitz_backup/innerblitz.db${C_RESET}"
fi

echo -e "${C_YELLOW}Удаление файлов /etc/hysteria...${C_RESET}"
rm -rf /etc/hysteria

echo -e "\n${C_GREEN}✔ InnerBlitz успешно удален с сервера.${C_RESET}\n"
