#!/usr/bin/env bash

# InnerBlitz TUI Management Menu
# https://github.com/Innernode-dev/innerblitz

INSTALL_DIR="/etc/hysteria"
PYTHON_BIN="${INSTALL_DIR}/venv/bin/python3"
CLI_CMD="${PYTHON_BIN} ${INSTALL_DIR}/cli.py"

# Colors
C_RESET='\033[0m'
C_BOLD='\033[1m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_BLUE='\033[0;34m'
C_PURPLE='\033[0;35m'
C_CYAN='\033[0;36m'
C_WHITE='\033[1;37m'
C_GRAY='\033[0;90m'

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${C_RED}Ошибка: Этот скрипт должен быть запущен от имени root!${C_RESET}"
        exit 1
    fi
}

get_status_line() {
    local hys_active="${C_RED}Неактивна${C_RESET}"
    local panel_active="${C_RED}Неактивна${C_RESET}"

    if systemctl is-active --quiet hysteria-server.service; then
        hys_active="${C_GREEN}Активна (OK)${C_RESET}"
    fi

    if systemctl is-active --quiet innerblitz.service; then
        panel_active="${C_GREEN}Активна (OK)${C_RESET}"
    fi

    local ip_addr=$(curl -s4 -m 2 icanhazip.com || echo "127.0.0.1")

    echo -e "${C_GRAY}┌──────────────────────────────────────────────────────────────┐${C_RESET}"
    echo -e "${C_GRAY}│${C_RESET} ${C_BOLD}Hysteria 2:${C_RESET} ${hys_active}    ${C_BOLD}Веб-панель:${C_RESET} ${panel_active} ${C_GRAY}│${C_RESET}"
    echo -e "${C_GRAY}│${C_RESET} ${C_BOLD}IP Сервера:${C_RESET} ${C_CYAN}${ip_addr}${C_RESET}                                   ${C_GRAY}│${C_RESET}"
    echo -e "${C_GRAY}└──────────────────────────────────────────────────────────────┘${C_RESET}"
}

print_header() {
    clear
    echo -e "${C_PURPLE}${C_BOLD}"
    cat << "EOF"
  ___                            ____  _ _ _       
 |_ _|_ __  _ __   ___ _ __     | __ )| (_) |_ ____
  | || '_ \| '_ \ / _ \ '__|____|  _ \| | | __|_  /
  | || | | | | | |  __/ | |_____| |_) | | | |_ / / 
 |___|_| |_|_| |_|\___|_|       |____/|_|_|\__/___|
EOF
    echo -e "${C_RESET}${C_GRAY}    Next-Gen Management Panel for Hysteria 2${C_RESET}\n"
    get_status_line
    echo ""
}

manage_users_menu() {
    while true; do
        print_header
        echo -e "${C_CYAN}${C_BOLD}=== Управление пользователями ===${C_RESET}\n"
        echo -e " ${C_GREEN}[1]${C_RESET} Добавить нового пользователя"
        echo -e " ${C_GREEN}[2]${C_RESET} Список всех пользователей"
        echo -e " ${C_GREEN}[3]${C_RESET} Показать данные подключения (URI и портал)"
        echo -e " ${C_GREEN}[4]${C_RESET} Сбросить использованный трафик"
        echo -e " ${C_RED}[5]${C_RESET} Удалить пользователя"
        echo -e "\n ${C_YELLOW}[0]${C_RESET} Вернуться в главное меню\n"
        read -rp "Выберите пункт [0-5]: " uopt

        case "$uopt" in
            1)
                echo ""
                read -rp "Введите имя пользователя: " uname
                read -rp "Пароль (Enter для автогенерации): " upass
                read -rp "Лимит трафика в GB (0 = безлимит) [30]: " utraffic
                utraffic=${utraffic:-30}
                read -rp "Срок действия в днях (0 = бессрочно) [30]: " udays
                udays=${udays:-30}
                read -rp "Лимит одновременных IP (0 = без лимита) [0]: " umaxips
                umaxips=${umaxips:-0}
                
                cmd_args=("-u" "$uname" "-t" "$utraffic" "-d" "$udays" "--max-ips" "$umaxips")
                if [ -n "$upass" ]; then cmd_args+=("-p" "$upass"); fi
                
                $CLI_CMD add-user "${cmd_args[@]}"
                read -rp "Нажмите Enter для продолжения..."
                ;;
            2)
                echo ""
                $CLI_CMD list-users
                echo ""
                read -rp "Нажмите Enter для продолжения..."
                ;;
            3)
                echo ""
                read -rp "Введите имя пользователя: " uname
                $CLI_CMD show-user "$uname"
                echo ""
                read -rp "Нажмите Enter для продолжения..."
                ;;
            4)
                echo ""
                read -rp "Введите имя пользователя для сброса трафика: " uname
                $CLI_CMD reset-user "$uname"
                read -rp "Нажмите Enter для продолжения..."
                ;;
            5)
                echo ""
                read -rp "Введите имя пользователя для удаления: " uname
                read -rp "Вы уверены? (y/N): " confirm
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    $CLI_CMD delete-user "$uname"
                fi
                read -rp "Нажмите Enter для продолжения..."
                ;;
            0)
                return
                ;;
            *)
                echo -e "${C_RED}Неверный ввод!${C_RESET}"
                sleep 1
                ;;
        esac
    done
}

issue_ip_cert() {
    echo ""
    echo -e "${C_CYAN}Выпуск самоподписанного TLS-сертификата с IP SAN и расчетом pinSHA256...${C_RESET}"
    $CLI_CMD gen-ip-cert
    read -rp "Нажмите Enter для продолжения..."
}

presets_menu() {
    while true; do
        print_header
        echo -e "${C_CYAN}${C_BOLD}=== Пресеты конфигурации в 1 клик ===${C_RESET}\n"
        echo -e " ${C_GREEN}[1]${C_RESET} ${C_BOLD}🛡️ Анти-DPI${C_RESET} (Salamander Obfs + Port Hopping + Маскировка Bing)"
        echo -e " ${C_GREEN}[2]${C_RESET} ${C_BOLD}⚡ Максимальная скорость${C_RESET} (1 Гбит/с, BBR, без hopping)"
        echo -e " ${C_GREEN}[3]${C_RESET} ${C_BOLD}🎮 Игровой${C_RESET} (Минимальный пинг и агрессивный keepalive)"
        echo -e "\n ${C_YELLOW}[0]${C_RESET} Назад\n"
        read -rp "Выберите пресет [0-3]: " popt

        case "$popt" in
            1)
                $PYTHON_BIN -c "import asyncio; from app.api.settings_routes import apply_preset; asyncio.run(apply_preset({'preset': 'anti-dpi'}))"
                echo -e "${C_GREEN}✔ Пресет Анти-DPI успешно применен!${C_RESET}"
                read -rp "Нажмите Enter для продолжения..."
                return
                ;;
            2)
                $PYTHON_BIN -c "import asyncio; from app.api.settings_routes import apply_preset; asyncio.run(apply_preset({'preset': 'speed'}))"
                echo -e "${C_GREEN}✔ Пресет Скорость успешно применен!${C_RESET}"
                read -rp "Нажмите Enter для продолжения..."
                return
                ;;
            3)
                $PYTHON_BIN -c "import asyncio; from app.api.settings_routes import apply_preset; asyncio.run(apply_preset({'preset': 'gaming'}))"
                echo -e "${C_GREEN}✔ Пресет Игровой успешно применен!${C_RESET}"
                read -rp "Нажмите Enter для продолжения..."
                return
                ;;
            0)
                return
                ;;
        esac
    done
}

manage_webpanel_menu() {
    while true; do
        print_header
        echo -e "${C_CYAN}${C_BOLD}=== Управление веб-панелью ===${C_RESET}\n"
        echo -e " ${C_GREEN}[1]${C_RESET} Сменить пароль администратора"
        echo -e " ${C_GREEN}[2]${C_RESET} Показать секретную ссылку для входа"
        echo -e " ${C_GREEN}[3]${C_RESET} Сменить порт панели и секретный URL-путь"
        echo -e " ${C_GREEN}[4]${C_RESET} Перезапустить службу панели"
        echo -e "\n ${C_YELLOW}[0]${C_RESET} Назад\n"
        read -rp "Выберите пункт [0-4]: " wopt

        case "$wopt" in
            1)
                echo ""
                read -rsp "Введите новый пароль администратора: " newpwd
                echo ""
                $CLI_CMD set-admin-password "$newpwd"
                read -rp "Нажмите Enter для продолжения..."
                ;;
            2)
                echo ""
                $CLI_CMD show-panel-url
                echo ""
                read -rp "Нажмите Enter для продолжения..."
                ;;
            3)
                echo ""
                read -rp "Новый порт панели (Enter чтобы оставить): " nport
                read -rp "Новый секретный URL-путь (Enter чтобы оставить): " npath
                cmd_p=()
                if [ -n "$nport" ]; then cmd_p+=("--port" "$nport"); fi
                if [ -n "$npath" ]; then cmd_p+=("--path" "$npath"); fi
                if [ ${#cmd_p[@]} -gt 0 ]; then
                    $CLI_CMD set-panel-access "${cmd_p[@]}"
                    systemctl restart innerblitz.service || true
                fi
                read -rp "Нажмите Enter для продолжения..."
                ;;
            4)
                systemctl restart innerblitz.service
                echo -e "${C_GREEN}✔ Служба innerblitz.service перезапущена.${C_RESET}"
                read -rp "Нажмите Enter для продолжения..."
                ;;
            0)
                return
                ;;
        esac
    done
}

update_hysteria_core() {
    echo ""
    echo -e "${C_CYAN}Обновление ядра Hysteria 2 до последней версии...${C_RESET}"
    bash <(curl -fsSL https://get.hy2.sh/)
    systemctl restart hysteria-server.service
    echo -e "${C_GREEN}✔ Ядро Hysteria 2 успешно обновлено и перезапущено!${C_RESET}"
    read -rp "Нажмите Enter для продолжения..."
}

update_innerblitz() {
    echo ""
    echo -e "${C_CYAN}Обновление InnerBlitz из официального репозитория...${C_RESET}"
    if [ -f "${INSTALL_DIR}/upgrade.sh" ]; then
        bash "${INSTALL_DIR}/upgrade.sh"
    else
        bash <(curl -fsSL https://raw.githubusercontent.com/Innernode-dev/innerblitz/main/upgrade.sh)
    fi
    read -rp "Нажмите Enter для продолжения..."
}

view_logs() {
    echo -e "${C_CYAN}Последние 50 строк логов Hysteria 2 (нажмите q для выхода):${C_RESET}"
    journalctl -u hysteria-server.service -n 50 -e
}

main_menu() {
    check_root

    while true; do
        print_header
        echo -e "${C_BOLD}Главное меню:${C_RESET}\n"
        echo -e " ${C_GREEN}[1]${C_RESET} 👥 Управление пользователями"
        echo -e " ${C_GREEN}[2]${C_RESET} 🔒 Выпустить сертификат на IP (SAN + pinSHA256)"
        echo -e " ${C_GREEN}[3]${C_RESET} 🛡️ Пресеты настроек ядра (Анти-DPI / Скорость / Игры)"
        echo -e " ${C_GREEN}[4]${C_RESET} 🖥️ Управление веб-панелью и паролем"
        echo -e " ${C_GREEN}[5]${C_RESET} 🔄 Перезапустить Hysteria 2"
        echo -e " ${C_GREEN}[6]${C_RESET} 📜 Просмотр системных логов"
        echo -e " ${C_CYAN}[7]${C_RESET} 🚀 Обновить ядро Hysteria 2"
        echo -e " ${C_CYAN}[8]${C_RESET} ⚡ Обновить InnerBlitz"
        echo -e "\n ${C_RED}[0]${C_RESET} Выход из меню\n"

        read -rp "Выберите опцию [0-8]: " opt

        case "$opt" in
            1) manage_users_menu ;;
            2) issue_ip_cert ;;
            3) presets_menu ;;
            4) manage_webpanel_menu ;;
            5) 
                $CLI_CMD restart
                read -rp "Нажмите Enter для продолжения..."
                ;;
            6) view_logs ;;
            7) update_hysteria_core ;;
            8) update_innerblitz ;;
            0) 
                echo -e "\n${C_PURPLE}Спасибо за использование InnerBlitz!${C_RESET}\n"
                exit 0 
                ;;
            *)
                echo -e "${C_RED}Неверный ввод!${C_RESET}"
                sleep 1
                ;;
        esac
    done
}

main_menu