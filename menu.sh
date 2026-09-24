#!/usr/bin/env bash

# InnerBlitz TUI Management Menu
# Next-Gen Hysteria 2 & Anti-Censorship Management Console
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

detect_server_ip() {
    local ip=""
    for url in "https://api.ipify.org" "https://icanhazip.com" "https://ip.sb" "https://ifconfig.me" "https://checkip.amazonaws.com"; do
        ip=$(curl -s4 -m 3 "$url" 2>/dev/null | tr -d '[:space:]')
        if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            echo "$ip"
            return 0
        fi
    done
    ip=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' | tr -d '[:space:]')
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "$ip"
        return 0
    fi
    echo "127.0.0.1"
}

get_status_line() {
    local hys_active="${C_RED}Неактивна${C_RESET}"
    local panel_active="${C_RED}Неактивна${C_RESET}"

    if systemctl is-active --quiet hysteria-server.service 2>/dev/null; then
        hys_active="${C_GREEN}Активна (OK)${C_RESET}"
    fi

    if systemctl is-active --quiet innerblitz.service 2>/dev/null; then
        panel_active="${C_GREEN}Активна (OK)${C_RESET}"
    fi

    local ip_addr=$(detect_server_ip)

    echo -e "${C_GRAY}┌──────────────────────────────────────────────────────────────┐${C_RESET}"
    printf "${C_GRAY}│${C_RESET} %-12s %-20b %-12s %-20b ${C_GRAY}│${C_RESET}\n" "Hysteria 2:" "$hys_active" "Веб-панель:" "$panel_active"
    printf "${C_GRAY}│${C_RESET} %-12s ${C_CYAN}%-45s${C_RESET} ${C_GRAY}│${C_RESET}\n" "IP Сервера:" "$ip_addr"
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

# ==================== 1. УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ ====================
manage_users_menu() {
    while true; do
        print_header
        echo -e "${C_CYAN}${C_BOLD}=== 👥 Управление пользователями ===${C_RESET}\n"
        echo -e " ${C_GREEN}[1]${C_RESET} Добавить нового пользователя"
        echo -e " ${C_GREEN}[2]${C_RESET} Список всех пользователей (Трафик, Срок, Статус)"
        echo -e " ${C_GREEN}[3]${C_RESET} Показать данные подключения (URI, QR-код и Портал)"
        echo -e " ${C_GREEN}[4]${C_RESET} Сбросить использованный трафик пользователя"
        echo -e " ${C_GREEN}[5]${C_RESET} Сменить пароль пользователя"
        echo -e " ${C_GREEN}[6]${C_RESET} Продлить срок действия (добавить дней)"
        echo -e " ${C_RED}[7]${C_RESET} Удалить пользователя"
        echo -e "\n ${C_YELLOW}[0]${C_RESET} Назад в главное меню\n"
        read -rp "Выберите пункт [0-7]: " uopt

        case "$uopt" in
            1)
                echo ""
                read -rp "Имя пользователя: " uname
                if [ -z "$uname" ]; then
                    echo -e "${C_RED}Имя пользователя не может быть пустым!${C_RESET}"
                    sleep 1
                    continue
                fi
                read -rp "Пароль (Enter для случайной автогенерации 🎲): " upass
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
                read -rp "Введите имя пользователя: " uname
                read -rp "Новый пароль (Enter для случайного 🎲): " newupass
                if [ -z "$newupass" ]; then
                    newupass=$(openssl rand -base64 10 | tr -dc 'a-zA-Z0-9' | head -c 12)
                    echo -e "Сгенерирован пароль: ${C_YELLOW}${newupass}${C_RESET}"
                fi
                $PYTHON_BIN -c "import asyncio; from app.database.connection import init_db; from app.database import crud; from app.database.models import UserUpdate; asyncio.run(init_db()); asyncio.run(crud.update_user('$uname', UserUpdate(password='$newupass')))"
                echo -e "${C_GREEN}✔ Пароль пользователя $uname успешно обновлен!${C_RESET}"
                read -rp "Нажмите Enter для продолжения..."
                ;;
            6)
                echo ""
                read -rp "Введите имя пользователя: " uname
                read -rp "Количество добавляемых дней: " add_days
                if [[ "$add_days" =~ ^[0-9]+$ ]]; then
                    $PYTHON_BIN -c "import asyncio; from app.database.connection import init_db; from app.database import crud; from app.database.models import UserUpdate; asyncio.run(init_db()); u = asyncio.run(crud.get_user_by_username('$uname')); asyncio.run(crud.update_user('$uname', UserUpdate(expiration_days=u['expiration_days'] + int($add_days)))) if u else print('User not found')"
                    echo -e "${C_GREEN}✔ Срок действия пользователя $uname продлен на $add_days дней!${C_RESET}"
                fi
                read -rp "Нажмите Enter для продолжения..."
                ;;
            7)
                echo ""
                read -rp "Введите имя пользователя для удаления: " uname
                read -rp "Вы действительно хотите удалить $uname? (y/N): " confirm
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    $CLI_CMD delete-user "$uname"
                fi
                read -rp "Нажмите Enter для продолжения..."
                ;;
            0) return ;;
            *)
                echo -e "${C_RED}Неверный ввод!${C_RESET}"
                sleep 1
                ;;
        esac
    done
}

# ==================== 2. СЕРТИФИКАТЫ И ДОМЕНЫ ====================
manage_certs_menu() {
    while true; do
        print_header
        echo -e "${C_CYAN}${C_BOLD}=== 🔒 Сертификаты и Домены ===${C_RESET}\n"
        echo -e " ${C_GREEN}[1]${C_RESET} Выпустить / Обновить сертификат на IP (ECDSA SAN + pinSHA256)"
        echo -e " ${C_GREEN}[2]${C_RESET} Настроить доменное имя и Let's Encrypt (ACME)"
        echo -e " ${C_GREEN}[3]${C_RESET} Показать текущий SHA256 отпечаток сертификата"
        echo -e "\n ${C_YELLOW}[0]${C_RESET} Назад\n"
        read -rp "Выберите пункт [0-3]: " copt

        case "$copt" in
            1)
                echo ""
                local cur_ip=$(detect_server_ip)
                read -rp "IP-адрес сервера [$cur_ip]: " user_ip
                user_ip=${user_ip:-$cur_ip}
                $CLI_CMD gen-ip-cert --ip "$user_ip"
                read -rp "Нажмите Enter для продолжения..."
                ;;
            2)
                echo ""
                read -rp "Введите ваш домен (должен указывать на IP сервера через DNS A-запись): " dom
                if [ -n "$dom" ]; then
                    $PYTHON_BIN -c "import asyncio; from app.database.connection import init_db; from app.database import crud; from app.core.hysteria import apply_and_save_config, restart_hysteria; asyncio.run(init_db()); asyncio.run(crud.set_settings({'server_domain': '$dom', 'tls_type': 'acme'})); asyncio.run(apply_and_save_config()); restart_hysteria()"
                    echo -e "${C_GREEN}✔ Режим Let's Encrypt (ACME) активирован для домена: $dom${C_RESET}"
                fi
                read -rp "Нажмите Enter для продолжения..."
                ;;
            3)
                echo ""
                $PYTHON_BIN -c "import asyncio; from app.database.connection import init_db; from app.database import crud; asyncio.run(init_db()); pin = asyncio.run(crud.get_setting('cert_sha256', '')); print(f'Текущий pinSHA256: {pin}')"
                echo ""
                read -rp "Нажмите Enter для продолжения..."
                ;;
            0) return ;;
            *) sleep 1 ;;
        esac
    done
}

# ==================== 3. УПРАВЛЕНИЕ ПОРТАМИ HYSTERIA 2 ====================
manage_ports_menu() {
    while true; do
        print_header
        echo -e "${C_CYAN}${C_BOLD}=== ⚡ Управление портами Hysteria 2 ===${C_RESET}\n"
        
        local l_port=$($PYTHON_BIN -c "import asyncio; from app.database.connection import init_db; from app.database import crud; asyncio.run(init_db()); print(asyncio.run(crud.get_setting('listen_port', '443')))" 2>/dev/null || echo "443")
        local h_on=$($PYTHON_BIN -c "import asyncio; from app.database.connection import init_db; from app.database import crud; asyncio.run(init_db()); print(asyncio.run(crud.get_setting('port_hopping_enabled', '1')))" 2>/dev/null || echo "1")
        local h_range=$($PYTHON_BIN -c "import asyncio; from app.database.connection import init_db; from app.database import crud; asyncio.run(init_db()); print(asyncio.run(crud.get_setting('port_hopping_range', '20000:50000')))" 2>/dev/null || echo "20000:50000")

        echo -e " Текущий UDP порт прослушивания: ${C_WHITE}${C_BOLD}${l_port}${C_RESET}"
        echo -e " Port Hopping (скачки портов):     $([ "$h_on" == "1" ] && echo -e "${C_GREEN}ВКЛЮЧЕН (${h_range})${C_RESET}" || echo -e "${C_RED}ВЫКЛЮЧЕН${C_RESET}")\n"

        echo -e " ${C_GREEN}[1]${C_RESET} Сменить основной UDP порт Hysteria 2"
        echo -e " ${C_GREEN}[2]${C_RESET} Сменить диапазон Port Hopping (например, 20000:50000)"
        echo -e " ${C_GREEN}[3]${C_RESET} Включить / Выключить Port Hopping"
        echo -e " ${C_GREEN}[4]${C_RESET} Очистить правила iptables для Port Hopping"
        echo -e " ${C_YELLOW}[5]${C_RESET} ${C_BOLD}🔄 Полный сброс портов на стандартные (Порт 443 + сброс iptables)${C_RESET}"
        echo -e "\n ${C_YELLOW}[0]${C_RESET} Назад\n"
        read -rp "Выберите пункт [0-5]: " popt

        case "$popt" in
            1)
                echo ""
                read -rp "Введите новый UDP порт [текущий: $l_port]: " new_lp
                if [ -n "$new_lp" ]; then
                    $PYTHON_BIN -c "import asyncio; from app.database.connection import init_db; from app.database import crud; from app.core.hysteria import apply_and_save_config, restart_hysteria; asyncio.run(init_db()); asyncio.run(crud.set_setting('listen_port', '$new_lp')); asyncio.run(apply_and_save_config()); restart_hysteria()"
                    echo -e "${C_GREEN}✔ Порт изменен на $new_lp и Hysteria перезапущена!${C_RESET}"
                fi
                read -rp "Нажмите Enter для продолжения..."
                ;;
            2)
                echo ""
                read -rp "Введите новый диапазон портов [текущий: $h_range]: " new_hr
                if [ -n "$new_hr" ]; then
                    $PYTHON_BIN -c "import asyncio; from app.database.connection import init_db; from app.database import crud; from app.core.hysteria import apply_and_save_config, restart_hysteria; from app.core.firewall import configure_port_hopping; asyncio.run(init_db()); asyncio.run(crud.set_setting('port_hopping_range', '$new_hr')); configure_port_hopping('$new_hr', int('$l_port'), True); asyncio.run(apply_and_save_config()); restart_hysteria()"
                    echo -e "${C_GREEN}✔ Диапазон Port Hopping обновлен на $new_hr!${C_RESET}"
                fi
                read -rp "Нажмите Enter для продолжения..."
                ;;
            3)
                local toggle_to=$([ "$h_on" == "1" ] && echo "0" || echo "1")
                $PYTHON_BIN -c "import asyncio; from app.database.connection import init_db; from app.database import crud; from app.core.hysteria import apply_and_save_config, restart_hysteria; from app.core.firewall import configure_port_hopping; asyncio.run(init_db()); asyncio.run(crud.set_setting('port_hopping_enabled', '$toggle_to')); configure_port_hopping('$h_range', int('$l_port'), bool(int('$toggle_to'))); asyncio.run(apply_and_save_config()); restart_hysteria()"
                echo -e "${C_GREEN}✔ Статус Port Hopping изменен!${C_RESET}"
                read -rp "Нажмите Enter для продолжения..."
                ;;
            4)
                echo ""
                $PYTHON_BIN -c "from app.core.firewall import flush_port_hopping; ok, msg = flush_port_hopping(); print('✔ ' + msg if ok else '✖ ' + msg)"
                read -rp "Нажмите Enter для продолжения..."
                ;;
            5)
                echo ""
                read -rp "Сбросить порт Hysteria 2 на 443 и очистить iptables? (y/N): " rconf
                if [[ "$rconf" =~ ^[Yy]$ ]]; then
                    $CLI_CMD reset-ports --port 443 --flush-hopping
                fi
                read -rp "Нажмите Enter для продолжения..."
                ;;
            0) return ;;
            *) sleep 1 ;;
        esac
    done
}

# ==================== 4. УПРАВЛЕНИЕ ВЕБ-ПАНЕЛЬЮ ====================
manage_webpanel_menu() {
    while true; do
        print_header
        echo -e "${C_CYAN}${C_BOLD}=== 🖥️ Управление веб-панелью и Стелс-защитой ===${C_RESET}\n"

        local p_port=$($PYTHON_BIN -c "import asyncio; from app.database.connection import init_db; from app.database import crud; asyncio.run(init_db()); print(asyncio.run(crud.get_setting('panel_port', '8080')))" 2>/dev/null || echo "8080")
        local p_path=$($PYTHON_BIN -c "import asyncio; from app.database.connection import init_db; from app.database import crud; asyncio.run(init_db()); print(asyncio.run(crud.get_setting('panel_secret_path', 'panel')))" 2>/dev/null || echo "panel")
        local p_decoy=$($PYTHON_BIN -c "import asyncio; from app.database.connection import init_db; from app.database import crud; asyncio.run(init_db()); print(asyncio.run(crud.get_setting('decoy_enabled', '1')))" 2>/dev/null || echo "1")
        local p_theme=$($PYTHON_BIN -c "import asyncio; from app.database.connection import init_db; from app.database import crud; asyncio.run(init_db()); print(asyncio.run(crud.get_setting('decoy_theme', 'nginx')))" 2>/dev/null || echo "nginx")
        local cur_ip=$(detect_server_ip)

        echo -e " 🌐 Секретный адрес входа: ${C_CYAN}${C_BOLD}http://${cur_ip}:${p_port}/${p_path}${C_RESET}"
        echo -e " 📁 Секретная директория: ${C_WHITE}/${p_path}${C_RESET} | Порт панели: ${C_WHITE}${p_port}${C_RESET}"
        echo -e " 🛡️ Маскировка от РКН (Decoy): $([ "$p_decoy" == "1" ] && echo -e "${C_GREEN}АКТИВНА (${p_theme})${C_RESET}" || echo -e "${C_RED}ВЫКЛЮЧЕНА${C_RESET})\n"

        echo -e " ${C_GREEN}[1]${C_RESET} 🌐 Показать секретную ссылку для входа и реквизиты"
        echo -e " ${C_GREEN}[2]${C_RESET} 👤 Сменить логин администратора"
        echo -e " ${C_GREEN}[3]${C_RESET} 🔑 Сменить пароль администратора"
        echo -e " ${C_GREEN}[4]${C_RESET} ⚙️ Сменить порт панели и секретную директорию (URL-путь) вручную"
        echo -e " ${C_GREEN}[5]${C_RESET} 🎲 ${C_BOLD}Сгенерировать случайный stealth-порт и директорию (Защита от РКН)${C_RESET}"
        echo -e " ${C_GREEN}[6]${C_RESET} 🎭 Настроить маскировку от РКН (Decoy сайт и темы Nginx/Cloud)"
        echo -e " ${C_YELLOW}[7]${C_RESET} ${C_BOLD}🔄 Сбросить настройки панели (Порт 8080/рандом, Путь /panel, Сброс 2FA)${C_RESET}"
        echo -e " ${C_RED}[8]${C_RESET} 🚨 Экстренно отключить 2FA (TOTP + Telegram подтверждение)"
        echo -e " ${C_GREEN}[9]${C_RESET} 🔄 Перезапустить службу веб-панели"
        echo -e " ${C_GREEN}[10]${C_RESET} 📜 Просмотреть логи веб-панели"
        echo -e "\n ${C_YELLOW}[0]${C_RESET} Назад в главное меню\n"
        read -rp "Выберите пункт [0-10]: " wopt

        case "$wopt" in
            1)
                echo ""
                $CLI_CMD show-panel-url
                read -rp "Нажмите Enter для продолжения..."
                ;;
            2)
                echo ""
                read -rp "Введите новый логин администратора: " new_admin_user
                if [ -n "$new_admin_user" ]; then
                    $CLI_CMD set-admin-user "$new_admin_user"
                fi
                read -rp "Нажмите Enter для продолжения..."
                ;;
            3)
                echo ""
                read -rsp "Введите новый пароль администратора: " newpwd
                echo ""
                if [ -n "$newpwd" ]; then
                    $CLI_CMD set-admin-password "$newpwd"
                fi
                read -rp "Нажмите Enter для продолжения..."
                ;;
            4)
                echo ""
                read -rp "Новый порт панели (Enter чтобы оставить прежний $p_port): " nport
                read -rp "Новая секретная директория входа (например: node-xyz) (Enter чтобы оставить): " npath
                cmd_p=()
                if [ -n "$nport" ]; then cmd_p+=("--port" "$nport"); fi
                if [ -n "$npath" ]; then cmd_p+=("--path" "$npath"); fi
                if [ ${#cmd_p[@]} -gt 0 ]; then
                    $CLI_CMD set-panel-access "${cmd_p[@]}"
                fi
                read -rp "Нажмите Enter для продолжения..."
                ;;
            5)
                echo ""
                echo -e "${C_CYAN}Генерация случайного stealth-порта (20000–60000) и директории (/node-XXXX)...${C_RESET}"
                $CLI_CMD reset-panel-access --random
                read -rp "Нажмите Enter для продолжения..."
                ;;
            6)
                echo ""
                echo -e "${C_CYAN}${C_BOLD}=== 🎭 Настройка сайта-приманки (Decoy Anti-RKN) ===${C_RESET}"
                echo -e " 1) Переключить статус (Включить / Выключить)"
                echo -e " 2) Выбрать тему: Nginx (Ubuntu Default — Рекомендуется)"
                echo -e " 3) Выбрать тему: InnerNode Cloud Telemetry Daemon"
                echo -e " 4) Выбрать тему: Edge REST API Docs"
                echo -e " 5) Выбрать тему: Черная дыра (Имитация закрытого порта 404)"
                read -rp "Выберите пункт [1-5]: " dopt
                case "$dopt" in
                    1)
                        local dec_target=$([ "$p_decoy" == "1" ] && echo "--disable" || echo "--enable")
                        $CLI_CMD toggle-decoy $dec_target
                        ;;
                    2) $CLI_CMD toggle-decoy --enable --theme "nginx" ;;
                    3) $CLI_CMD toggle-decoy --enable --theme "innernode" ;;
                    4) $CLI_CMD toggle-decoy --enable --theme "docs" ;;
                    5) $CLI_CMD toggle-decoy --enable --theme "404" ;;
                esac
                read -rp "Нажмите Enter для продолжения..."
                ;;
            7)
                echo ""
                echo -e "${C_YELLOW}${C_BOLD}=== Мастер сброса настроек доступа к панели ===${C_RESET}"
                echo -e " 1) Сбросить на стандартный порт 8080 и путь /panel"
                echo -e " 2) Сгенерировать новый случайный stealth-порт и путь"
                read -rp "Выберите режим [1/2]: " rmode
                
                read -rp "Сбросить двухфакторную аутентификацию 2FA (TOTP/Telegram)? (y/N): " r2fa
                r2fa_flag=""
                if [[ "$r2fa" =~ ^[Yy]$ ]]; then r2fa_flag="--reset-2fa"; fi

                read -rp "Задать новый пароль админа (Enter чтобы не менять): " rpass
                rpass_flag=""
                if [ -n "$rpass" ]; then rpass_flag="--password $rpass"; fi

                if [ "$rmode" == "2" ]; then
                    $CLI_CMD reset-panel-access --random $r2fa_flag $rpass_flag
                else
                    $CLI_CMD reset-panel-access --port 8080 --path panel $r2fa_flag $rpass_flag
                fi
                read -rp "Нажмите Enter для продолжения..."
                ;;
            8)
                echo ""
                read -rp "Действительно отключить 2FA для входа? (y/N): " c2fa
                if [[ "$c2fa" =~ ^[Yy]$ ]]; then
                    $CLI_CMD disable-2fa
                fi
                read -rp "Нажмите Enter для продолжения..."
                ;;
            9)
                systemctl restart innerblitz.service
                echo -e "${C_GREEN}✔ Служба innerblitz.service успешно перезапущена.${C_RESET}"
                read -rp "Нажмите Enter для продолжения..."
                ;;
            10)
                echo -e "${C_CYAN}Последние 50 строк логов панели (нажмите q для выхода):${C_RESET}"
                journalctl -u innerblitz.service -n 50 -e
                ;;
            0) return ;;
            *) sleep 1 ;;
        esac
    done
}

# ==================== 5. ТОНКИЕ НАСТРОЙКИ ЯДРА И ПРЕСЕТЫ ====================
presets_menu() {
    while true; do
        print_header
        echo -e "${C_CYAN}${C_BOLD}=== 🛡️ Тонкие настройки ядра и Пресеты ===${C_RESET}\n"
        echo -e " ${C_GREEN}[1]${C_RESET} ${C_BOLD}🛡️ Анти-DPI${C_RESET} (Salamander Obfs + Port Hopping + Маскировка Bing)"
        echo -e " ${C_GREEN}[2]${C_RESET} ${C_BOLD}⚡ Максимальная скорость${C_RESET} (1 Гбит/с, BBR, без hopping)"
        echo -e " ${C_GREEN}[3]${C_RESET} ${C_BOLD}🎮 Игровой${C_RESET} (Минимальный пинг и агрессивный keepalive)"
        echo -e " ${C_GREEN}[4]${C_RESET} Сменить пароль Salamander Obfs"
        echo -e " ${C_GREEN}[5]${C_RESET} Включить / Выключить Protocol Sniffing (распознавание доменов)"
        echo -e " ${C_GREEN}[6]${C_RESET} Настроить Cloudflare WARP SOCKS5 роутинг (OpenAI/Netflix)"
        echo -e "\n ${C_YELLOW}[0]${C_RESET} Назад\n"
        read -rp "Выберите пункт [0-6]: " popt

        case "$popt" in
            1)
                $PYTHON_BIN -c "import asyncio; from app.api.settings_routes import apply_preset; asyncio.run(apply_preset({'preset': 'anti-dpi'}))"
                echo -e "${C_GREEN}✔ Пресет «Анти-DPI» успешно применен!${C_RESET}"
                read -rp "Нажмите Enter для продолжения..."
                ;;
            2)
                $PYTHON_BIN -c "import asyncio; from app.api.settings_routes import apply_preset; asyncio.run(apply_preset({'preset': 'speed'}))"
                echo -e "${C_GREEN}✔ Пресет «Скорость» успешно применен!${C_RESET}"
                read -rp "Нажмите Enter для продолжения..."
                ;;
            3)
                $PYTHON_BIN -c "import asyncio; from app.api.settings_routes import apply_preset; asyncio.run(apply_preset({'preset': 'gaming'}))"
                echo -e "${C_GREEN}✔ Пресет «Игровой» успешно применен!${C_RESET}"
                read -rp "Нажмите Enter для продолжения..."
                ;;
            4)
                echo ""
                read -rp "Новый пароль Salamander Obfs (Enter для случайного 🎲): " nobfs
                if [ -z "$nobfs" ]; then
                    nobfs=$(openssl rand -hex 12)
                fi
                $PYTHON_BIN -c "import asyncio; from app.database.connection import init_db; from app.database import crud; from app.core.hysteria import apply_and_save_config, restart_hysteria; asyncio.run(init_db()); asyncio.run(crud.set_setting('obfs_password', '$nobfs')); asyncio.run(apply_and_save_config()); restart_hysteria()"
                echo -e "${C_GREEN}✔ Пароль Salamander Obfs обновлен: ${C_YELLOW}$nobfs${C_RESET}"
                read -rp "Нажмите Enter для продолжения..."
                ;;
            5)
                echo ""
                echo -e "${C_GREEN}✔ Protocol Sniffing активен по умолчанию для корректного роутинга в Hiddify/Sing-box.${C_RESET}"
                read -rp "Нажмите Enter для продолжения..."
                ;;
            6)
                echo ""
                read -rp "Включить WARP outbound для OpenAI/Netflix? (y/N): " wconf
                local w_val=$([[ "$wconf" =~ ^[Yy]$ ]] && echo "1" || echo "0")
                $PYTHON_BIN -c "import asyncio; from app.database.connection import init_db; from app.database import crud; from app.core.hysteria import apply_and_save_config, restart_hysteria; asyncio.run(init_db()); asyncio.run(crud.set_setting('warp_enabled', '$w_val')); asyncio.run(apply_and_save_config()); restart_hysteria()"
                echo -e "${C_GREEN}✔ Настройки WARP обновлены!${C_RESET}"
                read -rp "Нажмите Enter для продолжения..."
                ;;
            0) return ;;
            *) sleep 1 ;;
        esac
    done
}

# ==================== 6. СИСТЕМНЫЕ ИНСТРУМЕНТЫ И ОПТИМИЗАЦИЯ ====================
manage_system_menu() {
    while true; do
        print_header
        echo -e "${C_CYAN}${C_BOLD}=== 🛠️ Системные инструменты и Оптимизация ===${C_RESET}\n"
        echo -e " ${C_GREEN}[1]${C_RESET} 🚀 Включить оптимизацию TCP BBR и буферов UDP (макс. скорость QUIC)"
        echo -e " ${C_GREEN}[2]${C_RESET} 🔍 Проверить открытые и слушающие сетевые порты сервера"
        echo -e " ${C_GREEN}[3]${C_RESET} 💾 Создать резервную копию (Бэкап базы данных и сертификатов)"
        echo -e " ${C_GREEN}[4]${C_RESET} 📥 Восстановить систему из бэкапа"
        echo -e " ${C_GREEN}[5]${C_RESET} 📜 Просмотр системных логов ядра Hysteria 2"
        echo -e " ${C_GREEN}[6]${C_RESET} 🔄 Перезапустить все службы (Hysteria 2 + Панель)"
        echo -e "\n ${C_YELLOW}[0]${C_RESET} Назад в главное меню\n"
        read -rp "Выберите пункт [0-6]: " sopt

        case "$sopt" in
            1)
                echo ""
                $CLI_CMD optimize-bbr
                read -rp "Нажмите Enter для продолжения..."
                ;;
            2)
                echo ""
                echo -e "${C_CYAN}Слушающие порты UDP и TCP:${C_RESET}"
                if command -v ss &>/dev/null; then
                    ss -tulpn | grep -E "hysteria|python|uvicorn|443" || ss -tulpn | head -n 25
                elif command -v netstat &>/dev/null; then
                    netstat -tulpn | head -n 25
                fi
                echo ""
                read -rp "Нажмите Enter для продолжения..."
                ;;
            3)
                echo ""
                $CLI_CMD backup
                read -rp "Нажмите Enter для продолжения..."
                ;;
            4)
                echo ""
                read -rp "Введите полный путь к архиву бэкапа (.tar.gz): " bfile
                if [ -n "$bfile" ]; then
                    $CLI_CMD restore "$bfile"
                fi
                read -rp "Нажмите Enter для продолжения..."
                ;;
            5)
                echo -e "${C_CYAN}Последние 50 строк логов Hysteria 2 (нажмите q для выхода):${C_RESET}"
                journalctl -u hysteria-server.service -n 50 -e
                ;;
            6)
                echo ""
                systemctl restart hysteria-server.service innerblitz.service || true
                echo -e "${C_GREEN}✔ Все службы успешно перезапущены!${C_RESET}"
                read -rp "Нажмите Enter для продолжения..."
                ;;
            0) return ;;
            *) sleep 1 ;;
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

main_menu() {
    check_root

    while true; do
        print_header
        echo -e "${C_BOLD}Главное меню управления:${C_RESET}\n"
        echo -e " ${C_GREEN}[1]${C_RESET} 👥 Управление пользователями (Клиенты, Квоты, Сроки)"
        echo -e " ${C_GREEN}[2]${C_RESET} 🔒 Сертификаты и Домены (IP SAN TLS + pinSHA256 / ACME)"
        echo -e " ${C_GREEN}[3]${C_RESET} ⚡ Управление портами Hysteria 2 (Смена, Hopping, Сброс)"
        echo -e " ${C_GREEN}[4]${C_RESET} 🖥️ Управление веб-панелью (Пароли, Стелс-порт, Пути, Сброс 2FA)"
        echo -e " ${C_GREEN}[5]${C_RESET} 🛡️ Тонкие настройки ядра (Анти-DPI, Скорость, Игры, Obfs)"
        echo -e " ${C_GREEN}[6]${C_RESET} 🛠️ Системные инструменты (BBR, Бэкап, Логи, Диагностика)"
        echo -e " ${C_CYAN}[7]${C_RESET} 🚀 Обновить ядро Hysteria 2"
        echo -e " ${C_CYAN}[8]${C_RESET} ⚡ Обновить InnerBlitz"
        echo -e "\n ${C_RED}[0]${C_RESET} Выход из меню\n"

        read -rp "Выберите пункт [0-8]: " opt

        case "$opt" in
            1) manage_users_menu ;;
            2) manage_certs_menu ;;
            3) manage_ports_menu ;;
            4) manage_webpanel_menu ;;
            5) presets_menu ;;
            6) manage_system_menu ;;
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