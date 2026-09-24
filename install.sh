#!/usr/bin/env bash

# ==============================================================================
#  ⚡ InnerBlitz Installer — Next-Gen Hysteria 2 Management Panel
#  Repository: https://github.com/Innernode-dev/innerblitz
# ==============================================================================

set -e

INSTALL_DIR="/etc/hysteria"
REPO_URL="https://github.com/Innernode-dev/innerblitz.git"

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

log_info() { echo -e "${C_CYAN}[INFO]${C_RESET} $1"; }
log_success() { echo -e "${C_GREEN}[✔]${C_RESET} $1"; }
log_warn() { echo -e "${C_YELLOW}[!]${C_RESET} $1"; }
log_error() { echo -e "${C_RED}[✖]${C_RESET} $1" >&2; }

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "Этот скрипт должен быть запущен с правами root!"
        exit 1
    fi
}

detect_ip() {
    SERVER_IP=$(curl -s4 -m 3 icanhazip.com || curl -s4 -m 3 ifconfig.me || echo "127.0.0.1")
}

check_system() {
    log_info "Проверка совместимости операционной системы..."
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID=$ID
        OS_VER=$VERSION_ID
        log_success "ОС обнаружена: $NAME $VERSION_ID"
    else
        log_error "Не удалось определить операционную систему."
        exit 1
    fi
}

install_dependencies() {
    log_info "Обновление репозиториев и установка системных пакетов..."
    apt-get update -qq
    apt-get install -y -qq curl git wget python3 python3-pip python3-venv iptables openssl jq ca-certificates
    log_success "Системные зависимости установлены."
}

install_hysteria_core() {
    log_info "Установка актуального ядра Hysteria 2..."
    bash <(curl -fsSL https://get.hy2.sh/) >/dev/null 2>&1 || {
        log_warn "Стандартный установщик выдал предупреждение, проверяем наличие бинарника..."
    }
    if command -v hysteria &> /dev/null; then
        HYS_VER=$(hysteria version | grep "Version:" | awk '{print $2}' || echo "v2")
        log_success "Ядро Hysteria 2 установлено (Версия: ${HYS_VER})."
    else
        log_error "Не удалось установить Hysteria 2!"
        exit 1
    fi
}

deploy_codebase() {
    log_info "Развертывание кодовой базы InnerBlitz в ${INSTALL_DIR}..."
    mkdir -p "${INSTALL_DIR}"

    # If current directory contains app and requirements.txt, copy local files
    if [ -f "./requirements.txt" ] && [ -d "./app" ]; then
        log_info "Копирование локальных файлов проекта..."
        cp -r ./* "${INSTALL_DIR}/"
    else
        log_info "Клонирование репозитория Innernode-dev/innerblitz..."
        if [ -d "${INSTALL_DIR}/.git" ]; then
            cd "${INSTALL_DIR}" && git pull origin main
        else
            rm -rf "${INSTALL_DIR:?}"/*
            git clone "${REPO_URL}" "${INSTALL_DIR}"
        fi
    fi

    chmod +x "${INSTALL_DIR}/menu.sh" "${INSTALL_DIR}/cli.py" "${INSTALL_DIR}/upgrade.sh" "${INSTALL_DIR}/uninstall.sh" || true
    log_success "Файлы панели успешно развернуты."
}

setup_python_env() {
    log_info "Настройка изолированного виртуального окружения Python..."
    cd "${INSTALL_DIR}"
    if [ ! -d "${INSTALL_DIR}/venv" ]; then
        python3 -m venv "${INSTALL_DIR}/venv"
    fi
    "${INSTALL_DIR}/venv/bin/pip" install --upgrade pip --quiet
    log_info "Установка модулей Python (FastAPI, SQLite, Cryptography)..."
    "${INSTALL_DIR}/venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt" --quiet
    log_success "Python окружение настроено без ошибок."
}

configure_innerblitz() {
    echo ""
    echo -e "${C_PURPLE}${C_BOLD}┌────────────────────────────────────────────────────────┐${C_RESET}"
    echo -e "${C_PURPLE}${C_BOLD}│            Режим установки InnerBlitz                  │${C_RESET}"
    echo -e "${C_PURPLE}${C_BOLD}└────────────────────────────────────────────────────────┘${C_RESET}"
    echo -e " ${C_GREEN}[1]${C_RESET} ${C_BOLD}Экспресс-установка (1-Клик)${C_RESET} — Рекомендуется"
    echo -e "     Автоопределение IP, генерация TLS-сертификата с IP SAN,"
    echo -e "     случайные порты, пароли и мгновенный запуск."
    echo -e " ${C_CYAN}[2]${C_RESET} ${C_BOLD}Кастомная установка${C_RESET}"
    echo -e "     Выбор основного порта, домена, obfs и пароля администратора."
    echo ""
    read -rp "Выберите режим [1/2] (по умолчанию 1): " install_mode
    install_mode=${install_mode:-1}

    detect_ip

    LISTEN_PORT=443
    PORT_HOP_RANGE="20000:50000"
    DOMAIN=""
    RANDOM_PANEL_PORT=$(( 20000 + RANDOM % 40000 ))
    RANDOM_PANEL_SECRET="node-$(openssl rand -hex 3)"
    PANEL_PORT=$RANDOM_PANEL_PORT
    PANEL_SECRET=$RANDOM_PANEL_SECRET
    ADMIN_PASS=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 12)

    if [ "$install_mode" -eq 2 ]; then
        echo ""
        read -rp "Основной порт Hysteria 2 [443]: " user_port
        LISTEN_PORT=${user_port:-443}

        read -rp "Использовать домен? (Оставьте пустым для прямого IP $SERVER_IP): " user_domain
        DOMAIN=${user_domain:-""}

        read -rp "Диапазон Port Hopping [20000:50000]: " user_hop
        PORT_HOP_RANGE=${user_hop:-"20000:50000"}

        read -rp "Порт веб-панели [$RANDOM_PANEL_PORT]: " user_panel_port
        PANEL_PORT=${user_panel_port:-$RANDOM_PANEL_PORT}

        read -rp "Секретный URL-путь входа [$RANDOM_PANEL_SECRET]: " user_panel_secret
        PANEL_SECRET=${user_panel_secret:-$RANDOM_PANEL_SECRET}

        read -rp "Пароль администратора веб-панели [$ADMIN_PASS]: " user_pass
        ADMIN_PASS=${user_pass:-$ADMIN_PASS}
    fi

    log_info "Инициализация базы данных SQLite и сертификата на IP..."
    
    # Run CLI init
    "${INSTALL_DIR}/venv/bin/python3" "${INSTALL_DIR}/cli.py" init
    
    # Set panel access (custom or random port & secret path)
    "${INSTALL_DIR}/venv/bin/python3" "${INSTALL_DIR}/cli.py" set-panel-access --port "$PANEL_PORT" --path "$PANEL_SECRET"

    # Generate IP Certificate
    TARGET_HOST=${DOMAIN:-$SERVER_IP}
    "${INSTALL_DIR}/venv/bin/python3" "${INSTALL_DIR}/cli.py" gen-ip-cert --ip "$TARGET_HOST"

    # Set admin password
    "${INSTALL_DIR}/venv/bin/python3" "${INSTALL_DIR}/cli.py" set-admin-password "$ADMIN_PASS"

    # Create default user
    "${INSTALL_DIR}/venv/bin/python3" "${INSTALL_DIR}/cli.py" add-user -u "default" -t 50 -d 30 || true

    log_success "Конфигурация успешно создана."
}

setup_services() {
    log_info "Настройка и запуск системных служб systemd..."

    # Configure Hysteria server service to use our config.yaml
    mkdir -p /etc/systemd/system/
    cat << EOF > /etc/systemd/system/hysteria-server.service
[Unit]
Description=Hysteria 2 Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.yaml
Restart=always
RestartSec=3s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    # Copy innerblitz panel service
    cp "${INSTALL_DIR}/systemd/innerblitz.service" /etc/systemd/system/innerblitz.service

    systemctl daemon-reload
    systemctl enable --now hysteria-server.service
    systemctl enable --now innerblitz.service

    # Create shortcuts: blitz, inb, hys2
    ln -sf "${INSTALL_DIR}/menu.sh" /usr/local/bin/blitz
    ln -sf "${INSTALL_DIR}/menu.sh" /usr/local/bin/inb
    ln -sf "${INSTALL_DIR}/menu.sh" /usr/local/bin/hys2
    chmod +x /usr/local/bin/blitz /usr/local/bin/inb /usr/local/bin/hys2

    log_success "Службы запущены и добавлены в автозагрузку."
}

print_summary() {
    echo ""
    echo -e "${C_GREEN}${C_BOLD}================================================================${C_RESET}"
    echo -e "${C_GREEN}${C_BOLD}        🎉 InnerBlitz Panel успешно установлена! 🎉          ${C_RESET}"
    echo -e "${C_GREEN}${C_BOLD}================================================================${C_RESET}"
    echo ""
    echo -e " ${C_BOLD}🌐 Секретная ссылка на панель:${C_RESET} ${C_CYAN}http://${SERVER_IP}:${PANEL_PORT}/${PANEL_SECRET}${C_RESET}"
    echo -e " ${C_BOLD}👤 Логин администратора:${C_RESET}       ${C_WHITE}admin${C_RESET}"
    echo -e " ${C_BOLD}🔑 Пароль администратора:${C_RESET}      ${C_YELLOW}${ADMIN_PASS}${C_RESET}"
    echo ""
    echo -e " ${C_BOLD}🛡️ Маскировка от РКН/сканеров:${C_RESET} ${C_GREEN}АКТИВНА (Decoy Cloud Node)${C_RESET}"
    echo -e "   ${C_GRAY}(Корень http://${SERVER_IP}:${PANEL_PORT}/ показывает открытый IT-проект)${C_RESET}"
    echo ""
    echo -e " ${C_BOLD}🔒 Порт Hysteria 2:${C_RESET}            ${C_WHITE}${LISTEN_PORT} UDP${C_RESET}"
    echo -e " ${C_BOLD}⚡ Port Hopping диапазон:${C_RESET}      ${C_WHITE}${PORT_HOP_RANGE}${C_RESET}"
    echo -e " ${C_BOLD}🛡️ Сертификат на IP:${C_RESET}          ${C_GREEN}Активен (SAN + pinSHA256)${C_RESET}"
    echo ""
    echo -e " ${C_BOLD}Команда управления в терминале:${C_RESET} ${C_PURPLE}${C_BOLD}blitz${C_RESET} (или ${C_CYAN}inb${C_RESET}, ${C_CYAN}hys2${C_RESET})"
    echo -e "${C_GREEN}${C_BOLD}================================================================${C_RESET}\n"
}

main() {
    check_root
    check_system
    install_dependencies
    install_hysteria_core
    deploy_codebase
    setup_python_env
    configure_innerblitz
    setup_services
    print_summary
}

main
