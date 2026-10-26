<div align="center">

# ⚡ InnerBlitz — Hysteria 2 Next-Gen Panel

[![Hysteria 2](https://img.shields.io/badge/Hysteria_Core-v2.12.3+-6366f1?style=for-the-badge&logo=fastapi&logoColor=white)](https://github.com/HyNetworks/hysteria)
[![Python](https://img.shields.io/badge/Python-3.10+-3b82f6?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Database](https://img.shields.io/badge/Database-SQLite_WAL-0284c7?style=for-the-badge&logo=sqlite&logoColor=white)](https://sqlite.org)
[![License](https://img.shields.io/badge/License-GPL_v3-8b5cf6?style=for-the-badge)](LICENSE)

<p align="center">
  <b>Высокоскоростная, сверхзащищенная панель управления Hysteria 2 с визуальной маршрутизацией, интеграцией Cloudflare WARP, поддержкой сертификатов на IP, Port Hopping и авторским интерфейсом.</b><br>
  <b>High-performance, ultra-resilient Hysteria 2 management panel featuring visual split routing, Cloudflare WARP integration, IP SAN certificates, Port Hopping, and a human-crafted Glassmorphism UI.</b>
</p>

[ 🇷🇺 Русский ](#-русский) | [ 🇬🇧 English ](#-english)

</div>

---

# 🇷🇺 Русский

## 🌟 Ключевые возможности

### 🌐 Интеллектуальный жизненный цикл Cloudflare WARP
- **1-Клик установка на голое железо:** Автоматическое развертывание WireGuard/WARP прямо из веб-интерфейса или консольного меню со стримингом логов установки в реальном времени.
- **Автоопределение и переиспользование:** Панель мгновенно распознает существующий интерфейс (`warp`, `wgcf`) или локальный SOCKS5-прокси (`127.0.0.1:40000`), предотвращая создание дублирующих демонов.
- **Живая диагностика:** Мониторинг выходного IP-адреса через `cloudflare.com/cdn-cgi/trace`, измерение сетевой задержки (ping) и индикация статуса (*Active*, *Standby*, *Offline*).

### 🧭 Визуальный конструктор маршрутизации (Zero-YAML)
- **Управление правилами без правки файлов:** Полный отказ от ручного редактирования `config.yaml` — все параметры настраиваются переключателями в веб-интерфейсе.
- **Глобальный шлюз выхода (Global Outbound):** Переключение в 1 клик между прямым IP сервера (*Direct*) и адресом Cloudflare (*WARP*).
- **Раздельная маршрутизация для РФ (3-way selector):** Направление трафика `geosite:ru` и `geoip:ru`:
  - *Прямо через оператора (Direct)* — минимальный пинг до банков, Госуслуг и локальных сервисов.
  - *Через WARP* — скрытие IP-адреса сервера от российских систем блокировок.
  - *Блокировать (Block)*.
- **Матрица пресетов сервисов:** Быстрое перенаправление или блокировка для **OpenAI / ChatGPT**, **Discord**, **YouTube**, **Telegram**, **Netflix**, **P2P/Торренты**, блокировка рекламы (`category-ads-all`) и телеметрии Windows (`win-spy`).

### ⚡ Сниффинг протоколов и Port Hopping
- **Интерактивный Sniffing:** Включение анализа заголовков (`sniff.enable`), настройка таймаута и подмена доменов (`rewriteDomain`).
- **Изолированный Port Hopping:** Использование выделенной цепочки `INNERBLITZ_HOPPING` в `iptables`/`ip6tables` и таблицы `innerblitz_nat` в `nftables`.
- **Автовосстановление при перезагрузке:** Постоянство правил фаервола после перезагрузки хост-сервера и чистое удаление без остаточных блокировок.

### 📱 Подписки и Персональный портал клиента
- **Клиентские профили Sing-box v1.10+:** Генерация полного JSON-конфига с TUN-интерфейсом, DNS-серверами и правилами маршрутизации, соответствующими политике сервера.
- **Профили Clash Meta / Mihomo:** Автоматическое построение YAML с группами прокси (`PROXY`, `RU-Traffic`, `Services`) и гео-правилами.
- **1-Клик импорт в портале (`/portal/{token}`):** Поддержка нативных URI-схем для мгновенного добавления: `hiddify://`, `sing-box://`, `clash://`, `v2rayng://` и `nekobox://`.

### 🔒 Сертификаты на IP (IP SAN + pinSHA256)
- Подключение клиентов напрямую по IP-адресу без покупки доменного имени.
- Автоматическая генерация самоподписанного сертификата ECDSA с IP SAN и расчет хеша `pinSHA256` для надежной защиты от MITM-атак.
- Встроенная поддержка ACME (Let's Encrypt / ZeroSSL) при наличии доменного имени.

### 🛡️ Стелс-маскировка и Anti-Censorship
- **Случайный высокий порт и секретный URL-путь:** Панель скрыта на случайном порту (20000–60000) и в уникальной директории (например, `/node-8f2a`).
- **Сайт-приманка (Decoy):** Заглушка на корне `/` с маскировкой под веб-сервер Nginx (`Server: nginx/1.24.0`), облачный узел телеметрии или черную дыру 404.
- **Обход блокировок:** Поддержка Salamander Obfs, Masquerade (HTTP/3 proxy) и Mimic (Fake TCP).
- **1-Клик профили ядра:** Быстрое переключение между профилями *«Анти-DPI»*, *«Скорость (1 Гбит/с)»* и *«Игровой»*.

### ✨ Авторский дизайн и производительность (Zero-AVX)
- Глубокая темная тема Zinc/Slate с продуманной эргономикой без шаблонности нейросетей.
- Потребление оперативной памяти менее **50 МБ RAM** благодаря встроенной SQLite WAL (`aiosqlite`).
- Отсутствие зависимости от инструкций AVX — работа на любых серверах от 512 МБ RAM.

---

## 🚀 Быстрый старт (Установка за 60 секунд)

Выполните команду на чистом сервере с правами `root` (Ubuntu 20.04+, 22.04+, 24.04, Debian 11/12):

```bash
bash <(curl -sL https://raw.githubusercontent.com/Innernode-dev/innerblitz/main/install.sh)
```

Инсталлятор проверит зависимости, установит ядро Hysteria 2, сгенерирует сертификат на IP, настроит базу данных SQLite и выведет учетные данные с секретной ссылкой входа.

---

## 💻 Консольное меню управления

Для вызова интерактивного меню на сервере введите:

```bash
blitz
```
*(Также поддерживаются алиасы `inb` и `hys2`)*

---

## 📱 Поддерживаемые клиентские приложения

| Платформа | Рекомендуемые клиенты | Форматы подключения |
| :--- | :--- | :--- |
| **Android** | **Hiddify**, **v2rayNG**, **NekoBox**, **Sing-box** | 1-Клик импорт, QR-код, `hy2://`, Sing-box JSON |
| **iOS / iPadOS** | **Hiddify**, **Streisand**, **Shadowrocket**, **Sing-box** | 1-Клик импорт, QR-код, подписка |
| **Windows** | **Hiddify**, **Clash Verge Rev**, **v2rayN**, **Mihomo Party** | Clash Meta YAML, Sing-box JSON, `hy2://` |
| **macOS** | **Hiddify**, **Sing-box**, **Clash Verge Rev** | 1-Клик импорт, Clash YAML, Sing-box JSON |
| **Linux** | **Hiddify**, **Sing-box CLI** | Sing-box JSON, Clash YAML |

---

## ⚙️ Управление через CLI

Вы можете администрировать пользователей и сервер через утилиту `cli.py`:

```bash
# Добавить пользователя с лимитом 50 GB на 30 дней
/etc/hysteria/venv/bin/python3 /etc/hysteria/cli.py add-user -u alex -t 50 -d 30

# Список активных пользователей
/etc/hysteria/venv/bin/python3 /etc/hysteria/cli.py list-users

# Вывести секретный адрес панели
/etc/hysteria/venv/bin/python3 /etc/hysteria/cli.py show-panel-url

# Перезапуск службы ядра Hysteria 2
/etc/hysteria/venv/bin/python3 /etc/hysteria/cli.py restart
```

---

## 🔄 Обновление и Удаление

### Обновление до актуальной версии:
```bash
bash <(curl -sL https://raw.githubusercontent.com/Innernode-dev/innerblitz/main/upgrade.sh)
```

### Чистое удаление:
```bash
bash /etc/hysteria/uninstall.sh
```

---
---

# 🇬🇧 English

## 🌟 Key Features

### 🌐 Cloudflare WARP Outbound & Lifecycle Engine
- **1-Click Bare-Metal Installer:** Automated WireGuard/WARP deployment directly from the web dashboard or CLI menu with real-time log streaming.
- **Auto-Detection & Reuse:** Automatically detects existing WireGuard interfaces (`warp`, `wgcf`) or local SOCKS5 proxies (`127.0.0.1:40000`), avoiding duplicate daemons or registrations.
- **Live Diagnostics:** Displays real egress IP via `cloudflare.com/cdn-cgi/trace`, latency ping, and active status badges (*Active*, *Standby*, *Offline*).

### 🧭 Visual Routing Engine (Zero-YAML Configurator)
- **Zero Manual File Editing:** Interactive web UI rule builder with toggle switches — no manual editing of configuration files required.
- **Global Outbound Gateway Switcher:** Switch between Direct (server host IP) and Cloudflare WARP IP in a single click.
- **Russian Federation Traffic Routing (3-way selector):** Direction for `geosite:ru` and `geoip:ru`:
  - *Direct (Server ISP)* — Lowest latency for local services, banking, and government portals.
  - *WARP (Cloudflare)* — Egress through Cloudflare WARP to avoid server IP leakage.
  - *Block* — Restrict access entirely.
- **1-Click Service Presets:** Instant routing rules for **OpenAI / ChatGPT**, **Discord**, **YouTube**, **Telegram**, **Netflix**, **P2P/Torrents**, Ad-blocking (`category-ads-all`), and Windows Telemetry (`win-spy`).

### ⚡ Protocol Sniffing & Port Hopping Management
- **Interactive Domain Sniffing:** Toggle `sniff.enable`, configure timeouts, and domain rewriting (`rewriteDomain`).
- **Dedicated Port Hopping Chains:** Dedicated `INNERBLITZ_HOPPING` chain for `iptables`/`ip6tables` and native `innerblitz_nat` table for `nftables`.
- **Boot Persistence & Clean Teardown:** Automatic rule restoration on server boot and clean rule removal on uninstall.

### 📱 Client Subscriptions & Personal Portal
- **Sing-box v1.10+ Profiles:** Generates complete client JSON configurations with TUN inbounds, mixed proxy ports, DNS rule engines, and matching outbound routes.
- **Clash Meta / Mihomo Split Profiles:** Auto-generates YAML configurations with dedicated proxy-groups (`PROXY`, `RU-Traffic`, `Services`) and geo-rule sets.
- **1-Click Import Schemes:** Client portal (`/portal/{token}`) includes 1-click import schemes for `hiddify://`, `sing-box://`, `clash://`, `v2rayng://`, and `nekobox://`.

### 🔒 IP-Certificates (IP SAN + pinSHA256)
- Connect directly via IP address without requiring a domain name.
- Automatic self-signed ECDSA certificate generation with IP SAN and client `pinSHA256` calculation for 100% MITM protection.
- Built-in ACME (Let's Encrypt / ZeroSSL) support if a domain name is configured.

### 🛡️ Stealth Camouflage & Anti-Censorship
- **Dynamic High Ports & Secret Paths:** Panel listens on a random high port (20000–60000) behind an obfuscated path (e.g. `/node-8f2a`).
- **Decoy Camouflage:** Root path `/` serves a decoy web server mimicking Nginx (`Server: nginx/1.24.0`), cloud telemetry endpoints, or blackhole 404 responses.
- **Censorship Bypasses:** Full support for Salamander Obfs, Masquerade (HTTP/3 proxy), and Mimic (Fake TCP).
- **Core Optimization Presets:** 1-Click switching between *Anti-DPI*, *High Speed (1 Gbps)*, and *Gaming* profiles.

### ✨ Human-Crafted Glassmorphism UI (Zero-AVX)
- Elegant dark Slate/Zinc aesthetic with responsive desktop and mobile ergonomics.
- Memory consumption below **50 MB RAM** utilizing embedded SQLite WAL (`aiosqlite`).
- Zero AVX CPU requirements — compatible with any budget VPS starting at 512 MB RAM.

---

## 🚀 Quick Start (1-Click Deployment)

Run this command on a clean server with `root` privileges (Ubuntu 20.04+, 22.04+, 24.04, Debian 11/12):

```bash
bash <(curl -sL https://raw.githubusercontent.com/Innernode-dev/innerblitz/main/install.sh)
```

The installer verifies prerequisites, downloads Hysteria 2 core, sets up SQLite, generates IP SAN certificates, and outputs your secret panel URL and admin credentials.

---

## 💻 Terminal Management Console

Launch the interactive management TUI on your server:

```bash
blitz
```
*(Aliases: `inb`, `hys2`)*

---

## 📱 Supported Client Applications

| Platform | Recommended Clients | Connection Formats |
| :--- | :--- | :--- |
| **Android** | **Hiddify**, **v2rayNG**, **NekoBox**, **Sing-box** | 1-Click Import, QR Code, `hy2://`, Sing-box JSON |
| **iOS / iPadOS** | **Hiddify**, **Streisand**, **Shadowrocket**, **Sing-box** | 1-Click Import, QR Code, Subscription URL |
| **Windows** | **Hiddify**, **Clash Verge Rev**, **v2rayN**, **Mihomo Party** | Clash Meta YAML, Sing-box JSON, `hy2://` |
| **macOS** | **Hiddify**, **Sing-box**, **Clash Verge Rev** | 1-Click Import, Clash YAML, Sing-box JSON |
| **Linux** | **Hiddify**, **Sing-box CLI** | Sing-box JSON, Clash YAML |

---

## ⚙️ CLI Management

Manage users and services directly via `cli.py`:

```bash
# Add a client with 50 GB quota for 30 days
/etc/hysteria/venv/bin/python3 /etc/hysteria/cli.py add-user -u alex -t 50 -d 30

# List registered clients
/etc/hysteria/venv/bin/python3 /etc/hysteria/cli.py list-users

# Retrieve secret panel URL
/etc/hysteria/venv/bin/python3 /etc/hysteria/cli.py show-panel-url

# Restart Hysteria 2 daemon
/etc/hysteria/venv/bin/python3 /etc/hysteria/cli.py restart
```

---

## 🔄 Updates & Uninstallation

### Upgrade to latest release:
```bash
bash <(curl -sL https://raw.githubusercontent.com/Innernode-dev/innerblitz/main/upgrade.sh)
```

### Clean Uninstallation:
```bash
bash /etc/hysteria/uninstall.sh
```

---

## 📜 License

InnerBlitz is distributed under the **GNU General Public License v3.0 (GPL-3.0)**.  
Crafted with passion for speed and privacy by the **InnerNode** team (`Innernode-dev`).

---

## 🙏 Credits & Acknowledgments

- [HyNetworks / Hysteria Team](https://github.com/HyNetworks/hysteria) — for creating the revolutionary Hysteria 2 protocol.
- [ReturnFI (Blitz Panel)](https://github.com/ReturnFI/Blitz) — for the original Blitz panel concept inspiring this next-generation rewrite.
- [IamSarina](https://github.com/Iam54r1n4) — for contributions to the Hysteria community.
