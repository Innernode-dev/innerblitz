<div align="center">

# ⚡ InnerBlitz — Hysteria 2 Next-Gen Panel

[![Hysteria 2](https://img.shields.io/badge/Hysteria_Core-v2.12.3+-6366f1?style=for-the-badge&logo=fastapi&logoColor=white)](https://github.com/HyNetworks/hysteria)
[![Python](https://img.shields.io/badge/Python-3.10+-3b82f6?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Database](https://img.shields.io/badge/Database-SQLite_WAL-0284c7?style=for-the-badge&logo=sqlite&logoColor=white)](https://sqlite.org)
[![License](https://img.shields.io/badge/License-GPL_v3-8b5cf6?style=for-the-badge)](LICENSE)

<p align="center">
  <b>Современная, молниеносная и сверхзащищенная панель управления прокси-сервером Hysteria 2 с поддержкой сертификатов на IP, Port Hopping, премиальным Glassmorphism интерфейсом и гибкой 2FA.</b>
</p>

</div>

---

## 🌟 Ключевые особенности

- 🚀 **1-Click Экспресс Установка:** Полное автоматическое развертывание за 60 секунд одной командой.
- 💾 **Ультра-легкий стек (Zero AVX):** Полный отказ от тяжелого MongoDB в пользу молниеносного **SQLite** (`aiosqlite`). Потребляет менее **50 МБ RAM** и запускается на любых VPS от 512 МБ памяти без требований к инструкциям AVX.
- 🔒 **Сертификаты на IP (Subject Alternative Name + pinSHA256):**
  - Подключение напрямую по IP-адресу без покупки домена.
  - Автоматическая генерация сертификата с IP SAN и расчет хеша `pinSHA256` для 100% защиты клиентов от MITM-атак.
  - Автоматический ACME (Let's Encrypt / ZeroSSL) при наличии доменного имени.
- 🛡️ **Полная поддержка передовых функций Hysteria 2:**
  - **Port Hopping (Скачки портов):** Прослушивание диапазона портов (например, `:20000-50000`) для обхода блокировок конкретных UDP-портов операторами.
  - **Salamander Obfs:** Запутывание заголовков QUIC для маскировки под случайный энтропийный шум.
  - **Masquerade (HTTP/3 Proxy):** Перенаправление неавторизованных запросов на доверенные сайты (например, `https://bing.com`).
  - **Mimic (Fake TCP):** Обход ограничений провайдеров на чистый UDP-трафик.
  - **1-Click Пресеты:** Мгновенное переключение между профилями *«Анти-DPI»*, *«Скорость (1 Гбит/с)»* и *«Игровой»*.
- ✨ **Премиальный Glassmorphism Dashboard:**
  - Стильная адаптивная тёмная тема на Tailwind CSS.
  - Живые графики скорости (Download/Upload) в реальном времени.
  - Мониторинг CPU, памяти, диска и аптайма сервера.
- 📱 **Персональный портал клиента (Client Portal):**
  - Страница абонента (`/portal/{token}`): остаток трафика, дни до окончания, QR-код.
  - Быстрый импорт в 1 клик в **Hiddify**, **v2rayN**, **Sing-box**, **Shadowrocket**, **Clash Verge**, **Streisand**, **NekoBox**.
- 🔐 **Гибкая безопасность и Двухфакторная Аутентификация (2FA):**
  - Google Authenticator / Aegis (RFC 6238 TOTP).
  - Подтверждение входа одноразовым OTP-кодом в Telegram.
  - Защита от подбора паролей (Rate Limiting) и timing-safe проверки (`secrets.compare_digest`).
- 🤖 **Встроенный Telegram-бот:**
  - Оповещения администратора о трафике и статусе сервера.
  - Отправка кодов 2FA.
  - Проверка баланса пользователями.

---

## 🚀 Быстрый старт (Установка в 1 клик)

Выполните команду на вашем чистом сервере с правами `root` (Ubuntu 22.04+, Debian 12+):

```bash
bash <(curl -sL https://raw.githubusercontent.com/Innernode-dev/innerblitz/main/install.sh)
```

Скрипт автоматически установит ядро Hysteria 2, настроит SQLite базу данных, сгенерирует сертификат на IP, выведет данные для входа в веб-панель и образец подключения.

---

## 💻 Управление в терминале

Для вызова интерактивного консольного меню на сервере используйте команду:

```bash
blitz
```
*(Также работают привычные синонимы `inb` и `hys2`)*

---

## 📱 Поддерживаемые клиентские приложения

| Платформа | Рекомендуемые клиенты | Формат подключения |
| :--- | :--- | :--- |
| **Android** | **Hiddify**, **v2rayNG**, **NekoBox** | Ссылка подписки, QR-код, `hy2://` |
| **iOS / iPadOS** | **Hiddify**, **Streisand**, **Shadowrocket** | Импорт в 1 клик, QR-код |
| **Windows** | **Hiddify Next**, **v2rayN**, **Clash Verge Rev** | Ссылка подписки, Clash YAML, Sing-box JSON |
| **macOS** | **Hiddify**, **Sing-box**, **Shadowrocket** | Универсальная подписка |
| **Linux** | **Hiddify**, **Sing-box CLI** | JSON конфигурация |

---

## ⚙️ Команды CLI

Вы можете управлять пользователями и сервером без интерактивного меню:

```bash
# Добавить пользователя с лимитом 50 GB на 30 дней
/etc/hysteria/venv/bin/python3 /etc/hysteria/cli.py add-user -u alex -t 50 -d 30

# Список пользователей
/etc/hysteria/venv/bin/python3 /etc/hysteria/cli.py list-users

# Сгенерировать IP-сертификат
/etc/hysteria/venv/bin/python3 /etc/hysteria/cli.py gen-ip-cert

# Перезапуск службы Hysteria 2
/etc/hysteria/venv/bin/python3 /etc/hysteria/cli.py restart
```

---

## 🔄 Обновление

Обновить панель InnerBlitz и ядро Hysteria 2 до самых свежих версий можно двумя способами:

1. **Через меню терминала:**
   Запустите `blitz` и выберите пункт `[8] ⚡ Обновить InnerBlitz`.

2. **Одной командой bash:**
   ```bash
   bash <(curl -sL https://raw.githubusercontent.com/Innernode-dev/innerblitz/main/upgrade.sh)
   ```
   *Либо локально на сервере:*
   ```bash
   bash /etc/hysteria/upgrade.sh
   ```

---

## 🗑️ Удаление

Для полного и чистого удаления панели и ядра с возможностью сохранения бэкапа базы данных:

```bash
bash /etc/hysteria/uninstall.sh
```

---

## 📜 Лицензия

Проект распространяется под свободной лицензией **GPL-3.0**.  
Разработано с заботой о приватности и скорости командой **InnerNode** (`Innernode-dev`).

---

## 🙏 Благодарности и первоисточники (Credits & Acknowledgments)

- [HyNetworks / Hysteria Team](https://github.com/HyNetworks/hysteria) — за создание революционного протокола Hysteria 2.
- [ReturnFI (Blitz Panel)](https://github.com/ReturnFI/Blitz) — за оригинальную концепцию панели Blitz, вдохновившую на создание этой полной переработки (Next-Gen Rewrite).
- [IamSarina](https://github.com/Iam54r1n4) — за вклад в сообщество Hysteria.

