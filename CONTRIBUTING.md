# Contributing to InnerBlitz

Thank you for your interest in contributing to **InnerBlitz**!  
InnerBlitz is an open-source, next-generation management suite for **Hysteria 2**, designed for high throughput, absolute resilience against network censorship, and minimal server footprint.

We welcome contributions from developers, network engineers, UI designers, and security researchers of all skill levels.

---

## 🧭 Project Architecture & Philosophy

Before making changes, keep our core architectural tenets in mind:

1. **Zero-AVX & Ultra-Low Footprint:**  
   We strictly use embedded **SQLite WAL** (`aiosqlite`) rather than external database daemons (MongoDB, PostgreSQL). The entire panel must consume under **50 MB RAM** and run on any 512 MB VPS without CPU instruction set limitations.

2. **Censorship Resistance First:**  
   Every network-facing component must incorporate anti-censorship safeguards: dynamic port allocation, stealth secret paths, realistic decoy camouflage, and constant-time authentication.

3. **Modern Async Stack:**  
   Backend code is built with **Python 3.10+**, **FastAPI**, **Uvicorn**, and **aiosqlite**. Frontend interfaces use server-rendered **Jinja2** templates with **Tailwind CSS** and responsive Glassmorphism components.

---

## 📁 Repository Structure

```
innerblitz/
├── app/
│   ├── api/             # FastAPI REST endpoints & page controllers
│   │   ├── auth_routes.py        # Login, logout, session management, 2FA
│   │   ├── node_routes.py        # Inbound settings, YAML editor, core controls
│   │   ├── user_routes.py        # Client creation, limits, expiration, resets
│   │   ├── settings_routes.py    # Stealth access, backups, BBR, presets
│   │   ├── sub_routes.py         # Client subscription links & portals
│   │   └── system_routes.py      # Telemetry, live charts, service logs
│   ├── core/            # System automation & core engines
│   │   ├── cert.py               # Self-signed ECDSA IP SAN certificate generator
│   │   ├── firewall.py           # iptables & ip6tables Port Hopping manager
│   │   ├── hysteria.py           # Hysteria 2 config.yaml generator & systemctl
│   │   ├── security.py           # bcrypt hashing, TOTP generator, token verification
│   │   └── subscription.py       # URI schemes (hy2://, clash, sing-box)
│   ├── database/        # Data layer
│   │   ├── connection.py         # SQLite connection with WAL pragma & migrations
│   │   ├── crud.py               # Asynchronous CRUD queries
│   │   └── models.py             # Pydantic data schemas
│   ├── templates/       # Jinja2 HTML templates styled with Tailwind CSS
│   └── config.py        # Environment variables and application paths
├── systemd/             # Systemd service units
├── cli.py               # Command-line Click tool (/etc/hysteria/cli.py)
├── menu.sh              # Interactive terminal TUI management console (blitz)
├── install.sh           # 1-Click automated server installer
├── upgrade.sh           # Safe upgrade & stealth migration script
├── uninstall.sh         # Safe and clean uninstaller
└── requirements.txt     # Python runtime dependencies
```

---

## 🛠️ Setting Up Local Development

### 1. Fork & Clone
```bash
git clone https://github.com/Innernode-dev/innerblitz.git
cd innerblitz
```

### 2. Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Initialize SQLite Database
```bash
python cli.py init
```

### 4. Run Development Server
```bash
python -m app.main
```
The panel will start on `http://127.0.0.1:8080` (or the configured stealth port).

---

## 📋 Pull Request (PR) Guidelines

1. **Branch Naming:**  
   Use descriptive branch names:
   * `feat/node-traffic-sniffing`
   * `fix/port-hopping-ipv6-flush`
   * `docs/update-upgrade-guide`

2. **Commit Conventions:**  
   Write concise, descriptive commit messages following the Conventional Commits specification:
   * `feat: add custom decoy theme support`
   * `fix: prevent 404 leakage on secret panel routes`
   * `refactor: optimize SQLite WAL query performance`
   * `docs: update security policy and architecture overview`

3. **Code Style & Formatting:**
   * Python: Follow PEP 8 style guide.
   * Shell: Ensure scripts are compatible with `bash` across Ubuntu 20.04+, 22.04+, 24.04 and Debian 11/12.
   * Verify Python files compile cleanly:
     ```bash
     python -m py_compile app/main.py cli.py app/api/*.py app/core/*.py
     ```

4. **Testing Changes:**
   * Verify that existing CLI commands (`python cli.py list-users`, `show-panel-url`) function correctly.
   * Ensure any database schema modifications maintain backwards compatibility for existing deployments.

---

## 🐛 Reporting Bugs & Feature Requests

* **Bug Reports:** Open an issue on [GitHub Issues](https://github.com/Innernode-dev/innerblitz/issues). Please include:
  * Operating System and distribution version (`lsb_release -a`).
  * Python version (`python3 --version`).
  * Relevant logs from `journalctl -u innerblitz.service -n 50`.
* **Feature Requests:** Share your use case and proposed solution. Community feedback and real-world censorship bypass techniques are always appreciated!

---

## 🔒 Security Vulnerabilities

**Do not** report security vulnerabilities via public GitHub issues.  
Please consult our [Security Policy](SECURITY.md) or open a private advisory at [GitHub Security Advisories](https://github.com/Innernode-dev/innerblitz/security/advisories).

---

## ⚖️ License

By contributing to **InnerBlitz**, you agree that your contributions will be licensed under the **GNU General Public License v3.0 (GPL-3.0)**.
