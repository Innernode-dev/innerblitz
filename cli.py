import os
import sys
import secrets
import shutil
import tarfile
import subprocess
import asyncio
import click
from pathlib import Path
from datetime import datetime, date

# Force UTF-8 streams to avoid encoding crashes on minimal locales
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from app.config import settings
from app.database.connection import init_db
from app.database import crud
from app.database.models import UserCreate, UserUpdate
from app.core.cert import generate_self_signed_cert
from app.core.hysteria import (
    apply_and_save_config, restart_hysteria, 
    is_hysteria_running, get_hysteria_version, get_hysteria_logs,
    run_systemctl
)
from app.core.firewall import flush_port_hopping, configure_port_hopping
from app.core.subscription import build_hy2_uri
from app.core.security import hash_password, generate_secret_path

def run_async(coro):
    return asyncio.run(coro)

@click.group()
def cli():
    """InnerBlitz CLI — High-Speed Hysteria 2 Management Console."""
    pass

@cli.command("init")
def init_system():
    """Initialize SQLite database and configuration."""
    async def _init():
        await init_db()
        await apply_and_save_config()
        click.echo(click.style("✔ InnerBlitz database & config initialized.", fg="green"))
    run_async(_init())

@cli.command("add-user")
@click.option("--username", "-u", required=True, help="Username")
@click.option("--password", "-p", default=None, help="Password (auto-generated if omitted)")
@click.option("--traffic", "-t", default=0.0, type=float, help="Traffic limit in GB (0 = unlimited)")
@click.option("--days", "-d", default=30, type=int, help="Expiration days (0 = unlimited)")
@click.option("--max-ips", default=0, type=int, help="Max simultaneous IPs (0 = unlimited)")
@click.option("--unlimited", is_flag=True, help="Exempt from all limits")
@click.option("--note", default="", help="Optional note")
def add_user(username, password, traffic, days, max_ips, unlimited, note):
    """Create a new proxy user."""
    async def _add():
        await init_db()
        existing = await crud.get_user_by_username(username)
        if existing:
            click.echo(click.style(f"✖ User '{username}' already exists.", fg="red"))
            return
        user_in = UserCreate(
            username=username,
            password=password,
            traffic_limit_gb=traffic,
            expiration_days=days,
            max_ips=max_ips,
            unlimited_user=unlimited,
            note=note
        )
        created = await crud.create_user(user_in)
        cfg = await crud.get_all_settings()
        uri = build_hy2_uri(created, cfg)
        click.echo(click.style(f"✔ User '{username}' created successfully!", fg="green"))
        click.echo(f"Password: {created['password']}")
        click.echo(f"Traffic: {traffic or 'Unlimited'} GB | Expiration: {days or 'Unlimited'} days")
        click.echo(f"\nConnection URI:\n{uri}\n")
        click.echo(f"Client Portal: /portal/{created['sub_token']}")
    run_async(_add())

@cli.command("list-users")
def list_users():
    """List all registered proxy users."""
    async def _list():
        await init_db()
        users = await crud.get_all_users()
        if not users:
            click.echo("No users registered yet.")
            return
        
        click.echo(f"{'User':<15} {'Status':<12} {'Traffic (Used/Max)':<22} {'Days Left':<10} {'Max IPs':<10}")
        click.echo("-" * 72)
        for u in users:
            status = "Blocked" if u["blocked"] else ("Expired" if u["is_expired"] else ("Limit" if u["is_limit_reached"] else "Active"))
            max_tr = f"{u['max_traffic_gb']} GB" if u["max_traffic_gb"] > 0 else "Unlimited"
            tr_str = f"{u['used_traffic_gb']} / {max_tr}"
            days_str = str(u["days_left"]) if u["expiration_days"] > 0 else "∞"
            click.echo(f"{u['username']:<15} {status:<12} {tr_str:<22} {days_str:<10} {u['max_ips']:<10}")
    run_async(_list())

@cli.command("delete-user")
@click.argument("username")
def delete_user(username):
    """Delete a user."""
    async def _del():
        await init_db()
        ok = await crud.delete_user(username)
        if ok:
            click.echo(click.style(f"✔ User '{username}' deleted.", fg="green"))
        else:
            click.echo(click.style(f"✖ User '{username}' not found.", fg="red"))
    run_async(_del())

@cli.command("reset-user")
@click.argument("username")
def reset_user(username):
    """Reset user traffic usage to zero."""
    async def _reset():
        await init_db()
        ok = await crud.reset_user_traffic(username)
        if ok:
            click.echo(click.style(f"✔ Traffic for user '{username}' reset.", fg="green"))
        else:
            click.echo(click.style(f"✖ User '{username}' not found.", fg="red"))
    run_async(_reset())

@cli.command("show-user")
@click.argument("username")
def show_user(username):
    """Display user connection URI and portal link."""
    async def _show():
        await init_db()
        u = await crud.get_user_by_username(username)
        if not u:
            click.echo(click.style(f"✖ User '{username}' not found.", fg="red"))
            return
        cfg = await crud.get_all_settings()
        uri = build_hy2_uri(u, cfg)
        click.echo(click.style(f"=== Connection Info: {username} ===", fg="cyan"))
        click.echo(f"URI: {uri}")
        click.echo(f"Portal: /portal/{u['sub_token']}")
    run_async(_show())

@cli.command("gen-ip-cert")
@click.option("--ip", default=None, help="Server IP or domain")
def gen_cert(ip):
    """Generate self-signed certificate with IP SAN and pinSHA256."""
    async def _gen():
        await init_db()
        server_ip = ip or await crud.get_setting("server_ip", "127.0.0.1")
        cert_p, key_p, sha256_pin = generate_self_signed_cert(server_ip)
        await crud.set_settings({"server_ip": server_ip, "cert_sha256": sha256_pin})
        await apply_and_save_config()
        restart_hysteria()
        click.echo(click.style(f"✔ Generated IP certificate for {server_ip}", fg="green"))
        click.echo(f"Certificate: {cert_p}")
        click.echo(f"Private Key: {key_p}")
        click.echo(f"pinSHA256: {sha256_pin}")
    run_async(_gen())

@cli.command("status")
def server_status():
    """Check Hysteria 2 and Panel status."""
    active = is_hysteria_running()
    ver = get_hysteria_version()
    click.echo(f"Hysteria 2 Core: {'RUNNING' if active else 'STOPPED'} (Version: {ver})")

@cli.command("restart")
def restart_services():
    """Restart Hysteria 2 core."""
    ok, out = restart_hysteria()
    if ok:
        click.echo(click.style("✔ Hysteria 2 restarted successfully.", fg="green"))
    else:
        click.echo(click.style(f"✖ Restart failed: {out}", fg="red"))

@cli.command("set-admin-user")
@click.argument("new_username")
def set_admin_user(new_username):
    """Change admin username for web panel."""
    async def _user():
        await init_db()
        await crud.set_setting("admin_username", new_username.strip())
        click.echo(click.style(f"✔ Admin username changed to '{new_username.strip()}'.", fg="green"))
    run_async(_user())

@cli.command("set-admin-password")
@click.argument("new_password")
def set_admin_pwd(new_password):
    """Set new admin password for web panel."""
    async def _pwd():
        await init_db()
        h = hash_password(new_password)
        await crud.set_setting("admin_password_hash", h)
        click.echo(click.style("✔ Admin password updated successfully.", fg="green"))
    run_async(_pwd())

@cli.command("set-panel-access")
@click.option("--port", default=None, help="Panel port")
@click.option("--path", default=None, help="Secret URL path")
@click.option("--theme", default=None, help="Decoy theme (nginx, innernode, docs, 404)")
def set_panel_access(port, path, theme):
    """Set custom panel port, secret URL path, and decoy theme."""
    async def _set():
        await init_db()
        updates = {}
        if port: updates["panel_port"] = str(port)
        if path: updates["panel_secret_path"] = str(path).strip("/ ")
        if theme: updates["decoy_theme"] = str(theme)
        if updates:
            await crud.set_settings(updates)
            run_systemctl("restart", "innerblitz.service")
            click.echo(click.style(f"✔ Panel access updated: Port={port or 'unchanged'}, Path=/{path or 'unchanged'}, Decoy Theme={theme or 'unchanged'}", fg="green"))
    run_async(_set())

@cli.command("reset-panel-access")
@click.option("--port", default=None, help="Specific port (e.g. 8080)")
@click.option("--path", default=None, help="Specific path (e.g. panel)")
@click.option("--random", "use_random", is_flag=True, help="Generate random high port and random secret path")
@click.option("--reset-2fa", is_flag=True, help="Disable 2FA if locked out")
@click.option("--password", default=None, help="Optional new password")
def reset_panel_access(port, path, use_random, reset_2fa, password):
    """Reset Web Panel port, path, 2FA and admin credentials."""
    async def _reset():
        await init_db()
        updates = {}
        if use_random:
            updates["panel_port"] = str(secrets.randbelow(40000) + 20000)
            updates["panel_secret_path"] = generate_secret_path()
            updates["decoy_enabled"] = "1"
            updates["decoy_theme"] = "nginx"
        else:
            updates["panel_port"] = str(port or "8080")
            updates["panel_secret_path"] = str(path or "panel").strip("/ ")
        
        if reset_2fa:
            updates["totp_enabled"] = "0"
            updates["totp_secret"] = ""
            updates["tg_2fa_enabled"] = "0"
            click.echo(click.style("✔ 2FA authentication disabled.", fg="yellow"))
        
        if password:
            updates["admin_password_hash"] = hash_password(password)
            click.echo(click.style("✔ Admin password updated.", fg="yellow"))

        await crud.set_settings(updates)
        run_systemctl("restart", "innerblitz.service")

        ip = await crud.get_setting("server_ip", "127.0.0.1")
        click.echo(click.style("✔ Web panel access successfully reset!", fg="green", bold=True))
        click.echo(f"Secret URL: http://{ip}:{updates['panel_port']}/{updates['panel_secret_path']}")
        click.echo(f"Port: {updates['panel_port']} | Path: /{updates['panel_secret_path']}")
        click.echo(click.style("✔ Service innerblitz.service restarted.", fg="green"))
    run_async(_reset())

@cli.command("reset-ports")
@click.option("--port", default=443, type=int, help="Hysteria 2 UDP port [default: 443]")
@click.option("--flush-hopping", is_flag=True, default=True, help="Flush port hopping iptables rules")
def reset_ports(port, flush_hopping):
    """Reset Hysteria 2 ports and flush port hopping firewall rules."""
    async def _reset_p():
        await init_db()
        if flush_hopping:
            flush_port_hopping()
            click.echo(click.style("✔ Port hopping iptables rules flushed.", fg="yellow"))
        
        await crud.set_settings({
            "listen_port": str(port),
            "port_hopping_enabled": "0"
        })
        await apply_and_save_config()
        ok, out = restart_hysteria()
        if ok:
            click.echo(click.style(f"✔ Hysteria 2 ports reset to UDP {port}. Core restarted.", fg="green"))
        else:
            click.echo(click.style(f"✖ Failed to restart Hysteria: {out}", fg="red"))
    run_async(_reset_p())

@cli.command("disable-2fa")
def disable_2fa():
    """Emergency disable 2FA (TOTP and Telegram) to regain panel access."""
    async def _dis():
        await init_db()
        await crud.set_settings({
            "totp_enabled": "0",
            "totp_secret": "",
            "tg_2fa_enabled": "0"
        })
        click.echo(click.style("✔ All 2FA protections disabled. You can now log in with password only.", fg="green", bold=True))
    run_async(_dis())

@cli.command("show-panel-url")
def show_panel_url():
    """Display current secret access URL for Web Panel."""
    async def _show():
        await init_db()
        ip = await crud.get_setting("server_ip", "127.0.0.1")
        port = await crud.get_setting("panel_port", "8080")
        path = await crud.get_setting("panel_secret_path", "panel")
        user = await crud.get_setting("admin_username", "admin")
        decoy_on = await crud.get_setting("decoy_enabled", "1") == "1"
        theme = await crud.get_setting("decoy_theme", "nginx")
        totp_on = await crud.get_setting("totp_enabled", "0") == "1"
        tg_on = await crud.get_setting("tg_2fa_enabled", "0") == "1"

        click.echo(click.style("\n=== InnerBlitz Stealth Panel Access ===", fg="cyan", bold=True))
        click.echo(f"Web Panel URL:  http://{ip}:{port}/{path}")
        click.echo(f"Secret Path:    /{path}")
        click.echo(f"Port:           {port}")
        click.echo(f"Decoy Root URL: http://{ip}:{port}/ (Статус: {'Активен' if decoy_on else 'Выключен'}, Тема: {theme})")
        click.echo(f"Admin Username: {user}")
        click.echo(f"2FA Status:     {'Google TOTP' if totp_on else ('Telegram' if tg_on else 'Disabled')}\n")
    run_async(_show())

@cli.command("toggle-decoy")
@click.option("--enable/--disable", default=True, help="Enable or disable decoy site on root /")
@click.option("--theme", default=None, help="Camouflage theme: nginx, innernode, docs, 404")
def toggle_decoy(enable, theme):
    """Enable or disable Anti-RKN decoy site on root URL /."""
    async def _decoy():
        await init_db()
        updates = {"decoy_enabled": "1" if enable else "0"}
        if theme:
            updates["decoy_theme"] = theme
        await crud.set_settings(updates)
        run_systemctl("restart", "innerblitz.service")
        click.echo(click.style(f"✔ Anti-RKN Decoy site {'enabled' if enable else 'disabled'} (Theme: {theme or 'unchanged'}).", fg="green"))
    run_async(_decoy())

@cli.command("optimize-bbr")
def optimize_bbr():
    """Enable Linux TCP BBR congestion control and optimize UDP buffers for max QUIC speed."""
    try:
        conf_content = """# InnerBlitz High-Performance Network Tuning for Hysteria 2 QUIC
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.optmem_max = 2048576
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
net.ipv4.ip_forward = 1
"""
        sysctl_dir = Path("/etc/sysctl.d")
        if sysctl_dir.exists():
            conf_file = sysctl_dir / "99-innerblitz.conf"
            with open(conf_file, "w") as f:
                f.write(conf_content)
            subprocess.run(["sysctl", "--system"], capture_output=True)
            click.echo(click.style("✔ TCP BBR and high-speed UDP buffers successfully applied!", fg="green", bold=True))
        else:
            click.echo(click.style("✖ /etc/sysctl.d not found (Not a standard Linux OS)", fg="yellow"))
    except Exception as e:
        click.echo(click.style(f"✖ Failed to configure sysctl: {e}", fg="red"))

@cli.command("backup")
@click.option("--out", default=None, help="Output backup archive path")
def backup_system(out):
    """Create a backup archive of SQLite DB and certificates."""
    try:
        data_dir = Path(settings.DATA_DIR)
        backup_dir = Path("/etc/hysteria/backups")
        backup_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_file = Path(out) if out else backup_dir / f"innerblitz_backup_{timestamp}.tar.gz"

        with tarfile.open(target_file, "w:gz") as tar:
            if data_dir.exists():
                tar.add(data_dir, arcname="data")
            if Path(settings.HYSTERIA_CONFIG_PATH).exists():
                tar.add(settings.HYSTERIA_CONFIG_PATH, arcname="config.yaml")

        click.echo(click.style(f"✔ Backup created successfully: {target_file}", fg="green", bold=True))
    except Exception as e:
        click.echo(click.style(f"✖ Backup failed: {e}", fg="red"))

@cli.command("restore")
@click.argument("backup_file")
def restore_system(backup_file):
    """Restore SQLite DB and certificates from backup archive."""
    try:
        b_path = Path(backup_file)
        if not b_path.exists():
            click.echo(click.style(f"✖ Backup file not found: {backup_file}", fg="red"))
            return
        
        run_systemctl("stop", "innerblitz.service")
        run_systemctl("stop", "hysteria-server.service")

        with tarfile.open(b_path, "r:gz") as tar:
            tar.extractall(path="/etc/hysteria")

        run_systemctl("start", "innerblitz.service")
        run_systemctl("start", "hysteria-server.service")
        click.echo(click.style(f"✔ System restored successfully from {backup_file}!", fg="green", bold=True))
    except Exception as e:
        click.echo(click.style(f"✖ Restore failed: {e}", fg="red"))

if __name__ == "__main__":
    cli()

