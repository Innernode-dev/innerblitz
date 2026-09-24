#!/usr/bin/env python3
import asyncio
import sys
import click
from datetime import datetime, date

from app.config import settings
from app.database.connection import init_db
from app.database import crud
from app.database.models import UserCreate, UserUpdate
from app.core.cert import generate_self_signed_cert
from app.core.hysteria import (
    apply_and_save_config, restart_hysteria, 
    is_hysteria_running, get_hysteria_version, get_hysteria_logs
)
from app.core.subscription import build_hy2_uri
from app.core.security import hash_password

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

if __name__ == "__main__":
    cli()
