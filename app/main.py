import asyncio
import logging
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import settings
from app.database.connection import init_db
from app.database import crud
from app.core.traffic import traffic_collector
from app.core.limiter import limiter_daemon
from app.bot.bot import tg_bot
from app.core.hysteria import apply_and_save_config

# Import routers
from app.api.auth_routes import router as auth_router, get_current_admin
from app.api.user_routes import router as user_router
from app.api.settings_routes import router as settings_router
from app.api.sub_routes import router as sub_router
from app.api.system_routes import router as system_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("innerblitz")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Initializing InnerBlitz Database and Services...")
    await init_db()
    
    # Ensure Hysteria config exists on disk
    if not Path(settings.HYSTERIA_CONFIG_PATH).exists():
        await apply_and_save_config()

    # Start background daemons
    traffic_task = asyncio.create_task(traffic_collector.start_loop(interval_seconds=4))
    limiter_task = asyncio.create_task(limiter_daemon.start_loop(interval_seconds=15))
    bot_task = asyncio.create_task(tg_bot.start_polling())

    async def cert_auto_renew_loop():
        while True:
            try:
                await asyncio.sleep(3600)  # Check every hour
                ssl_mode = await crud.get_setting("panel_ssl_mode", "http")
                if ssl_mode == "self_signed_ip":
                    server_ip = await crud.get_setting("server_ip", "127.0.0.1")
                    from app.core.cert import check_and_renew_panel_cert
                    renewed = check_and_renew_panel_cert(server_ip, min_days_left=1.0)
                    if renewed:
                        logger.info("[SSL] 6-day IP certificate auto-renewed! Triggering panel restart...")
                        import subprocess
                        subprocess.Popen(["systemctl", "restart", "innerblitz.service"])
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[SSL Auto-Renew] Daemon error: {e}")

    cert_task = asyncio.create_task(cert_auto_renew_loop())
    
    yield
    
    # Shutdown
    logger.info("Shutting down InnerBlitz services...")
    traffic_collector.stop()
    limiter_daemon.stop()
    tg_bot.stop()
    for task in [traffic_task, limiter_task, bot_task, cert_task]:
        task.cancel()

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="Next-Gen High-Performance Management Panel for Hysteria 2",
    lifespan=lifespan
)

# Anti-scan camouflage middleware (masks Python/Uvicorn signatures to look like Nginx)
@app.middleware("http")
async def anti_scan_camouflage_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["Server"] = "nginx/1.24.0 (Ubuntu)"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

# Ensure static folder exists
static_dir = Path(__file__).parent / "static"
static_dir.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

templates_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))

# Include API and Subscription Routers
app.include_router(auth_router)
app.include_router(user_router)
app.include_router(settings_router)
app.include_router(sub_router)
app.include_router(system_router)

# ==================== PAGE VIEW ROUTES ====================

async def check_auth_or_redirect(request: Request):
    """Helper to redirect unauthenticated browser users to /login."""
    session_id = request.cookies.get(settings.COOKIE_NAME)
    if not session_id:
        return None
    session = await crud.get_session(session_id)
    return session["username"] if session else None

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    user = await check_auth_or_redirect(request)
    if user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

    expected_secret = await crud.get_setting("panel_secret_path", "panel")
    decoy_enabled = await crud.get_setting("decoy_enabled", "1") == "1"

    # If a custom secret path is active, hide the login page on standard /login to prevent discovery
    if expected_secret not in ("login", "panel"):
        if decoy_enabled:
            theme = await crud.get_setting("decoy_theme", "innernode")
            status_code = 404 if theme == "404" else 200
            return templates.TemplateResponse("decoy.html", {"request": request, "theme": theme}, status_code=status_code)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")

    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/", response_class=HTMLResponse)
async def root_page(request: Request):
    user = await check_auth_or_redirect(request)
    decoy_enabled = await crud.get_setting("decoy_enabled", "1") == "1"
    
    # If admin is logged in, show dashboard
    if user:
        return templates.TemplateResponse("index.html", {"request": request, "user": user})
    
    # If unauthenticated and decoy enabled, render fake open-source cloud node page (anti-RKN)
    if decoy_enabled:
        theme = await crud.get_setting("decoy_theme", "innernode")
        status_code = 404 if theme == "404" else 200
        return templates.TemplateResponse("decoy.html", {"request": request, "theme": theme}, status_code=status_code)
        
    return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

@app.get("/users", response_class=HTMLResponse)
async def users_page(request: Request):
    user = await check_auth_or_redirect(request)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("users.html", {"request": request, "user": user})

@app.get("/node", response_class=HTMLResponse)
async def node_page(request: Request):
    user = await check_auth_or_redirect(request)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("node.html", {"request": request, "user": user})

@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    user = await check_auth_or_redirect(request)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("settings.html", {"request": request, "user": user})

@app.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request):
    user = await check_auth_or_redirect(request)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("logs.html", {"request": request, "user": user})

@app.get("/{secret_path}", response_class=HTMLResponse)
async def secret_path_entry(secret_path: str, request: Request):
    expected_secret = await crud.get_setting("panel_secret_path", "panel")
    decoy_enabled = await crud.get_setting("decoy_enabled", "1") == "1"

    if secret_path != expected_secret:
        if decoy_enabled:
            theme = await crud.get_setting("decoy_theme", "innernode")
            status_code = 404 if theme == "404" else 200
            return templates.TemplateResponse("decoy.html", {"request": request, "theme": theme}, status_code=status_code)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")

    user = await check_auth_or_redirect(request)
    if user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("login.html", {"request": request})

@app.exception_handler(404)
async def custom_404_handler(request: Request, exc):
    """Mask scanner 404 probes with decoy template."""
    decoy_enabled = await crud.get_setting("decoy_enabled", "1") == "1"
    if decoy_enabled:
        theme = await crud.get_setting("decoy_theme", "innernode")
        status_code = 404 if theme == "404" else 200
        return templates.TemplateResponse("decoy.html", {"request": request, "theme": theme}, status_code=status_code)
    return HTMLResponse("<html><body><h1>404 Not Found</h1><hr><address>nginx/1.24.0 (Ubuntu)</address></body></html>", status_code=404)

if __name__ == "__main__":
    import os
    import uvicorn
    import asyncio

    async def get_launch_config():
        await init_db()
        p = await crud.get_setting("panel_port", "")
        port = int(p) if p and p.isdigit() else settings.PANEL_PORT
        ssl_mode = await crud.get_setting("panel_ssl_mode", "http")
        server_ip = await crud.get_setting("server_ip", "127.0.0.1")
        
        cert_file = await crud.get_setting("panel_cert_path", settings.PANEL_CERT_PATH)
        key_file = await crud.get_setting("panel_key_path", settings.PANEL_KEY_PATH)

        # In self-signed IP mode, ensure 6-day cert exists and is valid
        if ssl_mode == "self_signed_ip":
            if not os.path.exists(cert_file) or not os.path.exists(key_file):
                from app.core.cert import generate_panel_cert
                generate_panel_cert(server_ip, valid_days=6)

        return port, ssl_mode, cert_file, key_file

    listen_port, ssl_mode, cert_file, key_file = asyncio.run(get_launch_config())
    
    use_ssl = (
        ssl_mode in ("self_signed_ip", "domain", "https")
        and os.path.exists(cert_file)
        and os.path.exists(key_file)
    )

    kwargs = {
        "app": "app.main:app",
        "host": settings.PANEL_HOST,
        "port": listen_port,
        "server_header": False,
        "reload": False,
    }
    if use_ssl:
        kwargs["ssl_certfile"] = cert_file
        kwargs["ssl_keyfile"] = key_file

    uvicorn.run(**kwargs)
