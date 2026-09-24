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
    
    yield
    
    # Shutdown
    logger.info("Shutting down InnerBlitz services...")
    traffic_collector.stop()
    limiter_daemon.stop()
    tg_bot.stop()
    for task in [traffic_task, limiter_task, bot_task]:
        task.cancel()

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="Next-Gen High-Performance Management Panel for Hysteria 2",
    lifespan=lifespan
)

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
        return templates.TemplateResponse("decoy.html", {"request": request})
        
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

    if secret_path != expected_secret and secret_path != "panel":
        if decoy_enabled:
            return templates.TemplateResponse("decoy.html", {"request": request})
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")

    user = await check_auth_or_redirect(request)
    if user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("login.html", {"request": request})

if __name__ == "__main__":
    import uvicorn
    import asyncio

    async def get_configured_port() -> int:
        await init_db()
        p = await crud.get_setting("panel_port", "")
        return int(p) if p and p.isdigit() else settings.PANEL_PORT

    listen_port = asyncio.run(get_configured_port())
    uvicorn.run(
        "app.main:app",
        host=settings.PANEL_HOST,
        port=listen_port,
        reload=False
    )
