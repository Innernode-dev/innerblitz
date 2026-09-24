import os
from pathlib import Path
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str = "InnerBlitz"
    VERSION: str = "2.0.0"
    REPO_URL: str = "https://github.com/Innernode-dev/innerblitz"
    
    # Base paths
    BASE_DIR: str = os.getenv("INNERBLITZ_DIR", "/etc/hysteria")
    
    @property
    def DATA_DIR(self) -> Path:
        path = Path(self.BASE_DIR)
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def DB_PATH(self) -> str:
        return str(self.DATA_DIR / "innerblitz.db")

    @property
    def HYSTERIA_CONFIG_PATH(self) -> str:
        return str(self.DATA_DIR / "config.yaml")

    @property
    def CERT_PATH(self) -> str:
        return str(self.DATA_DIR / "server.crt")

    @property
    def KEY_PATH(self) -> str:
        return str(self.DATA_DIR / "server.key")

    @property
    def PANEL_CERT_PATH(self) -> str:
        return str(self.DATA_DIR / "panel.crt")

    @property
    def PANEL_KEY_PATH(self) -> str:
        return str(self.DATA_DIR / "panel.key")

    @property
    def GEOIP_PATH(self) -> str:
        return str(self.DATA_DIR / "geoip.dat")

    @property
    def GEOSITE_PATH(self) -> str:
        return str(self.DATA_DIR / "geosite.dat")

    # Web Panel settings
    PANEL_HOST: str = os.getenv("PANEL_HOST", "0.0.0.0")
    PANEL_PORT: int = int(os.getenv("PANEL_PORT", 8080))
    SECRET_KEY: str = os.getenv("SECRET_KEY", "innerblitz-secure-random-default-secret-key-321")
    COOKIE_NAME: str = "innerblitz_session"
    SESSION_EXPIRE_HOURS: int = 168 # 7 days
    
    # Internal Hysteria 2 Ports
    HYSTERIA_TRAFFIC_STATS_PORT: int = 25413
    HYSTERIA_AUTH_PORT: int = 28262

    # Rate Limiting
    MAX_LOGIN_ATTEMPTS: int = 5
    LOGIN_COOLDOWN_SECONDS: int = 60

settings = Settings()
