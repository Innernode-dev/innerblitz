from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, date

class UserBase(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: Optional[str] = None
    traffic_limit_gb: float = Field(default=0, ge=0) # 0 = unlimited
    expiration_days: int = Field(default=30, ge=0) # 0 = unlimited
    unlimited_user: bool = False
    max_ips: int = Field(default=0, ge=0) # 0 = unlimited
    note: str = ""

class UserCreate(UserBase):
    pass

class UserUpdate(BaseModel):
    password: Optional[str] = None
    traffic_limit_gb: Optional[float] = None
    expiration_days: Optional[int] = None
    account_creation_date: Optional[str] = None
    blocked: Optional[bool] = None
    unlimited_user: Optional[bool] = None
    max_ips: Optional[int] = None
    note: Optional[str] = None

class UserOut(BaseModel):
    id: int
    username: str
    password: str
    max_download_bytes: int
    upload_bytes: int
    download_bytes: int
    expiration_days: int
    account_creation_date: str
    blocked: bool
    unlimited_user: bool
    max_ips: int
    note: str
    sub_token: str
    
    # Calculated properties
    is_expired: bool = False
    is_limit_reached: bool = False
    used_traffic_gb: float = 0.0
    max_traffic_gb: float = 0.0
    days_left: int = 0

class LoginRequest(BaseModel):
    username: str
    password: str
    totp_code: Optional[str] = None
    tg_code: Optional[str] = None

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str

class HysteriaSettingsModel(BaseModel):
    server_ip: Optional[str] = None
    server_domain: Optional[str] = None
    listen_port: int = 443
    port_hopping_enabled: bool = True
    port_hopping_range: str = "20000:50000"
    tls_type: str = "self_signed_ip" # self_signed_ip, acme, custom
    obfs_type: str = "salamander" # salamander, none
    obfs_password: str = ""
    mimic_enabled: bool = False
    masquerade_type: str = "proxy" # proxy, file, string
    masquerade_target: str = "https://bing.com"
    up_mbps: str = "200"
    down_mbps: str = "200"
    ignore_client_bandwidth: bool = False
    preset: str = "anti-dpi"
