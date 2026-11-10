from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Optional, List, Literal, Union, Any, Dict
from datetime import datetime, date

class UserBase(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: Optional[str] = None
    traffic_limit_gb: float = Field(default=0, ge=0) # 0 = unlimited
    expiration_days: int = Field(default=30, ge=0) # 0 = unlimited
    unlimited_user: bool = False
    max_ips: int = Field(default=0, ge=0) # 0 = unlimited
    note: str = ""
    enable: bool = True
    total_bytes: Optional[int] = None
    total_gb: Optional[float] = None
    expiry_time: Optional[int] = None

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
    enable: Optional[bool] = None
    total_bytes: Optional[int] = None
    total_gb: Optional[float] = None
    expiry_time: Optional[int] = None

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
    
    # 3x-ui enhanced properties
    enable: bool = True
    total_bytes: int = 0
    expiry_time: int = 0
    is_active: bool = True
    is_quota_exceeded: bool = False
    used_traffic_bytes: int = 0
    percent_used: float = 0.0
    expiry_date_str: str = "Unlimited"
    online_status: bool = False
    current_ips: int = 0

    # Calculated properties
    is_expired: bool = False
    is_limit_reached: bool = False
    used_traffic_gb: float = 0.0
    max_traffic_gb: float = 0.0
    days_left: int = 0

# ==================== INBOUND & CLIENT MODELS (3x-ui) ====================

class InboundModel(BaseModel):
    id: Optional[int] = None
    tag: str = "Hysteria-Main"
    protocol: str = "hysteria2"
    listen_ip: str = "0.0.0.0"
    listen_port: int = 443
    port_hopping_enabled: bool = True
    port_hopping_range: str = "20000:50000"
    tls_type: str = "self_signed_ip"
    sni: str = "bing.com"
    cert_sha256: str = ""
    obfs_type: str = "salamander"
    obfs_password: str = ""
    masquerade_type: str = "proxy"
    masquerade_target: str = "https://bing.com"
    up_mbps: int = 200
    down_mbps: int = 200
    ignore_client_bandwidth: bool = False
    sniff_enabled: bool = True
    sniff_timeout: str = "2s"
    sniff_rewrite_domain: bool = True
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

class InboundCreate(BaseModel):
    tag: str = "Hysteria-Main"
    protocol: str = "hysteria2"
    listen_ip: str = "0.0.0.0"
    listen_port: int = 443
    port_hopping_enabled: bool = True
    port_hopping_range: str = "20000:50000"
    tls_type: str = "self_signed_ip"
    sni: str = "bing.com"
    cert_sha256: str = ""
    obfs_type: str = "salamander"
    obfs_password: str = ""
    masquerade_type: str = "proxy"
    masquerade_target: str = "https://bing.com"
    up_mbps: int = 200
    down_mbps: int = 200
    ignore_client_bandwidth: bool = False
    sniff_enabled: bool = True
    sniff_timeout: str = "2s"
    sniff_rewrite_domain: bool = True

class InboundUpdate(BaseModel):
    tag: Optional[str] = None
    protocol: Optional[str] = None
    listen_ip: Optional[str] = None
    listen_port: Optional[int] = None
    port_hopping_enabled: Optional[bool] = None
    port_hopping_range: Optional[str] = None
    tls_type: Optional[str] = None
    sni: Optional[str] = None
    cert_sha256: Optional[str] = None
    obfs_type: Optional[str] = None
    obfs_password: Optional[str] = None
    masquerade_type: Optional[str] = None
    masquerade_target: Optional[str] = None
    up_mbps: Optional[int] = None
    down_mbps: Optional[int] = None
    ignore_client_bandwidth: Optional[bool] = None
    sniff_enabled: Optional[bool] = None
    sniff_timeout: Optional[str] = None
    sniff_rewrite_domain: Optional[bool] = None

class ClientCreate(BaseModel):
    inbound_id: int = 1
    username: str = Field(..., min_length=1, max_length=64)
    password: Optional[str] = None
    enable: bool = True
    total_bytes: Optional[int] = None
    total_gb: Optional[float] = None
    traffic_limit_gb: Optional[float] = None  # backward compatibility alias
    expiry_time: Optional[int] = None  # epoch ms (0 = unlimited)
    expiration_days: Optional[int] = None  # backward compatibility alias
    unlimited_user: bool = False
    max_ips: int = Field(default=0, ge=0)
    note: str = ""

class ClientUpdate(BaseModel):
    password: Optional[str] = None
    enable: Optional[bool] = None
    total_bytes: Optional[int] = None
    total_gb: Optional[float] = None
    traffic_limit_gb: Optional[float] = None
    expiry_time: Optional[int] = None
    expiration_days: Optional[int] = None
    unlimited_user: Optional[bool] = None
    max_ips: Optional[int] = None
    note: Optional[str] = None
    inbound_id: Optional[int] = None
    blocked: Optional[bool] = None  # backward compatibility alias

class ClientOut(BaseModel):
    id: int
    inbound_id: int = 1
    username: str
    password: str
    enable: bool = True
    total_bytes: int = 0
    upload_bytes: int = 0
    download_bytes: int = 0
    expiry_time: int = 0
    max_ips: int = 0
    note: str = ""
    sub_token: str
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    # Calculated metrics
    used_traffic_bytes: int = 0
    used_traffic_gb: float = 0.0
    total_traffic_gb: float = 0.0
    percent_used: float = 0.0
    is_active: bool = True
    is_expired: bool = False
    is_quota_exceeded: bool = False
    days_left: int = 999
    expiry_date_str: str = "Unlimited"
    online_status: bool = False
    current_ips: int = 0

    # Backward compatibility aliases
    blocked: bool = False
    unlimited_user: bool = False
    max_download_bytes: int = 0
    max_traffic_gb: float = 0.0
    is_limit_reached: bool = False
    expiration_days: int = 30
    account_creation_date: str = ""

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
    routing_global_outbound: str = "direct"
    routing_ru: str = "direct"
    routing_openai: str = "warp"
    routing_discord: str = "warp"
    routing_youtube: str = "warp"
    routing_telegram: str = "direct"
    routing_netflix: str = "warp"
    routing_p2p: str = "block"
    routing_ads: str = "1"
    routing_win_spy: str = "1"

class RoutingSettingsModel(BaseModel):
    routing_global_outbound: str = "direct"
    routing_ru: str = "direct"
    routing_openai: str = "warp"
    routing_discord: str = "warp"
    routing_youtube: str = "warp"
    routing_telegram: str = "direct"
    routing_netflix: str = "warp"
    routing_p2p: str = "block"
    routing_ads: str = "1"
    routing_win_spy: str = "1"
    warp_enabled: Optional[bool] = None

# ==================== CUSTOM ROUTING RULE MODELS (Milestone M2) ====================

class RoutingRuleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    action: Literal["direct", "warp", "block"]
    rule_type: Literal["domain", "suffix", "keyword", "ip_cidr", "geoip", "geosite"]
    rule_values: Union[List[str], str] = Field(default_factory=list)
    priority: int = 100
    enabled: bool = True
    description: str = ""

    @field_validator("rule_values", mode="before")
    @classmethod
    def parse_rule_values(cls, v):
        if isinstance(v, str):
            return [x.strip() for x in v.replace("\n", ",").split(",") if x.strip()]
        if isinstance(v, list):
            res = []
            for item in v:
                if isinstance(item, str) and ("," in item or "\n" in item):
                    res.extend([x.strip() for x in item.replace("\n", ",").split(",") if x.strip()])
                elif isinstance(item, str):
                    s = item.strip()
                    if s:
                        res.append(s)
            return res
        return v

class RoutingRuleUpdate(BaseModel):
    name: Optional[str] = None
    action: Optional[Literal["direct", "warp", "block"]] = None
    rule_type: Optional[Literal["domain", "suffix", "keyword", "ip_cidr", "geoip", "geosite"]] = None
    rule_values: Optional[Union[List[str], str]] = None
    priority: Optional[int] = None
    enabled: Optional[bool] = None
    description: Optional[str] = None

    @field_validator("rule_values", mode="before")
    @classmethod
    def parse_rule_values_update(cls, v):
        if v is None:
            return None
        if isinstance(v, str):
            return [x.strip() for x in v.replace("\n", ",").split(",") if x.strip()]
        if isinstance(v, list):
            res = []
            for item in v:
                if isinstance(item, str) and ("," in item or "\n" in item):
                    res.extend([x.strip() for x in item.replace("\n", ",").split(",") if x.strip()])
                elif isinstance(item, str):
                    s = item.strip()
                    if s:
                        res.append(s)
            return res
        return v

class RoutingRuleOut(BaseModel):
    id: int
    name: str
    action: Literal["direct", "warp", "block"]
    rule_type: Literal["domain", "suffix", "keyword", "ip_cidr", "geoip", "geosite"]
    rule_values: List[str]
    priority: int
    enabled: bool
    description: str = ""
    created_at: str
    updated_at: str

class ReorderRulesRequest(BaseModel):
    rule_ids: Optional[List[int]] = None
    order: Optional[List[Any]] = None

    @model_validator(mode="before")
    @classmethod
    def populate_rule_ids(cls, data):
        if isinstance(data, dict):
            if not data.get("rule_ids"):
                if "order" in data and isinstance(data["order"], list):
                    extracted = []
                    for item in data["order"]:
                        if isinstance(item, dict) and "id" in item:
                            extracted.append(int(item["id"]))
                        elif isinstance(item, (int, str)):
                            extracted.append(int(item))
                    data["rule_ids"] = extracted
        return data

class ValidateRuleRequest(BaseModel):
    action: Optional[str] = None
    rule_type: Optional[str] = None
    rule_values: Optional[Union[List[str], str]] = None
    raw_rule: Optional[str] = None

    @field_validator("rule_values", mode="before")
    @classmethod
    def parse_validate_rule_values(cls, v):
        if v is None:
            return None
        if isinstance(v, str):
            return [x.strip() for x in v.replace("\n", ",").split(",") if x.strip()]
        if isinstance(v, list):
            res = []
            for item in v:
                if isinstance(item, str) and ("," in item or "\n" in item):
                    res.extend([x.strip() for x in item.replace("\n", ",").split(",") if x.strip()])
                elif isinstance(item, str):
                    s = item.strip()
                    if s:
                        res.append(s)
            return res
        return v



