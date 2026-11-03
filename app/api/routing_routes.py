import logging
import ipaddress
import re
from typing import List, Dict, Any, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, status
from app.api.auth_routes import get_current_admin
from app.database import crud
from app.database.models import (
    RoutingRuleCreate,
    RoutingRuleUpdate,
    RoutingRuleOut,
    ReorderRulesRequest,
    ValidateRuleRequest
)
from app.core.hysteria import apply_and_save_config, restart_hysteria

logger = logging.getLogger("innerblitz.routing_api")

router = APIRouter(prefix="/api/routing", tags=["Routing Rules"])

@router.get("/rules", response_model=List[RoutingRuleOut])
async def list_routing_rules(admin: str = Depends(get_current_admin)):
    """List all custom dynamic routing rules sorted by priority ASC, id ASC."""
    rules = await crud.get_routing_rules()
    return rules

@router.post("/rules", response_model=RoutingRuleOut, status_code=status.HTTP_201_CREATED)
async def create_new_routing_rule(
    payload: RoutingRuleCreate,
    admin: str = Depends(get_current_admin)
):
    """Create a new custom routing rule, persist to DB, and recompile Hysteria configuration."""
    if not payload.name or not payload.name.strip():
        raise HTTPException(status_code=400, detail="Rule name cannot be empty")
    if not payload.rule_values:
        raise HTTPException(status_code=400, detail="rule_values list cannot be empty")

    created = await crud.create_routing_rule(payload)
    # Recompile Hysteria 2 configuration atomically
    apply_res = await apply_and_save_config()
    if apply_res.success:
        restart_hysteria()
    else:
        logger.warning(f"Notice: recompiled config with newly added rule had warning: {apply_res.message}")

    return created

@router.get("/rules/{rule_id}", response_model=RoutingRuleOut)
async def get_single_routing_rule(
    rule_id: int,
    admin: str = Depends(get_current_admin)
):
    """Retrieve details of a single custom routing rule."""
    rule = await crud.get_routing_rule_by_id(rule_id)
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Routing rule {rule_id} not found")
    return rule

@router.put("/rules/{rule_id}", response_model=RoutingRuleOut)
async def update_single_routing_rule(
    rule_id: int,
    payload: RoutingRuleUpdate,
    admin: str = Depends(get_current_admin)
):
    """Update fields of an existing routing rule and recompile configuration."""
    existing = await crud.get_routing_rule_by_id(rule_id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Routing rule {rule_id} not found")

    updated = await crud.update_routing_rule(rule_id, payload)
    apply_res = await apply_and_save_config()
    if apply_res.success:
        restart_hysteria()

    return updated

@router.delete("/rules/{rule_id}")
async def delete_single_routing_rule(
    rule_id: int,
    admin: str = Depends(get_current_admin)
):
    """Delete a custom routing rule and recompile configuration."""
    existing = await crud.get_routing_rule_by_id(rule_id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Routing rule {rule_id} not found")

    deleted = await crud.delete_routing_rule(rule_id)
    if not deleted:
        raise HTTPException(status_code=500, detail="Failed to delete routing rule")

    apply_res = await apply_and_save_config()
    if apply_res.success:
        restart_hysteria()

    return {"ok": True, "message": f"Rule {rule_id} deleted successfully"}

@router.post("/rules/reorder")
async def reorder_rules(
    payload: ReorderRulesRequest,
    admin: str = Depends(get_current_admin)
):
    """Reorder custom routing rules by setting sequential priorities."""
    items = payload.order if payload.order is not None else payload.rule_ids
    if not items:
        raise HTTPException(status_code=400, detail="rule_ids or order cannot be empty")

    success = await crud.reorder_routing_rules(items)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to reorder rules")

    apply_res = await apply_and_save_config()
    if apply_res.success:
        restart_hysteria()

    return {"ok": True, "message": "Rules reordered successfully"}

@router.post("/rules/{rule_id}/toggle", response_model=RoutingRuleOut)
@router.put("/rules/{rule_id}/toggle", response_model=RoutingRuleOut)
async def toggle_rule_enabled(
    rule_id: int,
    admin: str = Depends(get_current_admin)
):
    """Toggle enable/disable status of a routing rule."""
    existing = await crud.get_routing_rule_by_id(rule_id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Routing rule {rule_id} not found")

    toggled = await crud.toggle_routing_rule(rule_id)
    apply_res = await apply_and_save_config()
    if apply_res.success:
        restart_hysteria()

    return toggled

def _validate_single_value(rule_type: str, val: str) -> Tuple[bool, str]:
    """Validate a single pattern value against its rule_type."""
    val = val.strip()
    if not val:
        return False, "Value cannot be empty"

    if rule_type == "ip_cidr":
        # Check IP address or CIDR network
        clean = val.replace("cidr:", "").strip()
        try:
            if "/" in clean:
                ipaddress.ip_network(clean, strict=False)
            else:
                ipaddress.ip_address(clean)
            return True, "Valid IP/CIDR"
        except ValueError:
            return False, f"Invalid IP address or CIDR notation: '{val}'"

    elif rule_type == "geoip":
        clean = val.replace("geoip:", "").strip()
        if not (2 <= len(clean) <= 6 and clean.isalnum()):
            return False, f"Invalid GeoIP country code: '{clean}'"
        return True, "Valid GeoIP"

    elif rule_type in ("domain", "suffix"):
        clean = val.replace("domain:", "").replace("suffix:", "").replace("domain-suffix:", "").strip()
        if not clean or " " in clean:
            return False, f"Invalid domain: '{val}'"
        return True, "Valid domain"

    elif rule_type == "geosite":
        clean = val.replace("geosite:", "").strip()
        if not clean or " " in clean:
            return False, f"Invalid geosite: '{val}'"
        return True, "Valid geosite"

    elif rule_type == "keyword":
        clean = val.strip("*").replace("keyword:", "").replace("domain-keyword:", "").strip()
        if not clean:
            return False, f"Invalid keyword pattern: '{val}'"
        return True, "Valid keyword"

    return True, "Valid"

@router.post("/validate")
async def validate_routing_rule(
    payload: Dict[str, Any],
    admin: str = Depends(get_current_admin)
):
    """
    Validate routing rule syntax and parameters without saving.
    Accepts structured fields (action, rule_type, rule_values) or raw rule string (rule).
    """
    # 1. Check raw rule string format e.g. "direct(domain:example.com)"
    raw_rule = payload.get("raw_rule") or payload.get("rule") or payload.get("content")
    if raw_rule and isinstance(raw_rule, str):
        rule_str = raw_rule.strip()
        m = re.match(r"^([a-zA-Z0-9_\-]+)\((.+)\)$", rule_str)
        if not m:
            return {"ok": False, "valid": False, "message": f"Malformed ACL syntax: '{rule_str}'. Expected format: action(matcher)"}
        act, body = m.group(1).lower(), m.group(2).strip()
        if act not in ("direct", "warp", "reject", "block", "outbound"):
            return {"ok": False, "valid": False, "message": f"Unsupported ACL action '{act}'"}
        if not body:
            return {"ok": False, "valid": False, "message": "ACL rule matcher cannot be empty"}
        return {"ok": True, "valid": True, "message": "Rule syntax is valid"}

    # 2. Structured rule validation
    action = str(payload.get("action", "") or "").strip().lower()
    rule_type = str(payload.get("rule_type", "") or "").strip().lower()
    rule_values = payload.get("rule_values")

    if not action:
        return {"ok": False, "valid": False, "message": "Field 'action' is required"}
    if action not in ("direct", "warp", "block"):
        return {"ok": False, "valid": False, "message": f"Invalid action '{action}'. Must be 'direct', 'warp', or 'block'"}

    if not rule_type:
        return {"ok": False, "valid": False, "message": "Field 'rule_type' is required"}
    valid_types = ("domain", "suffix", "keyword", "ip_cidr", "geoip", "geosite")
    if rule_type not in valid_types:
        return {"ok": False, "valid": False, "message": f"Invalid rule_type '{rule_type}'. Must be one of: {', '.join(valid_types)}"}

    if rule_values is None:
        return {"ok": False, "valid": False, "message": "Field 'rule_values' is required"}
    if isinstance(rule_values, str):
        rule_values = [v.strip() for v in rule_values.split(",") if v.strip()]
    if not isinstance(rule_values, list) or len(rule_values) == 0:
        return {"ok": False, "valid": False, "message": "Field 'rule_values' must be a non-empty list of strings"}

    for val in rule_values:
        is_ok, err = _validate_single_value(rule_type, str(val))
        if not is_ok:
            return {"ok": False, "valid": False, "message": err}

    return {"ok": True, "valid": True, "message": "Rule syntax and values are valid"}
