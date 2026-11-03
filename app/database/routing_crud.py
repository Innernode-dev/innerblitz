import aiosqlite
import json
import logging
from datetime import datetime
from typing import List, Optional, Dict, Any, Union

from app.database.connection import get_db_connection
from app.database.models import RoutingRuleCreate, RoutingRuleUpdate

logger = logging.getLogger("innerblitz.routing_crud")

def _format_rule_row(row: aiosqlite.Row) -> Dict[str, Any]:
    """Convert an aiosqlite Row from routing_rules into a normalized dict."""
    data = dict(row)
    raw_vals = data.get("rule_values", "[]")
    if isinstance(raw_vals, str):
        try:
            parsed = json.loads(raw_vals)
            data["rule_values"] = parsed if isinstance(parsed, list) else [str(parsed)]
        except Exception:
            data["rule_values"] = [raw_vals] if raw_vals else []
    elif isinstance(raw_vals, list):
        data["rule_values"] = raw_vals
    else:
        data["rule_values"] = []

    data["enabled"] = bool(data.get("enabled", 1))
    data["priority"] = int(data.get("priority", 100))
    data["description"] = str(data.get("description") or "")
    data["created_at"] = str(data.get("created_at") or datetime.utcnow().isoformat())
    data["updated_at"] = str(data.get("updated_at") or datetime.utcnow().isoformat())
    return data

async def get_routing_rules(enabled_only: bool = False) -> List[Dict[str, Any]]:
    """Retrieve all routing rules sorted by priority ASC, id ASC."""
    db = await get_db_connection()
    try:
        if enabled_only:
            cursor = await db.execute("SELECT * FROM routing_rules WHERE enabled = 1 ORDER BY priority ASC, id ASC;")
        else:
            cursor = await db.execute("SELECT * FROM routing_rules ORDER BY priority ASC, id ASC;")
        rows = await cursor.fetchall()
        return [_format_rule_row(r) for r in rows]
    finally:
        await db.close()

async def get_routing_rule_by_id(rule_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve single routing rule by ID or None."""
    db = await get_db_connection()
    try:
        cursor = await db.execute("SELECT * FROM routing_rules WHERE id = ?;", (rule_id,))
        row = await cursor.fetchone()
        if not row:
            return None
        return _format_rule_row(row)
    finally:
        await db.close()

async def create_routing_rule(rule: RoutingRuleCreate) -> Dict[str, Any]:
    """Create a new routing rule and return the created record."""
    db = await get_db_connection()
    try:
        values_json = json.dumps(rule.rule_values)
        enabled_int = 1 if rule.enabled else 0
        now_str = datetime.utcnow().isoformat()
        cursor = await db.execute("""
            INSERT INTO routing_rules (
                name, action, rule_type, rule_values, priority, enabled, description, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            rule.name,
            rule.action,
            rule.rule_type,
            values_json,
            rule.priority,
            enabled_int,
            rule.description,
            now_str,
            now_str
        ))
        await db.commit()
        rule_id = cursor.lastrowid
        res = await get_routing_rule_by_id(rule_id)
        if not res:
            raise RuntimeError(f"Failed to fetch newly created rule {rule_id}")
        return res
    finally:
        await db.close()

async def update_routing_rule(rule_id: int, update_data: RoutingRuleUpdate) -> Optional[Dict[str, Any]]:
    """Update fields of an existing routing rule."""
    db = await get_db_connection()
    try:
        existing = await get_routing_rule_by_id(rule_id)
        if not existing:
            return None

        fields = []
        values = []
        dump = update_data.model_dump(exclude_unset=True) if hasattr(update_data, "model_dump") else update_data.dict(exclude_unset=True)

        for k, v in dump.items():
            if v is None:
                continue
            if k == "rule_values":
                fields.append("rule_values = ?")
                values.append(json.dumps(v))
            elif k == "enabled":
                fields.append("enabled = ?")
                values.append(1 if v else 0)
            elif k in ("name", "action", "rule_type", "priority", "description"):
                fields.append(f"{k} = ?")
                values.append(v)

        if fields:
            fields.append("updated_at = ?")
            values.append(datetime.utcnow().isoformat())
            values.append(rule_id)
            sql = f"UPDATE routing_rules SET {', '.join(fields)} WHERE id = ?;"
            await db.execute(sql, values)
            await db.commit()

        return await get_routing_rule_by_id(rule_id)
    finally:
        await db.close()

async def delete_routing_rule(rule_id: int) -> bool:
    """Delete routing rule by ID. Returns True if a record was removed."""
    db = await get_db_connection()
    try:
        cursor = await db.execute("DELETE FROM routing_rules WHERE id = ?;", (rule_id,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()

async def toggle_routing_rule(rule_id: int) -> Optional[Dict[str, Any]]:
    """Toggle enabled flag of a routing rule."""
    db = await get_db_connection()
    try:
        existing = await get_routing_rule_by_id(rule_id)
        if not existing:
            return None
        new_enabled = 0 if existing["enabled"] else 1
        now_str = datetime.utcnow().isoformat()
        await db.execute("""
            UPDATE routing_rules
            SET enabled = ?, updated_at = ?
            WHERE id = ?;
        """, (new_enabled, now_str, rule_id))
        await db.commit()
        return await get_routing_rule_by_id(rule_id)
    finally:
        await db.close()

async def reorder_routing_rules(rule_items: Union[List[int], List[Dict[str, Any]], List[Any]]) -> bool:
    """Reorder rules sequentially or by explicit priority."""
    db = await get_db_connection()
    try:
        now_str = datetime.utcnow().isoformat()
        for idx, item in enumerate(rule_items):
            if isinstance(item, dict) and "id" in item:
                rid = int(item["id"])
                prio = int(item.get("priority", (idx + 1) * 10))
            elif isinstance(item, (tuple, list)) and len(item) == 2:
                rid, prio = int(item[0]), int(item[1])
            else:
                rid = int(item)
                prio = (idx + 1) * 10

            await db.execute("""
                UPDATE routing_rules
                SET priority = ?, updated_at = ?
                WHERE id = ?;
            """, (prio, now_str, rid))
        await db.commit()
        return True
    finally:
        await db.close()
