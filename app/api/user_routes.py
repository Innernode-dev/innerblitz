from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Dict, Any
import qrcode
import io
import base64

from app.api.auth_routes import get_current_admin
from app.database import crud
from app.database.models import UserCreate, UserUpdate
from app.core.subscription import build_hy2_uri, build_clash_yaml, build_singbox_json
from app.core.limiter import kick_users_api

router = APIRouter(prefix="/api/users", dependencies=[Depends(get_current_admin)])

@router.get("", response_model=List[Dict[str, Any]])
async def list_users():
    """Retrieve all users with calculated metrics."""
    return await crud.get_all_users()

@router.post("", status_code=status.HTTP_201_CREATED)
async def create_user(user: UserCreate):
    """Create a new proxy user."""
    existing = await crud.get_user_by_username(user.username)
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists")
    created = await crud.create_user(user)
    return created

@router.get("/{username}")
async def get_user(username: str):
    """Retrieve a single user."""
    user = await crud.get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user

@router.put("/{username}")
async def update_user(username: str, data: UserUpdate):
    """Update user attributes."""
    existing = await crud.get_user_by_username(username)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    updated = await crud.update_user(username, data)
    
    # If user was blocked, kick them immediately
    if data.blocked is True:
        await kick_users_api([username])
        
    return updated

@router.delete("/{username}")
async def delete_user(username: str):
    """Delete user and kick any active connections."""
    existing = await crud.get_user_by_username(username)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    await crud.delete_user(username)
    await kick_users_api([username])
    return {"ok": True, "message": f"User {username} deleted"}

@router.post("/{username}/reset")
async def reset_user(username: str):
    """Reset user's uploaded/downloaded bytes and creation date."""
    existing = await crud.get_user_by_username(username)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    await crud.reset_user_traffic(username)
    return {"ok": True, "message": f"User {username} traffic reset"}

@router.get("/{username}/config")
async def get_user_config(username: str):
    """Generate configuration payloads, URIs, and QR code for user."""
    user = await crud.get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    settings_dict = await crud.get_all_settings()
    uri = build_hy2_uri(user, settings_dict)

    # Generate QR Code image (PNG in base64)
    qr = qrcode.QRCode(box_size=8, border=2)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#000000", back_color="#ffffff")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    return {
        "username": username,
        "uri": uri,
        "qr_base64": f"data:image/png;base64,{qr_b64}",
        "sub_token": user.get("sub_token", ""),
        "clash_yaml": build_clash_yaml(user, settings_dict),
        "singbox_json": build_singbox_json(user, settings_dict)
    }
