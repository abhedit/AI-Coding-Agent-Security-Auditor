from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import ApiKey, Organization, User, get_db, utcnow
from .security import hash_api_key


class LoginRequired(Exception):
    pass


def current_user_optional(request: Request, db: Session = Depends(get_db)) -> User | None:
    uid = request.session.get("uid")
    if not uid:
        return None
    return db.get(User, uid)


def current_user(user: User | None = Depends(current_user_optional)) -> User:
    if user is None:
        raise LoginRequired()
    return user


def admin_user(user: User = Depends(current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(403, "Admins only")
    return user


def api_org(request: Request, db: Session = Depends(get_db)) -> Organization:
    auth = request.headers.get("authorization", "")
    raw = auth[7:].strip() if auth.lower().startswith("bearer ") else request.headers.get("x-api-key", "").strip()
    if not raw:
        raise HTTPException(401, "Missing API key. Send 'Authorization: Bearer ags_...'")
    key = db.scalar(select(ApiKey).where(ApiKey.key_hash == hash_api_key(raw), ApiKey.revoked.is_(False)))
    if key is None:
        raise HTTPException(401, "Invalid or revoked API key")
    key.last_used_at = utcnow()
    db.commit()
    return db.get(Organization, key.org_id)
