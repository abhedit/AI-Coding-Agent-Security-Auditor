"""Minimal Stripe integration over HTTPS (no SDK dependency).

If STRIPE_* env vars are not configured, the platform runs in "manual billing" mode:
customers request an upgrade and the operator flips the plan in /admin.
"""
from __future__ import annotations

import hashlib
import hmac
import time

import httpx

from .config import settings

API = "https://api.stripe.com/v1"


def price_for(plan: str) -> str:
    return {"pro": settings.stripe_price_pro, "team": settings.stripe_price_team}.get(plan, "")


def create_checkout(org_id: int, plan: str, email: str, customer_id: str | None) -> str:
    data = {
        "mode": "subscription",
        "line_items[0][price]": price_for(plan),
        "line_items[0][quantity]": "1",
        "success_url": f"{settings.base_url}/billing?success=1",
        "cancel_url": f"{settings.base_url}/billing?canceled=1",
        "client_reference_id": str(org_id),
        "metadata[org_id]": str(org_id),
        "metadata[plan]": plan,
        "subscription_data[metadata][org_id]": str(org_id),
        "subscription_data[metadata][plan]": plan,
        "allow_promotion_codes": "true",
    }
    if customer_id:
        data["customer"] = customer_id
    else:
        data["customer_email"] = email
    r = httpx.post(f"{API}/checkout/sessions", data=data, auth=(settings.stripe_secret_key, ""), timeout=20)
    r.raise_for_status()
    return r.json()["url"]


def create_portal(customer_id: str) -> str:
    r = httpx.post(f"{API}/billing_portal/sessions", data={"customer": customer_id, "return_url": f"{settings.base_url}/billing"},
                   auth=(settings.stripe_secret_key, ""), timeout=20)
    r.raise_for_status()
    return r.json()["url"]


def verify_webhook(payload: bytes, sig_header: str, secret: str, tolerance: int = 300) -> bool:
    try:
        parts = dict(p.split("=", 1) for p in sig_header.split(","))
        ts = int(parts["t"])
        sigs = [v for k, v in (p.split("=", 1) for p in sig_header.split(",")) if k == "v1"]
    except (KeyError, ValueError):
        return False
    if abs(time.time() - ts) > tolerance:
        return False
    expected = hmac.new(secret.encode(), f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected, s) for s in sigs)
