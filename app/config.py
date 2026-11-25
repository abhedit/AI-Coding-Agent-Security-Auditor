"""Runtime configuration, read from environment variables (12-factor)."""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field


def _bool(v: str | None, default: bool) -> bool:
    return default if v is None else v.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    brand_name: str = os.environ.get("BRAND_NAME", "AgentSentinel")
    brand_owner: str = os.environ.get("BRAND_OWNER", "Abhijit")
    brand_tagline: str = os.environ.get("BRAND_TAGLINE", "Security audits for AI coding agents")
    contact_email: str = os.environ.get("CONTACT_EMAIL", "hello@example.com")
    base_url: str = os.environ.get("BASE_URL", "http://localhost:8000").rstrip("/")
    database_url: str = os.environ.get("DATABASE_URL", "sqlite:///./data/agentsentinel.db")
    secret_key: str = os.environ.get("SECRET_KEY") or secrets.token_urlsafe(32)
    allow_signup: bool = _bool(os.environ.get("ALLOW_SIGNUP"), True)
    secure_cookies: bool = _bool(os.environ.get("SECURE_COOKIES"), False)
    admin_emails: frozenset[str] = field(default_factory=lambda: frozenset(
        e.strip().lower() for e in os.environ.get("ADMIN_EMAILS", "").split(",") if e.strip()))
    git_scan_enabled: bool = _bool(os.environ.get("GIT_SCAN_ENABLED"), True)
    git_allowed_hosts: frozenset[str] = field(default_factory=lambda: frozenset(
        h.strip().lower() for h in os.environ.get("GIT_ALLOWED_HOSTS", "github.com,gitlab.com,bitbucket.org").split(",") if h.strip()))
    max_upload_mb: int = int(os.environ.get("MAX_UPLOAD_MB", "25"))
    # Billing (Stripe). When unset, upgrades are handled manually by the operator via the admin panel.
    stripe_secret_key: str = os.environ.get("STRIPE_SECRET_KEY", "")
    stripe_webhook_secret: str = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    stripe_price_pro: str = os.environ.get("STRIPE_PRICE_PRO", "")
    stripe_price_team: str = os.environ.get("STRIPE_PRICE_TEAM", "")

    @property
    def billing_enabled(self) -> bool:
        return bool(self.stripe_secret_key and (self.stripe_price_pro or self.stripe_price_team))


settings = Settings()
