"""Database models (SQLAlchemy 2.0). SQLite by default; set DATABASE_URL for Postgres."""
from __future__ import annotations

import json
import os
import secrets
from datetime import datetime, timezone

from sqlalchemy import (JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, create_engine, func, select)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from .config import settings


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def public_id() -> str:
    return secrets.token_urlsafe(9)


class Base(DeclarativeBase):
    pass


class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    plan: Mapped[str] = mapped_column(String(20), default="free")
    stripe_customer_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    stripe_subscription_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    users: Mapped[list["User"]] = relationship(back_populates="org")
    projects: Mapped[list["Project"]] = relationship(back_populates="org", cascade="all, delete-orphan")


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(120), default="")
    password_hash: Mapped[str] = mapped_column(String(255))
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    role: Mapped[str] = mapped_column(String(20), default="owner")  # owner | member
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    org: Mapped[Organization] = relationship(back_populates="users")


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[int] = mapped_column(primary_key=True)
    public_id: Mapped[str] = mapped_column(String(20), unique=True, default=public_id)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    repo_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    badge_public: Mapped[bool] = mapped_column(Boolean, default=False)
    disabled_rules: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    org: Mapped[Organization] = relationship(back_populates="projects")
    scans: Mapped[list["Scan"]] = relationship(back_populates="project", cascade="all, delete-orphan", order_by="Scan.id.desc()")

    @property
    def disabled_set(self) -> set[str]:
        return {r.strip() for r in self.disabled_rules.replace("\n", ",").split(",") if r.strip()}


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    public_id: Mapped[str] = mapped_column(String(20), unique=True, default=public_id)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    source: Mapped[str] = mapped_column(String(20))  # upload | paste | git | api | cli | action
    source_ref: Mapped[str] = mapped_column(String(500), default="")
    score: Mapped[int] = mapped_column(Integer)
    grade: Mapped[str] = mapped_column(String(2))
    critical: Mapped[int] = mapped_column(Integer, default=0)
    high: Mapped[int] = mapped_column(Integer, default=0)
    medium: Mapped[int] = mapped_column(Integer, default=0)
    low: Mapped[int] = mapped_column(Integer, default=0)
    info: Mapped[int] = mapped_column(Integer, default=0)
    files_scanned: Mapped[int] = mapped_column(Integer, default=0)
    result: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    project: Mapped[Project] = relationship(back_populates="scans")

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info


class ApiKey(Base):
    __tablename__ = "api_keys"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    prefix: Mapped[str] = mapped_column(String(16), index=True)
    key_hash: Mapped[str] = mapped_column(String(128), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), index=True, nullable=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(64))
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


def _make_engine(url: str):
    if url.startswith("sqlite:///"):
        path = url.removeprefix("sqlite:///")
        if path not in (":memory:", ""):
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        return create_engine(url, connect_args={"check_same_thread": False})
    return create_engine(url, pool_pre_ping=True)


engine = _make_engine(settings.database_url)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def init_db() -> None:
    Base.metadata.create_all(engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def scans_this_month(db, org_id: int) -> int:
    now = utcnow()
    start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return db.scalar(select(func.count(Scan.id)).where(Scan.org_id == org_id, Scan.created_at >= start)) or 0


def audit(db, action: str, org_id: int | None = None, user_id: int | None = None, **detail) -> None:
    db.add(AuditEvent(org_id=org_id, user_id=user_id, action=action, detail=json.dumps(detail) if detail else ""))
