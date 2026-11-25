"""Web application: marketing site, dashboard, reports, billing, admin."""
from __future__ import annotations

import json
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from auditor import __version__
from auditor.rules import RULES
from auditor.sarif import to_sarif
from auditor.scanner import rule_catalog

from . import billing, services
from .api import result_from_json, router as api_router
from .config import settings
from .db import ApiKey, AuditEvent, Organization, Project, Scan, User, audit, get_db, init_db, scans_this_month, utcnow
from .deps import LoginRequired, admin_user, current_user, current_user_optional
from .plans import PLANS, get_plan
from .security import check_csrf, csrf_token, hash_password, new_api_key, verify_password

BASE = Path(__file__).parent


@asynccontextmanager
async def lifespan(_app):
    init_db()
    yield


app = FastAPI(lifespan=lifespan, title=f"{settings.brand_name} API", version=__version__, docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json")
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key, same_site="lax", https_only=settings.secure_cookies,
                   max_age=14 * 24 * 3600, session_cookie="ags_session")
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
app.include_router(api_router)
templates = Jinja2Templates(directory=BASE / "templates")
templates.env.globals.update(brand=settings, plans=PLANS, version=__version__)

SEV_ORDER = ["critical", "high", "medium", "low", "info"]


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    if not request.url.path.startswith("/api/docs"):
        resp.headers.setdefault("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'")
    return resp


@app.exception_handler(LoginRequired)
async def _login_required(request: Request, exc):
    return RedirectResponse(f"/login?next={request.url.path}", 303)


def render(request: Request, name: str, user: User | None = None, status: int = 200, **ctx):
    ctx.update(request=request, user=user, csrf=csrf_token(request.session), flash=request.session.pop("flash", None))
    return templates.TemplateResponse(request, name, ctx, status_code=status)


def flash(request: Request, msg: str, kind: str = "ok"):
    request.session["flash"] = {"msg": msg, "kind": kind}


def require_csrf(request: Request, token: str | None):
    if not check_csrf(request.session, token):
        raise HTTPException(400, "Invalid form token - reload the page and try again")


def safe_next(nxt: str | None) -> str:
    return nxt if nxt and nxt.startswith("/") and not nxt.startswith("//") else "/dashboard"


# ---------------------------------------------------------------- public pages
@app.get("/", response_class=HTMLResponse)
def landing(request: Request, user=Depends(current_user_optional)):
    cats = sorted({r.category for r in RULES.values()})
    return render(request, "landing.html", user, rule_count=len(RULES), categories=cats)


@app.get("/pricing", response_class=HTMLResponse)
def pricing(request: Request, user=Depends(current_user_optional)):
    return render(request, "pricing.html", user)


@app.get("/rules", response_class=HTMLResponse)
def rules_page(request: Request, user=Depends(current_user_optional)):
    return render(request, "rules.html", user, rules=rule_catalog())


@app.get("/docs", response_class=HTMLResponse)
def docs_page(request: Request, user=Depends(current_user_optional)):
    return render(request, "docs.html", user)


@app.post("/try", response_class=HTMLResponse)
def try_scan(request: Request, filename: str = Form(...), content: str = Form(...), csrf: str = Form(None), user=Depends(current_user_optional)):
    """Anonymous single-file scan from the landing page (not stored)."""
    require_csrf(request, csrf)
    from auditor.scanner import scan_mapping
    if len(content) > 200_000:
        raise HTTPException(413, "File too large for the free try-it scanner")
    result = scan_mapping({filename.strip(): content})
    return render(request, "try_result.html", user, filename=filename, result=result.to_dict(), recognised=bool(result.files))


# ---------------------------------------------------------------- auth
@app.get("/signup", response_class=HTMLResponse)
def signup_form(request: Request, plan: str = "free", user=Depends(current_user_optional)):
    return render(request, "signup.html", user, plan=plan)


@app.post("/signup")
def signup(request: Request, name: str = Form(...), email: str = Form(...), password: str = Form(...), company: str = Form(""),
           csrf: str = Form(None), db: Session = Depends(get_db)):
    require_csrf(request, csrf)
    if not settings.allow_signup:
        raise HTTPException(403, "Sign-ups are currently closed")
    email = email.strip().lower()
    if "@" not in email or len(password) < 10:
        flash(request, "Use a valid email and a password of at least 10 characters.", "err")
        return RedirectResponse("/signup", 303)
    if db.scalar(select(User).where(User.email == email)):
        flash(request, "An account with that email already exists.", "err")
        return RedirectResponse("/login", 303)
    org = Organization(name=(company or f"{name}'s workspace").strip()[:120])
    db.add(org)
    db.flush()
    is_first = db.scalar(select(func.count(User.id))) == 0
    user = User(email=email, name=name.strip()[:120], password_hash=hash_password(password), org_id=org.id, role="owner",
                is_admin=is_first or email in settings.admin_emails)
    db.add(user)
    db.flush()
    audit(db, "user.signup", org.id, user.id)
    db.commit()
    request.session.clear()
    request.session["uid"] = user.id
    flash(request, f"Welcome to {settings.brand_name}! Run your first scan below.")
    return RedirectResponse("/scans/new", 303)


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request, next: str = "/dashboard", user=Depends(current_user_optional)):
    return render(request, "login.html", user, next=safe_next(next))


@app.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...), next: str = Form("/dashboard"),
          csrf: str = Form(None), db: Session = Depends(get_db)):
    require_csrf(request, csrf)
    user = db.scalar(select(User).where(User.email == email.strip().lower()))
    if not user or not verify_password(password, user.password_hash):
        flash(request, "Invalid email or password.", "err")
        return RedirectResponse("/login", 303)
    request.session.clear()
    request.session["uid"] = user.id
    audit(db, "user.login", user.org_id, user.id)
    db.commit()
    return RedirectResponse(safe_next(next), 303)


@app.post("/logout")
def logout(request: Request, csrf: str = Form(None)):
    require_csrf(request, csrf)
    request.session.clear()
    return RedirectResponse("/", 303)


# ---------------------------------------------------------------- dashboard
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    org = user.org
    projects = db.scalars(select(Project).where(Project.org_id == org.id).order_by(Project.name)).all()
    recent = db.scalars(select(Scan).where(Scan.org_id == org.id).order_by(Scan.id.desc()).limit(10)).all()
    latest = {p.id: (p.scans[0] if p.scans else None) for p in projects}
    open_counts = {s: sum(getattr(latest[p.id], s) for p in projects if latest[p.id]) for s in SEV_ORDER}
    scores = [latest[p.id].score for p in projects if latest[p.id]]
    plan = get_plan(org.plan)
    return render(request, "dashboard.html", user, org=org, plan=plan, projects=projects, latest=latest, recent=recent,
                  used=scans_this_month(db, org.id), open_counts=open_counts,
                  avg_score=round(sum(scores) / len(scores)) if scores else None)


@app.get("/scans/new", response_class=HTMLResponse)
def new_scan_form(request: Request, project: str = "", user: User = Depends(current_user), db: Session = Depends(get_db)):
    projects = db.scalars(select(Project).where(Project.org_id == user.org_id).order_by(Project.name)).all()
    return render(request, "new_scan.html", user, projects=projects, project=project, plan=get_plan(user.org.plan),
                  used=scans_this_month(db, user.org_id))


@app.post("/scans/new")
async def new_scan(request: Request, mode: str = Form(...), project: str = Form(""), git_url: str = Form(""),
                   filename: str = Form(""), content: str = Form(""), archive: UploadFile | None = File(None),
                   csrf: str = Form(None), user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_csrf(request, csrf)
    org = user.org
    try:
        services.check_quota(db, org)
        if mode == "git":
            url = services.validate_git_url(git_url)
            files = services.files_from_git(url)
            proj = services.get_or_create_project(db, org, project, url)
            scan = services.run_and_store(db, org, proj, files, "git", url)
        elif mode == "upload":
            if archive is None or not archive.filename:
                raise services.SourceError("Choose a .zip file to upload")
            data = await archive.read(settings.max_upload_mb * 1024 * 1024 + 1)
            if len(data) > settings.max_upload_mb * 1024 * 1024:
                raise services.SourceError(f"Upload exceeds {settings.max_upload_mb} MB")
            files = services.files_from_zip(data)
            proj = services.get_or_create_project(db, org, project or archive.filename.rsplit(".", 1)[0])
            scan = services.run_and_store(db, org, proj, files, "upload", archive.filename)
        elif mode == "paste":
            if not filename.strip() or not content.strip():
                raise services.SourceError("Provide a file name (e.g. .mcp.json or CLAUDE.md) and its content")
            proj = services.get_or_create_project(db, org, project)
            scan = services.run_and_store(db, org, proj, {filename.strip(): content}, "paste", filename.strip())
        else:
            raise services.SourceError("Unknown scan mode")
    except (services.SourceError, services.QuotaError) as e:
        db.rollback()
        flash(request, str(e), "err")
        return RedirectResponse("/scans/new", 303)
    audit(db, "scan.create", org.id, user.id, scan=scan.public_id, source=scan.source)
    db.commit()
    return RedirectResponse(f"/scans/{scan.public_id}", 303)


def _org_scan(db, user, sid) -> Scan:
    scan = db.scalar(select(Scan).where(Scan.public_id == sid, Scan.org_id == user.org_id))
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@app.get("/scans/{sid}", response_class=HTMLResponse)
def scan_report(request: Request, sid: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    scan = _org_scan(db, user, sid)
    prev = db.scalar(select(Scan).where(Scan.project_id == scan.project_id, Scan.id < scan.id).order_by(Scan.id.desc()))
    findings = scan.result.get("findings", [])
    by_cat: dict[str, int] = {}
    for f in findings:
        by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1
    rules_hit = {f["rule_id"]: RULES[f["rule_id"]] for f in findings if f["rule_id"] in RULES}
    return render(request, "report.html", user, scan=scan, prev=prev, findings=findings, by_cat=sorted(by_cat.items(), key=lambda x: -x[1]),
                  rules_hit=rules_hit, sev_order=SEV_ORDER, plan=get_plan(user.org.plan))


@app.get("/scans/{sid}/report.json")
def scan_json(sid: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    scan = _org_scan(db, user, sid)
    return JSONResponse(scan.result, headers={"Content-Disposition": f'attachment; filename="scan-{sid}.json"'})


@app.get("/scans/{sid}/report.sarif")
def scan_sarif(sid: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not get_plan(user.org.plan).sarif:
        raise HTTPException(402, "SARIF export requires the Pro plan or above")
    scan = _org_scan(db, user, sid)
    return JSONResponse(to_sarif(result_from_json(scan.result), version=__version__, info_uri=settings.base_url),
                        headers={"Content-Disposition": f'attachment; filename="scan-{sid}.sarif"'})


@app.get("/projects/{pid}", response_class=HTMLResponse)
def project_page(request: Request, pid: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    proj = db.scalar(select(Project).where(Project.public_id == pid, Project.org_id == user.org_id))
    if not proj:
        raise HTTPException(404)
    history_days = get_plan(user.org.plan).history_days
    cutoff = utcnow() - timedelta(days=history_days)
    scans = [s for s in proj.scans if s.created_at >= cutoff]
    trend = list(reversed(scans[:30]))
    return render(request, "project.html", user, project=proj, scans=scans, trend=trend, plan=get_plan(user.org.plan),
                  rules=sorted(RULES))


@app.post("/projects/{pid}")
def project_update(request: Request, pid: str, disabled_rules: str = Form(""), badge_public: str = Form(""),
                   csrf: str = Form(None), user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_csrf(request, csrf)
    proj = db.scalar(select(Project).where(Project.public_id == pid, Project.org_id == user.org_id))
    if not proj:
        raise HTTPException(404)
    proj.disabled_rules = ",".join(r for r in (x.strip() for x in disabled_rules.replace("\n", ",").split(",")) if r in RULES)
    proj.badge_public = bool(badge_public) and get_plan(user.org.plan).badges
    audit(db, "project.update", user.org_id, user.id, project=proj.public_id)
    db.commit()
    flash(request, "Project settings saved.")
    return RedirectResponse(f"/projects/{pid}", 303)


@app.post("/projects/{pid}/delete")
def project_delete(request: Request, pid: str, csrf: str = Form(None), user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_csrf(request, csrf)
    proj = db.scalar(select(Project).where(Project.public_id == pid, Project.org_id == user.org_id))
    if not proj or user.role != "owner":
        raise HTTPException(404)
    db.delete(proj)
    audit(db, "project.delete", user.org_id, user.id, project=pid)
    db.commit()
    flash(request, "Project deleted.")
    return RedirectResponse("/dashboard", 303)


@app.get("/badge/{pid}.svg")
def badge(pid: str, db: Session = Depends(get_db)):
    proj = db.scalar(select(Project).where(Project.public_id == pid))
    if not proj or not proj.badge_public or not proj.scans:
        label, value, color = "agent security", "unknown", "#9f9f9f"
    else:
        s = proj.scans[0]
        value = f"{s.grade} ({s.score})"
        color = {"A": "#2ea44f", "B": "#7cb342", "C": "#f9a825", "D": "#fb8c00", "F": "#e53935"}[s.grade]
        label = "agent security"
    lw, vw = 6 * len(label) + 12, 7 * len(value) + 12
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{lw+vw}" height="20" role="img" aria-label="{label}: {value}">
<rect width="{lw}" height="20" fill="#555"/><rect x="{lw}" width="{vw}" height="20" fill="{color}"/>
<g fill="#fff" text-anchor="middle" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">
<text x="{lw/2}" y="14">{label}</text><text x="{lw+vw/2}" y="14">{value}</text></g></svg>'''
    return Response(svg, media_type="image/svg+xml", headers={"Cache-Control": "max-age=300"})


# ---------------------------------------------------------------- settings / API keys
@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    keys = db.scalars(select(ApiKey).where(ApiKey.org_id == user.org_id).order_by(ApiKey.id.desc())).all()
    members = db.scalars(select(User).where(User.org_id == user.org_id)).all()
    events = db.scalars(select(AuditEvent).where(AuditEvent.org_id == user.org_id).order_by(AuditEvent.id.desc()).limit(25)).all()
    new_key = request.session.pop("new_key", None)
    return render(request, "settings.html", user, keys=keys, members=members, events=events, new_key=new_key, plan=get_plan(user.org.plan))


@app.post("/settings/keys")
def create_key(request: Request, name: str = Form("CI key"), csrf: str = Form(None), user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_csrf(request, csrf)
    raw, prefix, h = new_api_key()
    db.add(ApiKey(org_id=user.org_id, name=name.strip()[:120] or "API key", prefix=prefix, key_hash=h))
    audit(db, "apikey.create", user.org_id, user.id, prefix=prefix)
    db.commit()
    request.session["new_key"] = raw
    return RedirectResponse("/settings", 303)


@app.post("/settings/keys/{kid}/revoke")
def revoke_key(request: Request, kid: int, csrf: str = Form(None), user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_csrf(request, csrf)
    key = db.get(ApiKey, kid)
    if not key or key.org_id != user.org_id:
        raise HTTPException(404)
    key.revoked = True
    audit(db, "apikey.revoke", user.org_id, user.id, prefix=key.prefix)
    db.commit()
    flash(request, f"Key {key.prefix}… revoked.")
    return RedirectResponse("/settings", 303)


@app.post("/settings/members")
def add_member(request: Request, email: str = Form(...), name: str = Form(""), password: str = Form(...), csrf: str = Form(None),
               user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_csrf(request, csrf)
    if user.role != "owner":
        raise HTTPException(403)
    plan = get_plan(user.org.plan)
    count = db.scalar(select(func.count(User.id)).where(User.org_id == user.org_id))
    email = email.strip().lower()
    if count >= plan.members:
        flash(request, f"Your {plan.name} plan includes {plan.members} member(s). Upgrade to add more.", "err")
    elif db.scalar(select(User).where(User.email == email)) or "@" not in email or len(password) < 10:
        flash(request, "That email is in use or invalid, or the password is shorter than 10 characters.", "err")
    else:
        db.add(User(email=email, name=name.strip(), password_hash=hash_password(password), org_id=user.org_id, role="member"))
        audit(db, "member.add", user.org_id, user.id, email=email)
        db.commit()
        flash(request, f"{email} added. Share the temporary password with them securely.")
    return RedirectResponse("/settings", 303)


# ---------------------------------------------------------------- billing
@app.get("/billing", response_class=HTMLResponse)
def billing_page(request: Request, success: int = 0, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if success:
        flash(request, "Payment received - your plan will update within a few seconds.")
    return render(request, "billing.html", user, org=user.org, plan=get_plan(user.org.plan), used=scans_this_month(db, user.org_id))


@app.post("/billing/checkout")
def checkout(request: Request, plan: str = Form(...), csrf: str = Form(None), user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_csrf(request, csrf)
    if plan not in {"pro", "team"}:
        raise HTTPException(400)
    if not settings.billing_enabled or not billing.price_for(plan):
        audit(db, "billing.upgrade_request", user.org_id, user.id, plan=plan)
        db.commit()
        flash(request, f"Thanks! Your upgrade request to {PLANS[plan].name} was sent. {settings.brand_owner} will contact you at {user.email}.")
        return RedirectResponse("/billing", 303)
    return RedirectResponse(billing.create_checkout(user.org_id, plan, user.email, user.org.stripe_customer_id), 303)


@app.post("/billing/portal")
def portal(request: Request, csrf: str = Form(None), user: User = Depends(current_user)):
    require_csrf(request, csrf)
    if not (settings.billing_enabled and user.org.stripe_customer_id):
        raise HTTPException(400, "No billing account")
    return RedirectResponse(billing.create_portal(user.org.stripe_customer_id), 303)


@app.post("/billing/webhook")
async def stripe_webhook(request: Request, db: Session = Depends(get_db)):
    payload = await request.body()
    if not settings.stripe_webhook_secret or not billing.verify_webhook(payload, request.headers.get("stripe-signature", ""), settings.stripe_webhook_secret):
        raise HTTPException(400, "bad signature")
    event = json.loads(payload)
    obj = event.get("data", {}).get("object", {})
    meta = obj.get("metadata") or {}
    org = db.get(Organization, int(meta["org_id"])) if meta.get("org_id", "").isdigit() else None
    if org:
        if event["type"] == "checkout.session.completed" and meta.get("plan") in PLANS:
            org.plan = meta["plan"]
            org.stripe_customer_id = obj.get("customer") or org.stripe_customer_id
            org.stripe_subscription_id = obj.get("subscription") or org.stripe_subscription_id
        elif event["type"] == "customer.subscription.deleted":
            org.plan = "free"
        elif event["type"] == "customer.subscription.updated" and meta.get("plan") in PLANS and obj.get("status") in {"active", "trialing"}:
            org.plan = meta["plan"]
        audit(db, f"billing.{event['type']}", org.id, plan=org.plan)
        db.commit()
    return {"received": True}


# ---------------------------------------------------------------- operator admin
@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request, user: User = Depends(admin_user), db: Session = Depends(get_db)):
    orgs = db.scalars(select(Organization).order_by(Organization.id.desc())).all()
    stats = {
        "orgs": len(orgs),
        "users": db.scalar(select(func.count(User.id))),
        "scans": db.scalar(select(func.count(Scan.id))),
        "mrr": sum(PLANS[o.plan].price_month or 0 for o in orgs if o.plan in PLANS),
    }
    usage = {o.id: scans_this_month(db, o.id) for o in orgs}
    owners = {u.org_id: u.email for u in db.scalars(select(User).where(User.role == "owner"))}
    requests_ = db.scalars(select(AuditEvent).where(AuditEvent.action == "billing.upgrade_request").order_by(AuditEvent.id.desc()).limit(20)).all()
    return render(request, "admin.html", user, orgs=orgs, stats=stats, usage=usage, owners=owners, upgrade_requests=requests_)


@app.post("/admin/orgs/{oid}/plan")
def admin_set_plan(request: Request, oid: int, plan: str = Form(...), csrf: str = Form(None), user: User = Depends(admin_user), db: Session = Depends(get_db)):
    require_csrf(request, csrf)
    org = db.get(Organization, oid)
    if not org or plan not in PLANS:
        raise HTTPException(404)
    org.plan = plan
    audit(db, "admin.set_plan", org.id, user.id, plan=plan)
    db.commit()
    flash(request, f"{org.name} is now on {PLANS[plan].name}.")
    return RedirectResponse("/admin", 303)
