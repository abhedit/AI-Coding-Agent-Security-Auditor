"""Public REST API (v1), authenticated by organisation API keys."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from auditor import __version__
from auditor.models import SourceFile, Severity
from auditor.sarif import to_sarif
from auditor.scanner import ScanResult, rule_catalog
from auditor.models import Finding

from .config import settings
from .db import Organization, Project, Scan, get_db, scans_this_month
from .deps import api_org
from .plans import get_plan
from . import services

router = APIRouter(prefix="/api/v1", tags=["api"])


class ScanIn(BaseModel):
    files: dict[str, str] = Field(..., description="Map of repo-relative path -> file content")
    project: str | None = None
    source: str = "api"
    ref: str = ""


class GitScanIn(BaseModel):
    url: str
    project: str | None = None


def _scan_out(scan: Scan) -> dict:
    return {
        "id": scan.public_id, "project": scan.project.name, "created_at": scan.created_at.isoformat() + "Z",
        "score": scan.score, "grade": scan.grade, "source": scan.source, "ref": scan.source_ref,
        "report_url": f"{settings.base_url}/scans/{scan.public_id}", **{k: v for k, v in scan.result.items() if k != "score"},
    }


def _guard(fn):
    try:
        return fn()
    except services.QuotaError as e:
        raise HTTPException(402, str(e))
    except services.SourceError as e:
        raise HTTPException(400, str(e))


@router.get("/health")
def health():
    return {"status": "ok", "engine": __version__}


@router.get("/rules")
def rules():
    return rule_catalog()


@router.post("/scans")
def create_scan(body: ScanIn, org: Organization = Depends(api_org), db: Session = Depends(get_db)):
    if len(body.files) > 2000 or sum(len(v) for v in body.files.values()) > settings.max_upload_mb * 1024 * 1024:
        raise HTTPException(413, "Payload too large")
    source = body.source if body.source in {"api", "cli", "action"} else "api"

    def go():
        proj = services.get_or_create_project(db, org, body.project)
        return services.run_and_store(db, org, proj, body.files, source, body.ref)
    return _scan_out(_guard(go))


@router.post("/scans/git")
def create_git_scan(body: GitScanIn, org: Organization = Depends(api_org), db: Session = Depends(get_db)):
    def go():
        url = services.validate_git_url(body.url)
        services.check_quota(db, org)
        files = services.files_from_git(url)
        proj = services.get_or_create_project(db, org, body.project, url)
        return services.run_and_store(db, org, proj, files, "git", url)
    return _scan_out(_guard(go))


def _own_scan(db, org, sid) -> Scan:
    scan = db.scalar(select(Scan).where(Scan.public_id == sid, Scan.org_id == org.id))
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@router.get("/scans")
def list_scans(limit: int = 20, org: Organization = Depends(api_org), db: Session = Depends(get_db)):
    rows = db.scalars(select(Scan).where(Scan.org_id == org.id).order_by(Scan.id.desc()).limit(min(limit, 100)))
    return [{"id": s.public_id, "project": s.project.name, "score": s.score, "grade": s.grade,
             "created_at": s.created_at.isoformat() + "Z"} for s in rows]


@router.get("/scans/{sid}")
def get_scan(sid: str, org: Organization = Depends(api_org), db: Session = Depends(get_db)):
    return _scan_out(_own_scan(db, org, sid))


@router.get("/scans/{sid}/sarif")
def get_sarif(sid: str, org: Organization = Depends(api_org), db: Session = Depends(get_db)):
    if not get_plan(org.plan).sarif:
        raise HTTPException(402, "SARIF export requires the Pro plan or above")
    return JSONResponse(to_sarif(result_from_json(_own_scan(db, org, sid).result), version=__version__, info_uri=settings.base_url))


@router.get("/usage")
def usage(org: Organization = Depends(api_org), db: Session = Depends(get_db)):
    plan = get_plan(org.plan)
    return {"plan": plan.id, "scans_this_month": scans_this_month(db, org.id), "scan_limit": plan.scans_per_month,
            "projects": db.query(Project).filter(Project.org_id == org.id).count(), "project_limit": plan.projects}


def result_from_json(d: dict) -> ScanResult:
    files = [SourceFile(f["path"], f["kind"], f["agent"], "") for f in d.get("files_scanned", [])]
    findings = [Finding(**{**f, "severity": Severity(f["severity"])}) for f in d.get("findings", [])]
    return ScanResult(files, findings, d.get("duration_ms", 0), d.get("errors", []))
