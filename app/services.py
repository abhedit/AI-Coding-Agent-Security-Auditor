"""Business logic: ingesting sources, enforcing quotas, persisting scans."""
from __future__ import annotations

import io
import os
import re
import subprocess
import tempfile
import zipfile
from urllib.parse import urlparse

from sqlalchemy import select

from auditor import discovery
from auditor.scanner import scan_files

from .config import settings
from .db import Organization, Project, Scan, scans_this_month
from .plans import get_plan


class QuotaError(Exception):
    pass


class SourceError(Exception):
    pass


MAX_ZIP_ENTRIES = 20000
MAX_TOTAL_UNCOMPRESSED = 200 * 1024 * 1024


def files_from_zip(data: bytes) -> dict[str, str]:
    """Read only agent-config files from a zip - nothing is ever extracted to disk."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as e:
        raise SourceError("Not a valid .zip archive") from e
    infos = zf.infolist()
    if len(infos) > MAX_ZIP_ENTRIES:
        raise SourceError("Archive has too many entries")
    names = [i.filename for i in infos if not i.is_dir()]
    # GitHub "Download ZIP" wraps everything in <repo>-<branch>/ - strip a common top folder
    prefix = ""
    tops = {n.split("/", 1)[0] for n in names if "/" in n}
    if len(tops) == 1 and all("/" in n for n in names):
        prefix = tops.pop() + "/"
    out: dict[str, str] = {}
    total = 0
    for info in infos:
        if info.is_dir():
            continue
        rel = info.filename[len(prefix):] if prefix and info.filename.startswith(prefix) else info.filename
        if ".." in rel.split("/") or rel.startswith("/"):
            continue
        if any(part in discovery.SKIP_DIRS for part in rel.split("/")[:-1]):
            continue
        if discovery.classify(rel) is None:
            continue
        if info.file_size > discovery.MAX_FILE_BYTES:
            continue
        total += info.file_size
        if total > MAX_TOTAL_UNCOMPRESSED:
            raise SourceError("Archive too large")
        out[rel] = zf.read(info).decode("utf-8", errors="replace")
    return out


GIT_URL = re.compile(r"^https://[A-Za-z0-9.\-]+/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+(\.git)?/?$")


def validate_git_url(url: str) -> str:
    url = url.strip()
    if not GIT_URL.match(url):
        raise SourceError("Use a public HTTPS repository URL like https://github.com/owner/repo")
    host = (urlparse(url).hostname or "").lower()
    if host not in settings.git_allowed_hosts:
        raise SourceError(f"Host '{host}' is not allowed. Allowed: {', '.join(sorted(settings.git_allowed_hosts))}")
    return url.rstrip("/")


def files_from_git(url: str, timeout: int = 90) -> dict[str, str]:
    if not settings.git_scan_enabled:
        raise SourceError("Git scanning is disabled on this server")
    url = validate_git_url(url)
    with tempfile.TemporaryDirectory(prefix="ags-") as tmp:
        dest = os.path.join(tmp, "repo")
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/bin/false", "GIT_CONFIG_NOSYSTEM": "1",
               "GIT_LFS_SKIP_SMUDGE": "1", "HOME": tmp}
        cmd = ["git", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always", "-c", "core.hooksPath=/dev/null",
               "-c", "core.symlinks=false", "clone", "--depth", "1", "--single-branch", "--no-tags",
               "--filter=blob:limit=1m", "--", url, dest]
        try:
            proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            raise SourceError("Clone timed out") from e
        except FileNotFoundError as e:
            raise SourceError("git is not installed on the server") from e
        if proc.returncode != 0:
            raise SourceError("Could not clone repository (is it public?)")
        return {sf.path: sf.content for sf in discovery.discover(dest)}


def check_quota(db, org: Organization) -> None:
    plan = get_plan(org.plan)
    used = scans_this_month(db, org.id)
    if used >= plan.scans_per_month:
        raise QuotaError(f"Monthly scan limit reached ({plan.scans_per_month} on the {plan.name} plan). Upgrade to keep scanning.")


def get_or_create_project(db, org: Organization, name: str | None, repo_url: str | None = None) -> Project:
    name = (name or "").strip()[:120] or (repo_url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git") if repo_url else "default")
    proj = db.scalar(select(Project).where(Project.org_id == org.id, Project.name == name))
    if proj:
        return proj
    plan = get_plan(org.plan)
    count = db.query(Project).filter(Project.org_id == org.id).count()
    if count >= plan.projects:
        raise QuotaError(f"Project limit reached ({plan.projects} on the {plan.name} plan).")
    proj = Project(org_id=org.id, name=name, repo_url=repo_url)
    db.add(proj)
    db.flush()
    return proj


def run_and_store(db, org: Organization, project: Project, files: dict[str, str], source: str, source_ref: str = "") -> Scan:
    check_quota(db, org)
    result = scan_files(discovery.from_mapping(files), project.disabled_set)
    c = result.counts
    scan = Scan(org_id=org.id, project_id=project.id, source=source, source_ref=source_ref[:500],
                score=result.score, grade=result.grade, critical=c["critical"], high=c["high"], medium=c["medium"],
                low=c["low"], info=c["info"], files_scanned=len(result.files), result=result.to_dict())
    db.add(scan)
    db.commit()
    return scan
