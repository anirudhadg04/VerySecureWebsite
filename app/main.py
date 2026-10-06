"""Main FastAPI application for the VerySecureWebsite security lab.

Entry point: uvicorn app.main:app
Configurable to run in vulnerable or secured mode per lab module.
"""

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import func
from contextlib import asynccontextmanager
import uvicorn
from datetime import datetime, timezone

from .database import get_db, engine
from .models import (
    User, Record, AuditLog, OperatorProfile, LabProgress, Achievement,
    DailyContract, UserSettings, XPAwardLog, ACHIEVEMENTS,
)
from .config import settings
from . import auth

# Create all tables on import (for lab simplicity)
from . import init_db


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Create missing tables and apply only additive compatibility migrations.
    init_db.init_db()
    yield

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="VerySecureWebsite - AI-assisted application security research lab",
    lifespan=lifespan,
)
app.include_router(auth.router)
app.middleware("http")(auth.csrf_middleware)

# Mount static files and templates
app.mount("/static", StaticFiles(directory="app/templates/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

# ────────────────────────────────────────────────────────────────────
# Dependency: Get current user from session cookie
# ──────────────────────────────────────────────────────────────────
def get_current_user(request: Request, db=Depends(get_db)):
    """Resolve only a valid, revocable browser session."""
    return auth.get_current_user(request, db)


# Record Routes (BOLA/IDOR target)
# ────────────────────────────────────────────────────────────────────
@app.get("/records", response_model=list)
def list_records(
    db=Depends(get_db),
    current_user=Depends(get_current_user),
):
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    """List all records.

    Vulnerable version: No ownership validation - returns ALL records.
    Secured version: Only returns records owned by the current user.
    """
    records = db.query(Record).all()
    return [
        {"id": r.id, "title": r.title, "content": r.content,
         "owner": r.owner.username if r.owner else None}
        for r in records
    ]


@app.post("/records")
def create_record(
    title: str,
    content: str = "",
    db=Depends(get_db),
    current_user=Depends(get_current_user),
):
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    """Create a new record owned by the current user."""
    from .models import Record

    record = Record(
        title=title,
        content=content,
        owner_id=current_user.id,  # Always assign ownership to current user
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    return {"id": record.id, "title": record.title, "content": record.content, "owner": current_user.username}


@app.get("/records/{record_id}")
def get_record(
    record_id: int,
    db=Depends(get_db),
    current_user=Depends(get_current_user),
):
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    """Get a specific record.

    Vulnerable version: No ownership check - BOLA/IDOR vulnerability.
    Any authenticated user can access any record ID.
    """
    record = db.query(Record).filter(Record.id == record_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")
    if current_user:
        db.add(AuditLog(user_id=current_user.id, action=f"record_access:{record_id}", path=f"/records/{record_id}", success=True, record_owner_id=record.owner_id))
        db.commit()
    return {
        "id": record.id,
        "title": record.title,
        "content": record.content,
        "owner": record.owner.username if record.owner else None,
    }


@app.put("/records/{record_id}")
def update_record(
    record_id: int,
    title: str = "",
    content: str = "",
    db=Depends(get_db),
    current_user=Depends(get_current_user),
):
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    """Update a record.

    Vulnerable version: No ownership validation - BOLA/IDOR.
    """
    record = db.query(Record).filter(Record.id == record_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")

    # Vulnerable: no ownership check
    if title:
        record.title = title
    if content:
        record.content = content
    db.commit()

    return {"id": record.id, "title": record.title, "content": record.content}


@app.delete("/records/{record_id}")
def delete_record(
    record_id: int,
    db=Depends(get_db),
    current_user=Depends(get_current_user),
):
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    """Delete a record.

    Vulnerable version: No ownership validation - BOLA/IDOR.
    """
    record = db.query(Record).filter(Record.id == record_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")

    # Vulnerable: no ownership check
    db.delete(record)
    db.commit()

    return {"detail": "Record deleted"}


# ────────────────────────────────────────────────────────────────────
# Admin Routes (BFLA target)
# ────────────────────────────────────────────────────────────────────
@app.get("/admin/users")
def list_users(
    db=Depends(get_db),
    current_user=Depends(get_current_user),
):
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    """List all users.

    Vulnerable version: Regular users can access this endpoint (BFLA).
    Secured version: Only users with role='admin' can access.
    """
    if current_user and current_user.role != "admin":
        db.add(AuditLog(user_id=current_user.id, action="admin_access", path="/admin/users", success=True))
        db.commit()
    users = db.query(User).all()
    return [
        {"id": u.id, "username": u.username, "email": u.email, "role": u.role}
        for u in users
    ]


@app.get("/admin/debug")
def debug_info(
    db=Depends(get_db),
    current_user=Depends(get_current_user),
):
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    """Debug endpoint - vulnerable to information disclosure.

    Returns server configuration and environment details.
    Should be restricted to admin only.
    """
    # In a secured app, this would be admin-only
    # Vulnerable: returns info to any authenticated user
    return {
        "app_name": settings.APP_NAME,
        "app_version": settings.APP_VERSION,
        "debug": settings.DEBUG,
        "host": settings.HOST,
        "port": settings.PORT,
        "cookie_secure": settings.COOKIE_SECURE,
        "cookie_http_only": settings.COOKIE_HTTP_ONLY,
        "cookie_samesite": settings.COOKIE_SAMESITE,
        "database_url": str(engine.url),
    }


# ────────────────────────────────────────────────────────────────────
# Secure Record Routes (BOLA remediation)
# ────────────────────────────────────────────────────────────────────
@app.get("/secure/records")
def secure_list_records(
    db=Depends(get_db),
    current_user=Depends(get_current_user),
):
    """List only records owned by the current user.

    Secured version: Ownership validation enforced.
    """
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    records = db.query(Record).filter(Record.owner_id == current_user.id).all()
    return records


@app.get("/secure/records/{record_id}")
def secure_get_record(
    record_id: int,
    db=Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Get a specific record with ownership validation.

    Secured version: Ownership check enforced.
    Returns 404 if the record does not belong to the current user.
    """
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    record = db.query(Record).filter(
        Record.id == record_id,
        Record.owner_id == current_user.id
    ).first()
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")
    return {
        "id": record.id,
        "title": record.title,
        "content": record.content,
        "owner": record.owner.username if record.owner else None,
    }


@app.put("/secure/records/{record_id}")
def secure_update_record(
    record_id: int,
    title: str = "",
    content: str = "",
    db=Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Update a record with ownership validation.

    Secured version: Ownership check enforced.
    Returns 404 if the record does not belong to the current user.
    """
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    record = db.query(Record).filter(
        Record.id == record_id,
        Record.owner_id == current_user.id
    ).first()
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")

    if title:
        record.title = title
    if content:
        record.content = content
    db.commit()

    return {"id": record.id, "title": record.title, "content": record.content}


@app.delete("/secure/records/{record_id}")
def secure_delete_record(
    record_id: int,
    db=Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Delete a record with ownership validation.

    Secured version: Ownership check enforced.
    Returns 404 if the record does not belong to the current user.
    """
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    record = db.query(Record).filter(
        Record.id == record_id,
        Record.owner_id == current_user.id
    ).first()
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")

    db.delete(record)
    db.commit()

    return {"detail": "Record deleted"}


# ────────────────────────────────────────────────────────────────────
# Reflected XSS Lab Demo Endpoints (VUL-003 demonstration)
# ────────────────────────────────────────────────────────────────────
def escape_html(text: str) -> str:
    """HTML-encode user input to prevent XSS (mirrors template escapeHtml)."""
    return (text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#039;"))


@app.get("/xss", response_class=HTMLResponse)
def xss_demo_vulnerable(request: Request, username: str = "", attempt_id: str = "", db=Depends(get_db), current_user=Depends(get_current_user)):
    """Reflected XSS - vulnerable demo: raw reflection of user input.

    Vulnerable version: user input is reflected into HTML without encoding,
    so any script tags are executed by the browser.
    """
    if current_user and attempt_id and len(attempt_id) <= 64:
        db.add(AuditLog(user_id=current_user.id, action=f"xss_reflection:{attempt_id}", path=str(request.url), success=True))
        db.commit()
    body = (
        f"<!DOCTYPE html><html><head><title>XSS Demo - VULNERABLE</title></head>"
        f"<body><h1>Reflected XSS - VULNERABLE (no encoding)</h1>"
        f"<p>Username reflected raw:</p>"
        f"<div id='xss-output'>{username}</div>"
        f"<script>window.xssProofExecuted = true;</script>"
        f"</body></html>"
    )
    return body


@app.get("/secure/xss", response_class=HTMLResponse)
def xss_demo_secure(username: str = ""):
    """Reflected XSS - secure demo: HTML-encoded reflection.

    Secured version: user input is HTML-encoded before rendering, so script
    tags are displayed as text and never executed.
    """
    escaped = escape_html(username)
    body = (
        f"<!DOCTYPE html><html><head><title>XSS Demo - SECURE</title></head>"
        f"<body><h1>Reflected XSS - SECURE (HTML-encoded)</h1>"
        f"<p>Username reflected with encoding:</p>"
        f"<div id='xss-output'>{escaped}</div>"
        f"<script>window.xssSecureRendered = true;</script>"
        f"</body></html>"
    )
    return body


@app.get("/api/health")
def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": settings.APP_NAME}


@app.get("/api/records")
def api_records(
    db=Depends(get_db),
    current_user=Depends(get_current_user),
):
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    """API endpoint for records.

    Vulnerable version: No access control.
    Secured version: Requires authentication and returns only user's records.
    """
    records = db.query(Record).filter(Record.owner_id == current_user.id).all() if current_user else []
    return [
        {"id": r.id, "title": r.title, "owner": r.owner.username}
        for r in records
    ]


# ────────────────────────────────────────────────────────────────────
# Secure Admin Routes (BFLA remediation)
# ────────────────────────────────────────────────────────────────────
def require_admin(current_user=Depends(get_current_user)):
    """Dependency that enforces admin role.

    Raises 403 if the current user is not an administrator.
    """
    if not current_user or current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Administrator privileges required")
    return current_user


@app.get("/secure/admin/users")
def secure_list_users(
    db=Depends(get_db),
    current_user=Depends(require_admin),
):
    """List all users - admin only.

    Secured version: Role check enforced.
    """
    users = db.query(User).all()
    return [
        {"id": u.id, "username": u.username, "email": u.email, "role": u.role}
        for u in users
    ]


@app.get("/secure/admin/debug")
def secure_debug_info(
    db=Depends(get_db),
    current_user=Depends(require_admin),
):
    """Debug endpoint - admin only.

    Secured version: Role check enforced.
    Returns minimal configuration without sensitive internal details.
    """
    return {
        "app_name": settings.APP_NAME,
        "app_version": settings.APP_VERSION,
        "debug": settings.DEBUG,
        "host": settings.HOST,
        "port": settings.PORT,
    }
@app.get("/", response_class=HTMLResponse)
def landing(request: Request, current_user=Depends(get_current_user)):
    """Landing page."""
    return templates.TemplateResponse(request, "landing.html", {"request": request, "app": settings, "current_user": current_user})


@app.get("/labs", response_class=HTMLResponse)
def labs_dashboard(request: Request, current_user=Depends(get_current_user)):
    """Lab dashboard showing available security labs."""
    if not current_user:
        from fastapi.responses import RedirectResponse
        return RedirectResponse("/login?next=/labs", status_code=303)
    labs = [
        {
            "id": "bola",
            "name": "BOLA/IDOR - Object Level Authorization",
            "category": "Authorization",
            "objective": "Demonstrate unauthorized access to another user's records",
            "status": "not_started",
        },
        {
            "id": "bfla",
            "name": "BFLA - Function Level Authorization",
            "category": "Authorization",
            "objective": "Demonstrate regular user accessing admin functions",
            "status": "not_started",
        },
        {
            "id": "xss",
            "name": "Reflected XSS - Cross Site Scripting",
            "category": "Injection",
            "objective": "Demonstrate reflected payload execution in browser",
            "status": "not_started",
        },
    ]
    return templates.TemplateResponse(request, "labs_dashboard.html", {"request": request, "labs": labs, "app": settings, "current_user": current_user})


def _protected_template(request: Request, name: str, current_user):
    if not current_user:
        from fastapi.responses import RedirectResponse
        return RedirectResponse(f"/login?next={request.url.path}", status_code=303)
    return templates.TemplateResponse(request, name, {"request": request, "app": settings, "current_user": current_user})


@app.get("/bola_lab.html", response_class=HTMLResponse)
def bola_lab_page(request: Request, current_user=Depends(get_current_user)):
    return _protected_template(request, "bola_lab.html", current_user)


@app.get("/bfla_lab.html", response_class=HTMLResponse)
def bfla_lab_page(request: Request, current_user=Depends(get_current_user)):
    return _protected_template(request, "bfla_lab.html", current_user)


@app.get("/xss_lab.html", response_class=HTMLResponse)
def xss_lab_page(request: Request, current_user=Depends(get_current_user)):
    return _protected_template(request, "xss_lab.html", current_user)


@app.get("/operator/profile", response_class=HTMLResponse)
def operator_profile_page(request: Request, current_user=Depends(get_current_user)):
    return _protected_template(request, "operator_profile.html", current_user)


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, current_user=Depends(get_current_user)):
    return _protected_template(request, "settings.html", current_user)


@app.get("/terminal", response_class=HTMLResponse)
def terminal_page(request: Request, current_user=Depends(get_current_user)):
    return _protected_template(request, "terminal.html", current_user)


# ────────────────────────────────────────────────────────────────────
# Completion verification endpoint (server-side)
# ────────────────────────────────────────────────────────────────────
LAB_IDS = ("bola", "bfla", "xss")


def _get_or_create_progress(db, user_id: int, lab_id: str):
    progress = db.query(LabProgress).filter_by(user_id=user_id, lab_id=lab_id).first()
    if progress is None:
        progress = LabProgress(user_id=user_id, lab_id=lab_id, status="not_started")
        db.add(progress)
        db.flush()
    return progress


@app.get("/labs/{lab_id}/status")
def get_lab_status(lab_id: str, db=Depends(get_db), current_user=Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    if lab_id not in LAB_IDS:
        raise HTTPException(status_code=404, detail="Lab not found")
    progress = db.query(LabProgress).filter_by(user_id=current_user.id, lab_id=lab_id).first()
    return {"lab_id": lab_id, "status": progress.status if progress else "not_started"}


@app.post("/labs/{lab_id}/status")
def update_lab_status(lab_id: str, payload: dict, db=Depends(get_db), current_user=Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    if lab_id not in LAB_IDS:
        raise HTTPException(status_code=404, detail="Lab not found")
    status = payload.get("status")
    if status != "in_progress":
        raise HTTPException(status_code=400, detail="Completion must be verified by the server")
    progress = _get_or_create_progress(db, current_user.id, lab_id)
    if progress.status != "completed":
        progress.status = "in_progress"
        progress.started_at = progress.started_at or datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()
    return {"lab_id": lab_id, "status": progress.status}


@app.get("/api/labs/progress")
def get_lab_progress(db=Depends(get_db), current_user=Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    rows = db.query(LabProgress).filter_by(user_id=current_user.id).all()
    statuses = {row.lab_id: row.status for row in rows}
    return {"labs": {lab_id: {"status": statuses.get(lab_id, "not_started")} for lab_id in LAB_IDS}}


@app.post("/labs/{lab_id}/complete")
async def verify_lab_completion(
    lab_id: str,
    request: Request,
    db=Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Server-side verification of lab completion conditions.

    The frontend cannot mark a lab complete by itself.
    This endpoint validates that the user actually demonstrated
    the vulnerable behavior as intended.

    Returns:
        - verified: bool - whether completion was verified
        - lab_id: the lab identifier
        - verified_at: timestamp if verified
    """
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    if lab_id not in LAB_IDS:
        raise HTTPException(status_code=404, detail="Lab not found")
    body = await request.json()
    evidence = body.get("evidence") or {}
    verified = False
    if lab_id == "bola":
        record_id = body.get("record_id", evidence.get("record_id"))
        verified = bool(record_id and db.query(AuditLog).filter(
            AuditLog.user_id == current_user.id,
            AuditLog.action == f"record_access:{record_id}",
            AuditLog.record_owner_id.is_not(None),
            AuditLog.record_owner_id != current_user.id,
        ).first())
    elif lab_id == "bfla":
        verified = current_user.role != "admin" and bool(db.query(AuditLog).filter(
            AuditLog.user_id == current_user.id,
            AuditLog.action == "admin_access",
        ).first())
    elif lab_id == "xss":
        payload = evidence.get("payload", "")
        attempt_id = evidence.get("attempt_id", "")
        xss_log = db.query(AuditLog).filter(
            AuditLog.user_id == current_user.id,
            AuditLog.action == f"xss_reflection:{attempt_id}",
            AuditLog.success.is_(True),
        ).first() if attempt_id else None
        if xss_log and payload and "<script" in payload.lower() and "</script>" in payload.lower() and "postmessage" in payload.lower():
            from urllib.parse import parse_qs, urlsplit
            reflected_payload = parse_qs(urlsplit(xss_log.path or "").query).get("username", [""])[0]
            verified = payload == reflected_payload
    if verified:
        progress = _get_or_create_progress(db, current_user.id, lab_id)
        progress.status = "completed"
        progress.completed_at = progress.completed_at or datetime.now(timezone.utc).replace(tzinfo=None)
        progress.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        today = datetime.now(timezone.utc).date()
        contract = db.query(DailyContract).filter(
            DailyContract.user_id == current_user.id,
            DailyContract.contract_id == "complete_one_mission",
            func.date(DailyContract.date) == today,
        ).first()
        if contract and contract.status == "available":
            contract.progress = 1
            contract.status = "completed"
            contract.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
        db.commit()
    return {
        "verified": verified,
        "lab_id": lab_id,
        "verified_at": datetime.now(timezone.utc).isoformat() if verified else None,
        "reason": "passed" if verified else "conditions_not_met",
    }


# ────────────────────────────────────────────────────────────────────
# Gamification API Endpoints (XP, Ranks, Achievements, Contracts)
# ────────────────────────────────────────────────────────────────────

@app.get("/api/operator/profile")
def get_operator_profile(db=Depends(get_db), current_user=Depends(auth.require_current_user)):
    """Get the operator profile for the current user."""
    profile = db.query(OperatorProfile).filter(OperatorProfile.user_id == current_user.id).first()
    if not profile:
        # Create profile if it doesn't exist
        profile = OperatorProfile(user_id=current_user.id)
        db.add(profile)
        db.commit()
        db.refresh(profile)
    profile.recalculate_level_and_rank()
    return {
        "user_id": current_user.id,
        "username": current_user.username,
        "created_at": current_user.created_at.isoformat() if current_user.created_at else None,
        "handle": profile.handle,
        "avatar": profile.avatar,
        "theme": profile.theme,
        "xp": profile.xp,
        "level": profile.level,
        "rank": profile.rank,
        "total_missions_completed": profile.total_missions_completed,
        "total_attempts": profile.total_attempts,
        "hints_used": profile.hints_used,
        "requests_inspected": profile.requests_inspected,
        "updated_at": profile.updated_at.isoformat() if profile.updated_at else None,
        "xp_for_next_level": profile.xp_for_next_level(),
        "xp_progress_in_level": profile.xp_progress_in_level(),
    }


@app.post("/api/operator/profile/handle")
def set_operator_handle(
    handle: str,
    db=Depends(get_db),
    current_user=Depends(auth.require_current_user),
):
    """Set the operator handle for the current user."""
    if not handle or len(handle.strip()) == 0:
        raise HTTPException(status_code=400, detail="Handle cannot be empty")
    if len(handle) > 32:
        raise HTTPException(status_code=400, detail="Handle must be 32 characters or less")

    profile = db.query(OperatorProfile).filter(OperatorProfile.user_id == current_user.id).first()
    if not profile:
        profile = OperatorProfile(user_id=current_user.id)
        db.add(profile)

    profile.handle = handle.strip()
    db.commit()
    return {"message": "Operator handle updated", "handle": profile.handle}


class XPAwardRequest(BaseModel):
    source: str


@app.post("/api/xp/award")
def award_xp(
    payload: XPAwardRequest,
    db=Depends(get_db),
    current_user=Depends(auth.require_current_user),
):
    """Award the fixed server-side reward for a verified lab completion."""
    source = payload.source
    if not source.startswith("lab_completion:") or source.split(":", 1)[1] not in LAB_IDS:
        raise HTTPException(status_code=400, detail="Unsupported XP source")
    lab_id = source.split(":", 1)[1]
    progress = db.query(LabProgress).filter_by(
        user_id=current_user.id, lab_id=lab_id, status="completed"
    ).first()
    if not progress:
        raise HTTPException(status_code=403, detail="Lab completion has not been verified")
    xp_amount = 500

    # Check for duplicate award
    existing_award = db.query(XPAwardLog).filter(
        XPAwardLog.user_id == current_user.id,
        XPAwardLog.source == source
    ).first()

    if existing_award:
        raise HTTPException(status_code=409, detail="XP already awarded for this source")

    # Create award log entry
    award_log = XPAwardLog(
        user_id=current_user.id,
        source=source,
        xp_amount=xp_amount,
        description=f"Verified completion of {lab_id} lab"
    )
    db.add(award_log)

    # Update operator profile
    profile = db.query(OperatorProfile).filter(OperatorProfile.user_id == current_user.id).first()
    if not profile:
        profile = OperatorProfile(user_id=current_user.id)
        db.add(profile)

    profile.xp += xp_amount
    profile.recalculate_level_and_rank()

    # Update mission completion counter if this is a lab completion
    if source.startswith("lab_completion:"):
        lab_id = source.split(":")[1]
        progress = db.query(LabProgress).filter(
            LabProgress.user_id == current_user.id,
            LabProgress.lab_id == lab_id
        ).first()
        if progress and progress.status == "completed":
            # Count completed missions
            completed_count = db.query(LabProgress).filter(
                LabProgress.user_id == current_user.id,
                LabProgress.status == "completed"
            ).count()
            profile.total_missions_completed = completed_count

    db.commit()

    return {
        "message": f"Awarded {xp_amount} XP",
        "total_xp": profile.xp,
        "level": profile.level,
        "rank": profile.rank,
        "xp_for_next_level": profile.xp_for_next_level(),
        "xp_progress_in_level": profile.xp_progress_in_level(),
    }


@app.get("/api/achievements")
def get_achievements(db=Depends(get_db), current_user=Depends(auth.require_current_user)):
    """Get all achievements for the current user."""
    user_achievements = db.query(Achievement).filter(Achievement.user_id == current_user.id).all()
    unlocked_ids = {ua.achievement_id for ua in user_achievements}

    achievements = []
    for ach in ACHIEVEMENTS:
        achievements.append({
            "id": ach["id"],
            "name": ach["name"],
            "description": ach["description"],
            "icon": ach["icon"],
            "unlocked": ach["id"] in unlocked_ids,
            "unlocked_at": next((ua.unlocked_at.isoformat() for ua in user_achievements if ua.achievement_id == ach["id"]), None)
        })

    return {"achievements": achievements}


@app.post("/api/achievements/check")
def check_achievements(db=Depends(get_db), current_user=Depends(auth.require_current_user)):
    """Check and unlock achievements based on current progress."""
    newly_unlocked = []

    # Get current user stats
    profile = db.query(OperatorProfile).filter(OperatorProfile.user_id == current_user.id).first()
    if not profile:
        return {"newly_unlocked": []}

    completed_labs = db.query(LabProgress).filter(
        LabProgress.user_id == current_user.id,
        LabProgress.status == "completed"
    ).count()

    total_labs = len(settings.LABS_ENABLED)

    # Check each achievement
    for ach in ACHIEVEMENTS:
        # Skip if already unlocked
        existing = db.query(Achievement).filter(
            Achievement.user_id == current_user.id,
            Achievement.achievement_id == ach["id"]
        ).first()

        if existing:
            continue

        unlocked = False

        if ach["id"] == "first_breach" and completed_labs >= 1:
            unlocked = True
        elif ach["id"] == "ghost_in_the_system":
            # Check if any lab was completed without hints (would need to track this)
            # For now, we'll implement a simplified version
            if completed_labs >= 1 and profile.hints_used == 0:
                unlocked = True
        elif ach["id"] == "root_access" and completed_labs >= total_labs:
            unlocked = True
        elif ach["id"] == "packet_goblin" and profile.requests_inspected >= 50:
            unlocked = True
        elif ach["id"] == "no_trace":
            # Would need to track error-free completions
            # Simplified: if they have completed labs and minimal attempts
            if completed_labs >= 1 and profile.total_attempts <= completed_labs:
                unlocked = True

        if unlocked:
            achievement = Achievement(
                user_id=current_user.id,
                achievement_id=ach["id"]
            )
            db.add(achievement)
            newly_unlocked.append({
                "id": ach["id"],
                "name": ach["name"],
                "description": ach["description"],
                "icon": ach["icon"]
            })

    if newly_unlocked:
        db.commit()

    return {"newly_unlocked": newly_unlocked}


@app.get("/api/daily-contracts")
def get_daily_contracts(db=Depends(get_db), current_user=Depends(auth.require_current_user)):
    """Get daily contracts for the current user."""
    today = datetime.now(timezone.utc).date()
    contract = db.query(DailyContract).filter(
        DailyContract.user_id == current_user.id,
        DailyContract.contract_id == "complete_one_mission",
        func.date(DailyContract.date) == today,
    ).first()
    if contract is None:
        contract = DailyContract(
            user_id=current_user.id,
            contract_id="complete_one_mission",
            date=datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=None),
            status="available",
            progress=0,
            target=1,
            xp_reward=100,
        )
        db.add(contract)
        db.commit()

    contracts = db.query(DailyContract).filter(
        DailyContract.user_id == current_user.id,
        func.date(DailyContract.date) == today
    ).all()

    return {
        "contracts": [
            {
                "id": c.id,
                "contract_id": c.contract_id,
                "status": c.status,
                "progress": c.progress,
                "target": c.target,
                "xp_reward": c.xp_reward,
                "completed_at": c.completed_at.isoformat() if c.completed_at else None,
                "claimed_at": c.claimed_at.isoformat() if c.claimed_at else None,
            }
            for c in contracts
        ]
    }


@app.post("/api/daily-contracts/{contract_id}/progress")
def update_contract_progress(
    contract_id: str,
    db=Depends(get_db),
    current_user=Depends(auth.require_current_user),
):
    """Reconcile contract progress from server-verified lab completions."""
    today = datetime.now(timezone.utc).date()

    contract = db.query(DailyContract).filter(
        DailyContract.user_id == current_user.id,
        DailyContract.contract_id == contract_id,
        func.date(DailyContract.date) == today
    ).first()

    if not contract:
        raise HTTPException(status_code=404, detail="Contract not found")

    completed_count = db.query(LabProgress).filter(
        LabProgress.user_id == current_user.id,
        LabProgress.status == "completed",
    ).count()
    if contract.status == "available" and completed_count >= contract.target:
        contract.progress = contract.target
        contract.status = "completed"
        contract.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)

    db.commit()

    return {
        "message": "Contract progress updated",
        "progress": contract.progress,
        "target": contract.target,
        "status": contract.status
    }


@app.post("/api/daily-contracts/{contract_id}/claim")
def claim_contract_reward(
    contract_id: str,
    db=Depends(get_db),
    current_user=Depends(auth.require_current_user),
):
    """Claim XP reward for a completed daily contract."""
    today = datetime.now(timezone.utc).date()

    contract = db.query(DailyContract).filter(
        DailyContract.user_id == current_user.id,
        DailyContract.contract_id == contract_id,
        func.date(DailyContract.date) == today
    ).first()

    if not contract:
        raise HTTPException(status_code=404, detail="Contract not found")

    if contract.status != "completed":
        raise HTTPException(status_code=400, detail="Contract not completed yet")

    if contract.claimed_at is not None:
        raise HTTPException(status_code=400, detail="Reward already claimed")

    # Award XP
    profile = db.query(OperatorProfile).filter(OperatorProfile.user_id == current_user.id).first()
    if not profile:
        profile = OperatorProfile(user_id=current_user.id)
        db.add(profile)

    profile.xp += contract.xp_reward
    profile.recalculate_level_and_rank()

    # Mark as claimed
    contract.status = "claimed"
    contract.claimed_at = datetime.now(timezone.utc).replace(tzinfo=None)

    # Log XP award to prevent double claiming
    award_log = XPAwardLog(
        user_id=current_user.id,
        source=f"daily_contract:{contract_id}:{today.isoformat()}",
        xp_amount=contract.xp_reward,
        description=f"Daily contract reward: {contract_id}"
    )
    db.add(award_log)

    db.commit()

    return {
        "message": f"Claimed {contract.xp_reward} XP reward",
        "total_xp": profile.xp,
        "level": profile.level,
        "rank": profile.rank
    }


@app.get("/api/user/settings")
def get_user_settings(db=Depends(get_db), current_user=Depends(auth.require_current_user)):
    """Get user settings for audio, visual effects, etc."""
    settings = db.query(UserSettings).filter(UserSettings.user_id == current_user.id).first()
    if not settings:
        # Create default settings
        settings = UserSettings(user_id=current_user.id)
        db.add(settings)
        db.commit()
        db.refresh(settings)

    return {
        "sound_enabled": settings.sound_enabled,
        "music_enabled": settings.music_enabled,
        "crt_scanlines": settings.crt_scanlines,
        "reduced_motion": settings.reduced_motion,
        "boot_sequence_enabled": settings.boot_sequence_enabled,
        "theme_accent": settings.theme_accent,
        "terminal_font": settings.terminal_font,
        "brightness": settings.brightness,
        "contrast": settings.contrast,
        "volume": settings.volume,
        "data_retention": settings.data_retention,
        "intelligence_sharing": settings.intelligence_sharing,
    }


@app.post("/api/user/settings")
def update_user_settings(
    updates: dict,
    db=Depends(get_db),
    current_user=Depends(auth.require_current_user),
):
    """Update user settings."""
    settings = db.query(UserSettings).filter(UserSettings.user_id == current_user.id).first()
    if not settings:
        settings = UserSettings(user_id=current_user.id)
        db.add(settings)

    # Update allowed fields
    allowed_fields = {
        "sound_enabled", "music_enabled", "crt_scanlines", "reduced_motion",
        "boot_sequence_enabled", "theme_accent", "terminal_font", "brightness",
        "contrast", "volume", "data_retention", "intelligence_sharing",
    }

    for key, value in updates.items():
        if key in allowed_fields:
            if key in {"brightness", "contrast", "volume"} and (not isinstance(value, int) or not 0 <= value <= 100):
                raise HTTPException(status_code=422, detail=f"{key} must be an integer from 0 to 100")
            if key in {"sound_enabled", "music_enabled", "crt_scanlines", "reduced_motion", "boot_sequence_enabled", "intelligence_sharing"} and not isinstance(value, bool):
                raise HTTPException(status_code=422, detail=f"{key} must be a boolean")
            if key == "theme_accent" and value not in {"phosphor", "cyan", "amber", "magenta"}:
                raise HTTPException(status_code=422, detail="Unsupported theme accent")
            if key == "terminal_font" and value not in {"vt323", "share_tech", "orbitron", "press_start"}:
                raise HTTPException(status_code=422, detail="Unsupported terminal font")
            if key == "data_retention" and str(value) not in {"30", "90", "365", "-1"}:
                raise HTTPException(status_code=422, detail="Unsupported data retention period")
            setattr(settings, key, value)

    db.commit()
    return {"message": "Settings updated"}

if __name__ == "__main__":
    uvicorn.run(
        app,
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
    )
