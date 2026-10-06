"""Browser authentication routes and database-backed session helpers."""

import logging
import re
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy.exc import IntegrityError

from .config import settings
from .database import get_db
from .email_service import (
    SMTPDeliveryError,
    SMTPNotConfigured,
    send_password_reset_email,
)
from .models import AuthRateLimit, AuditLog, PasswordResetToken, Record, User, UserSession
from .security import (
    create_csrf_token,
    hash_password,
    opaque_token_hash,
    password_policy_error,
    rate_limit_key,
    verify_csrf_token,
    verify_password,
)


logger = logging.getLogger(__name__)
router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


async def csrf_middleware(request: Request, call_next):
    """Protect state-changing browser requests with a signed double-submit token."""
    safe_methods = {"GET", "HEAD", "OPTIONS"}
    cookie_name = "vsw_csrf"
    if request.method not in safe_methods:
        cookie_token = request.cookies.get(cookie_name, "")
        header_token = request.headers.get("X-CSRF-Token", "")
        if (
            not cookie_token
            or not header_token
            or not secrets.compare_digest(cookie_token, header_token)
            or not verify_csrf_token(cookie_token, settings.SECRET_KEY)
        ):
            return JSONResponse(status_code=403, content={"detail": "CSRF validation failed"})

    response = await call_next(request)
    current_csrf = request.cookies.get(cookie_name, "")
    if request.method in safe_methods and not verify_csrf_token(current_csrf, settings.SECRET_KEY):
        response.set_cookie(
            cookie_name,
            create_csrf_token(settings.SECRET_KEY),
            httponly=False,
            secure=settings.COOKIE_SECURE,
            samesite=settings.COOKIE_SAMESITE,
            path="/",
        )
    return response


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def get_current_user(request: Request, db=Depends(get_db)):
    """Resolve an authenticated user from a revocable opaque session cookie."""
    raw_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if not raw_token:
        return None
    session = db.query(UserSession).filter(
        UserSession.token_hash == opaque_token_hash(raw_token),
        UserSession.revoked_at.is_(None),
        UserSession.expires_at > utcnow(),
    ).first()
    if not session:
        return None
    user = db.query(User).filter(User.id == session.user_id, User.is_active.is_(True)).first()
    if user:
        request.state.auth_session = session
    return user


def require_current_user(current_user=Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return current_user


def _rate_key(request: Request, action: str, identity: str = "") -> str:
    ip = request.client.host if request.client else "unknown"
    return rate_limit_key(settings.SECRET_KEY, action, f"{ip}:{identity}")


def _get_rate_bucket(db, key: str, limit: int, window_minutes: int) -> AuthRateLimit:
    now = utcnow()
    bucket = db.query(AuthRateLimit).filter(AuthRateLimit.key_hash == key).with_for_update().first()
    if bucket and bucket.locked_until and bucket.locked_until > now:
        retry_after = max(1, int((bucket.locked_until - now).total_seconds()))
        raise HTTPException(
            status_code=429,
            detail="Too many attempts. Please try again later.",
            headers={"Retry-After": str(retry_after)},
        )
    if bucket is None:
        bucket = AuthRateLimit(key_hash=key, attempts=0, window_started_at=now)
        db.add(bucket)
        db.flush()
    elif bucket.window_started_at + timedelta(minutes=window_minutes) <= now:
        bucket.attempts = 0
        bucket.window_started_at = now
        bucket.locked_until = None
    return bucket


def _record_login_failure(db, buckets: list[AuthRateLimit]) -> None:
    now = utcnow()
    for bucket in buckets:
        bucket.attempts += 1
        bucket.updated_at = now
        if bucket.attempts >= settings.LOGIN_MAX_ATTEMPTS:
            bucket.locked_until = now + timedelta(minutes=settings.LOGIN_LOCKOUT_MINUTES)
    db.commit()


def _consume_reset_limit(db, key: str) -> None:
    bucket = _get_rate_bucket(
        db,
        key,
        settings.PASSWORD_RESET_MAX_ATTEMPTS,
        settings.LOGIN_LOCKOUT_MINUTES,
    )
    if bucket.attempts >= settings.PASSWORD_RESET_MAX_ATTEMPTS:
        bucket.locked_until = utcnow() + timedelta(minutes=settings.LOGIN_LOCKOUT_MINUTES)
        db.commit()
        raise HTTPException(status_code=429, detail="Too many attempts. Please try again later.")
    bucket.attempts += 1
    bucket.updated_at = utcnow()
    db.commit()


def _consume_reset_rate_limit(db, key: str) -> None:
    _consume_reset_limit(db, key)


def _set_session_cookie(response: Response, raw_token: str) -> None:
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=raw_token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        path="/",
        max_age=settings.SESSION_MAX_AGE,
    )


def _safe_next(path: str | None) -> str:
    if path and path.startswith("/") and not path.startswith("//"):
        return path
    return "/labs"


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=72)
    rememberMe: bool = Field(default=False)


class PasswordPair(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: str = Field(min_length=1, max_length=72)
    confirm_password: str = Field(min_length=1, max_length=72)

    @field_validator("password")
    @classmethod
    def check_password_strength(cls, value: str) -> str:
        problem = password_policy_error(value)
        if problem:
            raise ValueError(problem)
        return value

    @model_validator(mode="after")
    def passwords_match(self):
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match")
        return self


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=254)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        value = value.strip().lower()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
            raise ValueError("Enter a valid email address")
        # For now, restrict to Gmail addresses as requested
        if not value.endswith("@gmail.com"):
            raise ValueError("Only Gmail addresses are supported for registration")
        return value


class OTPRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=254)


class OTPVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=254)
    otp: str = Field(min_length=1, max_length=10)


class PasswordSetupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=72)

    @field_validator("password")
    @classmethod
    def check_password_strength(cls, value: str) -> str:
        problem = password_policy_error(value)
        if problem:
            raise ValueError(problem)
        return value


class ForgotPasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=254)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return value.strip().lower()


class ResetPasswordRequest(PasswordPair):
    token: str = Field(min_length=32, max_length=256)


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = "/labs", current_user=Depends(get_current_user)):
    if current_user:
        return RedirectResponse(_safe_next(next), status_code=303)
    return templates.TemplateResponse(request, "auth.html", {"request": request, "mode": "login", "next": _safe_next(next)})


@router.get("/register", response_class=HTMLResponse)
def register_page(request: Request, current_user=Depends(get_current_user)):
    if current_user:
        return RedirectResponse("/labs", status_code=303)
    return templates.TemplateResponse(request, "auth.html", {"request": request, "mode": "register", "next": "/labs"})


@router.get("/forgot-password", response_class=HTMLResponse)
def forgot_password_page(request: Request, current_user=Depends(get_current_user)):
    if current_user:
        return RedirectResponse("/labs", status_code=303)
    return templates.TemplateResponse(request, "auth.html", {"request": request, "mode": "forgot", "next": "/login"})


@router.get("/reset-password", response_class=HTMLResponse)
def reset_password_page(request: Request, current_user=Depends(get_current_user)):
    if current_user:
        return RedirectResponse("/labs", status_code=303)
    return templates.TemplateResponse(request, "auth.html", {"request": request, "mode": "reset", "next": "/login"})


@router.post("/auth/register")
def register_start(payload: RegisterRequest, request: Request, db=Depends(get_db)):
    """Step 1: Validate email and send OTP"""
    # Check if email already exists
    existing_user = db.query(User).filter(User.email == payload.email).first()
    if existing_user:
        # Don't reveal that the email exists for security
        pass  # Continue as if everything is normal
    
    # Generate cryptographically secure OTP
    otp = ''.join([str(secrets.randbelow(10)) for _ in range(settings.OTP_LENGTH)])
    
    # Hash the OTP for storage (never store plaintext OTP)
    otp_hash = hash_password(otp, settings.BCRYPT_ROUNDS)
    
    # Store OTP verification record
    now = utcnow()
    expires_at = now + timedelta(minutes=settings.OTP_EXPIRY_MINUTES)
    
    # Remove any existing OTP record for this email
    db.query(OTPVerification).filter(OTPVerification.email == payload.email).delete()
    
    otp_verification = OTPVerification(
        email=payload.email,
        otp_hash=otp_hash,
        expires_at=expires_at,
    )
    db.add(otp_verification)
    db.commit()
    
    # Send OTP via email
    if not settings.SMTP_CONFIGURED:
        # In development, we might want to log the OTP for testing
        logger.warning(f"SMTP not configured. OTP for {payload.email}: {otp}")
        # For production, we would raise an error
        if settings.APP_ENV == "production":
            raise HTTPException(status_code=503, detail="Registration email is not configured")
    else:
        try:
            # Create OTP email message
            message = EmailMessage()
            message["Subject"] = "Your VerySecureWebsite OTP Code"
            message["From"] = formataddr((settings.SMTP_FROM_NAME, settings.SMTP_FROM_EMAIL))
            message["To"] = payload.email
            message.set_content(
                f"Your One-Time Password (OTP) for VerySecureWebsite registration is:\n\n"
                f"{otp}\n\n"
                f"This OTP will expire in {settings.OTP_EXPIRY_MINUTES} minutes.\n\n"
                "If you did not request this OTP, you can ignore this message."
            )
            
            # Send email
            if settings.SMTP_USE_SSL:
                client = smtplib.SMTP_SSL(
                    settings.SMTP_HOST,
                    settings.SMTP_PORT,
                    timeout=15,
                    context=ssl.create_default_context(),
                )
            else:
                client = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15)
            
            with client:
                client.ehlo()
                if settings.SMTP_USE_TLS:
                    client.starttls(context=ssl.create_default_context())
                    client.ehlo()
                if settings.SMTP_USERNAME:
                    client.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                client.send_message(message)
        except (OSError, smtplib.SMTPException) as exc:
            logger.error(f"SMTP delivery failed: {exc}")
            raise HTTPException(status_code=503, detail="Failed to send OTP email")
    
    return {
        "message": "OTP sent to your email. Please check your inbox.",
        "email": payload.email
    }


@router.post("/auth/register/verify-otp")
def verify_otp(payload: OTPVerifyRequest, request: Request, db=Depends(get_db)):
    """Step 2: Verify the OTP code"""
    now = utcnow()
    
    # Get OTP verification record
    otp_record = db.query(OTPVerification).filter(
        OTPVerification.email == payload.email,
        OTPVerification.expires_at > now,
        OTPVerification.verified_at.is_(None)
    ).first()
    
    if not otp_record:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")
    
    # Verify the OTP
    if not verify_password(payload.otp, otp_record.otp_hash):
        # Rate limit failed OTP attempts (optional but good for security)
        raise HTTPException(status_code=400, detail="Invalid OTP")
    
    # Mark OTP as verified
    otp_record.verified_at = now
    db.commit()
    
    return {
        "message": "OTP verified successfully. Please create your password.",
        "email": payload.email
    }


@router.post("/auth/register/setup-password")
def setup_password(payload: PasswordSetupRequest, request: Request, db=Depends(get_db)):
    """Step 3: Set password after OTP verification"""
    now = utcnow()
    
    # Verify that OTP was verified for this email
    otp_record = db.query(OTPVerification).filter(
        OTPVerification.email == payload.email,
        OTPVerification.verified_at.isnot(None),
        OTPVerification.expires_at > now
    ).first()
    
    if not otp_record:
        raise HTTPException(status_code=400, detail="Please verify your email first")
    
    # Check if user already exists (shouldn't happen if OTP flow was followed, but double-check)
    existing_user = db.query(User).filter(User.email == payload.email).first()
    if existing_user:
        raise HTTPException(status_code=409, detail="Account already exists with this email")
    
    # Hash the password
    password_hash = hash_password(payload.password, settings.BCRYPT_ROUNDS)
    
    # Create the user
    user = User(
        email=payload.email,
        password_hash=password_hash,
        role="user",
        is_active=True,
        created_at=now,
        updated_at=now,
    )
    
    # Generate a username from the email (part before @) for display purposes
    username = payload.email.split('@')[0]
    # Ensure username is unique
    counter = 1
    original_username = username
    while db.query(User).filter(User.username == username).first():
        username = f"{original_username}{counter}"
        counter += 1
    
    user.username = username
    
    db.add(user)
    try:
        db.flush()
        # Create initial records for the user (synthetic data for labs)
        db.add_all([
            Record(title=f"{username.title()}'s Medical Record", content="Synthetic medical data", owner_id=user.id),
            Record(title=f"{username.title()}'s Financial Record", content="Synthetic financial data", owner_id=user.id),
        ])
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Account creation failed") from exc
    
    # Clean up OTP verification record
    db.delete(otp_record)
    db.commit()
    
    return {
        "message": "Account created successfully. Please sign in.",
        "user_id": user.id,
        "email": user.email
    }


@router.post("/auth/login")
def login(payload: LoginRequest, request: Request, response: Response, db=Depends(get_db)):
    # Login now uses email instead of username
    email = payload.username.strip().lower()  # Field is still called username for compatibility but contains email
    ip_key = _rate_key(request, "login-ip")
    account_key = _rate_key(request, "login-account", email)
    buckets = [
        _get_rate_bucket(db, ip_key, settings.LOGIN_MAX_ATTEMPTS, settings.LOGIN_LOCKOUT_MINUTES),
        _get_rate_bucket(db, account_key, settings.LOGIN_MAX_ATTEMPTS, settings.LOGIN_LOCKOUT_MINUTES),
    ]
    user = db.query(User).filter(User.email == email).first()
    if not user or not user.is_active or not verify_password(payload.password, user.password_hash):
        _record_login_failure(db, buckets)
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    db.query(AuthRateLimit).filter(AuthRateLimit.key_hash.in_([ip_key, account_key])).delete(synchronize_session=False)
    raw_token = secrets.token_urlsafe(32)
    now = utcnow()
    
    # Determine session duration based on Remember Me checkbox
    session_duration = settings.SESSION_MAX_AGE
    if hasattr(payload, 'rememberMe') and payload.rememberMe:
        session_duration = settings.REMEMBER_ME_MAX_AGE
    
    db.add(UserSession(
        user_id=user.id,
        token_hash=opaque_token_hash(raw_token),
        created_at=now,
        expires_at=now + timedelta(seconds=session_duration),
    ))
    db.add(AuditLog(user_id=user.id, action="login", path=request.url.path, success=True))
    db.commit()
    _set_session_cookie(response, raw_token)
    return {"message": "Signed in", "user_id": user.id, "username": user.username, "email": user.email, "user_role": user.role, "role": user.role}


@router.post("/auth/logout")
def logout(request: Request, response: Response, db=Depends(get_db), current_user=Depends(get_current_user)):
    session = getattr(request.state, "auth_session", None)
    if session:
        db.delete(session)
    if current_user:
        db.add(AuditLog(user_id=current_user.id, action="logout", path=request.url.path, success=True))
    db.commit()
    response.delete_cookie(
        settings.SESSION_COOKIE_NAME,
        path="/",
        secure=settings.COOKIE_SECURE,
        httponly=True,
        samesite=settings.COOKIE_SAMESITE,
    )
    return {"message": "Logged out"}


@router.get("/auth/me")
def me(current_user=Depends(require_current_user)):
    return {"id": current_user.id, "username": current_user.username, "email": current_user.email, "role": current_user.role}


@router.post("/auth/forgot-password")
def forgot_password(payload: ForgotPasswordRequest, request: Request, db=Depends(get_db)):
    _consume_reset_rate_limit(db, _rate_key(request, "password-reset-request"))
    if not settings.SMTP_CONFIGURED:
        raise HTTPException(status_code=503, detail="Password recovery email is not configured. Set SMTP settings in .env.")

    user = db.query(User).filter(User.email == payload.email, User.is_active.is_(True)).first()
    if user:
        now = utcnow()
        db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used_at.is_(None),
        ).update({PasswordResetToken.used_at: now}, synchronize_session=False)
        raw_token = secrets.token_urlsafe(32)
        token_row = PasswordResetToken(
            user_id=user.id,
            token_hash=opaque_token_hash(raw_token),
            created_at=now,
            expires_at=now + timedelta(minutes=settings.PASSWORD_RESET_TOKEN_EXPIRY_MINUTES),
        )
        db.add(token_row)
        db.commit()
        try:
            send_password_reset_email(user.email, f"{settings.BASE_URL}/reset-password#token={raw_token}")
        except SMTPNotConfigured:
            db.delete(token_row)
            db.commit()
            raise HTTPException(status_code=503, detail="Password recovery email is not configured. Set SMTP settings in .env.")
        except SMTPDeliveryError:
            db.delete(token_row)
            db.commit()
            logger.warning("Password reset email delivery failed")

    return {
        "message": "If the address is registered and email delivery is available, recovery instructions will be sent.",
    }


@router.post("/auth/reset-password")
def reset_password(payload: ResetPasswordRequest, request: Request, db=Depends(get_db)):
    _consume_reset_rate_limit(db, _rate_key(request, "password-reset-confirm"))
    now = utcnow()
    token_row = db.query(PasswordResetToken).filter(
        PasswordResetToken.token_hash == opaque_token_hash(payload.token),
        PasswordResetToken.used_at.is_(None),
        PasswordResetToken.expires_at > now,
    ).first()
    if not token_row:
        raise HTTPException(status_code=400, detail="Reset link is invalid or expired. Request a new one.")
    updated = db.query(PasswordResetToken).filter(
        PasswordResetToken.id == token_row.id,
        PasswordResetToken.used_at.is_(None),
        PasswordResetToken.expires_at > now,
    ).update({PasswordResetToken.used_at: now}, synchronize_session=False)
    if updated != 1:
        db.rollback()
        raise HTTPException(status_code=400, detail="Reset link is invalid or expired. Request a new one.")

    user = db.query(User).filter(User.id == token_row.user_id, User.is_active.is_(True)).first()
    if not user:
        db.rollback()
        raise HTTPException(status_code=400, detail="Reset link is invalid or expired. Request a new one.")
    user.password_hash = hash_password(payload.password, settings.BCRYPT_ROUNDS)
    user.updated_at = now
    db.query(UserSession).filter(UserSession.user_id == user.id).delete(synchronize_session=False)
    db.query(PasswordResetToken).filter(
        PasswordResetToken.user_id == user.id,
        PasswordResetToken.id != token_row.id,
        PasswordResetToken.used_at.is_(None),
    ).update({PasswordResetToken.used_at: now}, synchronize_session=False)
    db.commit()
    return {"message": "Password reset successful. Sign in with your new password."}
