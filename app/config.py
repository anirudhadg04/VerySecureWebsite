"""Environment-backed configuration for VerySecureWebsite."""

import os
import secrets

from dotenv import load_dotenv


load_dotenv()


def _bool_setting(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean value")


def _int_setting(name: str, default: int, minimum: int = 1) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return value


class Settings:
    def __init__(self) -> None:
        self.APP_NAME = os.getenv("APP_NAME", "VerySecureWebsite")
        self.APP_VERSION = os.getenv("APP_VERSION", "1.0.0-lab")
        self.APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
        # Handle DEBUG setting: accept both boolean values and common environment names
        debug_env = os.getenv("DEBUG")
        if debug_env is not None:
            debug_env_lower = debug_env.strip().lower()
            # Map common environment names to boolean values
            if debug_env_lower in {"release", "production", "prod", "staging"}:
                debug_value = False
            elif debug_env_lower in {"development", "dev", "test", "debug"}:
                debug_value = True
            else:
                # For explicit boolean values, use the standard parser
                debug_value = _bool_setting("DEBUG", self.APP_ENV != "production")
        else:
            # Use default based on APP_ENV when DEBUG is not set
            debug_value = self.APP_ENV != "production"
        self.DEBUG = debug_value
        self.HOST = os.getenv("HOST", "127.0.0.1")
        self.PORT = _int_setting("PORT", 8000)
        self.BASE_URL = os.getenv("BASE_URL", f"http://{self.HOST}:{self.PORT}").rstrip("/")
        self.DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./verysecurewebsite.db")

        secret_key = os.getenv("SECRET_KEY", "").strip()
        if not secret_key:
            if self.APP_ENV == "production":
                raise ValueError("SECRET_KEY must be configured in production")
            secret_key = secrets.token_urlsafe(48)
        if len(secret_key) < 32:
            raise ValueError("SECRET_KEY must contain at least 32 characters")
        self.SECRET_KEY = secret_key

        self.SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "vsw_session")
        self.SESSION_MAX_AGE = _int_setting("SESSION_MAX_AGE", 86400)
        self.COOKIE_SECURE = _bool_setting("COOKIE_SECURE", self.APP_ENV == "production")
        self.COOKIE_HTTP_ONLY = True
        self.COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "lax").strip().lower()
        if self.COOKIE_SAMESITE not in {"lax", "strict", "none"}:
            raise ValueError("COOKIE_SAMESITE must be lax, strict, or none")
        if self.COOKIE_SAMESITE == "none" and not self.COOKIE_SECURE:
            raise ValueError("COOKIE_SECURE must be true when COOKIE_SAMESITE is none")

        self.BCRYPT_ROUNDS = _int_setting("BCRYPT_ROUNDS", 12, minimum=4)
        self.LOGIN_MAX_ATTEMPTS = _int_setting("LOGIN_MAX_ATTEMPTS", 5)
        self.LOGIN_LOCKOUT_MINUTES = _int_setting("LOGIN_LOCKOUT_MINUTES", 15)
        self.PASSWORD_RESET_MAX_ATTEMPTS = _int_setting("PASSWORD_RESET_MAX_ATTEMPTS", 3)
        self.PASSWORD_RESET_TOKEN_EXPIRY_MINUTES = _int_setting(
            "PASSWORD_RESET_TOKEN_EXPIRY_MINUTES", 5
        )

        self.SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
        self.SMTP_PORT = _int_setting("SMTP_PORT", 587)
        self.SMTP_USERNAME = os.getenv("SMTP_USERNAME", "").strip()
        self.SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
        self.SMTP_USE_TLS = _bool_setting("SMTP_USE_TLS", True)
        self.SMTP_USE_SSL = _bool_setting("SMTP_USE_SSL", False)
        self.SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", "").strip()
        self.SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", self.APP_NAME).strip()
        if self.SMTP_USE_TLS and self.SMTP_USE_SSL:
            raise ValueError("SMTP_USE_TLS and SMTP_USE_SSL cannot both be enabled")

        self.LABS_ENABLED = ["bola", "bfla", "xss"]
        
        # OTP Configuration
        self.OTP_EXPIRY_MINUTES = _int_setting("OTP_EXPIRY_MINUTES", 5)
        self.OTP_LENGTH = _int_setting("OTP_LENGTH", 6)
        self.OTP_RESEND_DELAY_SECONDS = _int_setting("OTP_RESEND_DELAY_SECONDS", 30)

    @property
    def SMTP_CONFIGURED(self) -> bool:
        credentials_valid = bool(self.SMTP_USERNAME) == bool(self.SMTP_PASSWORD)
        return bool(self.SMTP_HOST and self.SMTP_FROM_EMAIL and credentials_valid)


settings = Settings()