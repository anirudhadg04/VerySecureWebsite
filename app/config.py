"""Configuration settings for the VerySecureWebsite security lab."""

from pydantic import Field


class Settings:
    """Application settings with sensible defaults for local development.

    Uses manual instantiation instead of BaseSettings to avoid pydantic-settings
    package dependency issues in the lab environment. All values are configurable
    via environment variables if needed.
    """

    # Server settings
    APP_NAME: str = "VerySecureWebsite"
    APP_VERSION: str = "1.0.0-lab"
    DEBUG: bool = True
    HOST: str = "127.0.0.1"
    PORT: int = 8000

    # Cookie security - configurable for local HTTP dev
    # These are set to permissive values for local lab testing;
    # production deployment should use secure flags.
    COOKIE_SECURE: bool = False       # True for HTTPS only
    COOKIE_HTTP_ONLY: bool = True
    COOKIE_SAMESITE: str = "lax"      # "lax" | "strict" | "none"

    # Authentication settings
    BCRYPT_ROUNDS: int = 12
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Lab configuration
    LABS_ENABLED: list = None  # initialized below

    def __init__(self):
        if self.LABS_ENABLED is None:
            self.LABS_ENABLED = ["bola", "bfla", "xss"]


# Global settings instance
settings = Settings()