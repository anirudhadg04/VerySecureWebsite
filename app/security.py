"""Authentication primitives shared by browser-facing routes."""

import hashlib
import hmac
import secrets

import bcrypt


def hash_password(password: str, rounds: int) -> str:
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(rounds=rounds),
    ).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))
    except (ValueError, TypeError, UnicodeEncodeError):
        return False


def opaque_token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_csrf_token(secret_key: str) -> str:
    nonce = secrets.token_urlsafe(32)
    signature = hmac.new(secret_key.encode("utf-8"), nonce.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{nonce}.{signature}"


def verify_csrf_token(token: str, secret_key: str) -> bool:
    try:
        nonce, signature = token.rsplit(".", 1)
    except ValueError:
        return False
    expected = hmac.new(secret_key.encode("utf-8"), nonce.encode("ascii"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, expected)


def rate_limit_key(secret_key: str, scope: str, identity: str) -> str:
    message = f"{scope}:{identity.strip().lower()}".encode("utf-8")
    return hmac.new(secret_key.encode("utf-8"), message, hashlib.sha256).hexdigest()


def password_policy_error(password: str) -> str | None:
    encoded = password.encode("utf-8")
    if len(encoded) < 12:
        return "Password must be at least 12 characters long."
    if len(encoded) > 72:
        return "Password must be no more than 72 UTF-8 bytes."
    if not any(char.islower() for char in password):
        return "Password must include a lowercase letter."
    if not any(char.isupper() for char in password):
        return "Password must include an uppercase letter."
    if not any(char.isdigit() for char in password):
        return "Password must include a number."
    return None