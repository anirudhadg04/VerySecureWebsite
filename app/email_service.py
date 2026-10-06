"""SMTP delivery for password-reset messages."""

import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr

from .config import settings


class SMTPNotConfigured(RuntimeError):
    pass


class SMTPDeliveryError(RuntimeError):
    pass


def send_password_reset_email(recipient: str, reset_url: str) -> None:
    if not settings.SMTP_CONFIGURED:
        raise SMTPNotConfigured("SMTP_HOST and SMTP_FROM_EMAIL must be configured")

    message = EmailMessage()
    message["Subject"] = "Reset your VerySecureWebsite password"
    message["From"] = formataddr((settings.SMTP_FROM_NAME, settings.SMTP_FROM_EMAIL))
    message["To"] = recipient
    message.set_content(
        "A password reset was requested for your VerySecureWebsite account.\n\n"
        f"Use this single-use link within {settings.PASSWORD_RESET_TOKEN_EXPIRY_MINUTES} minutes:\n"
        f"{reset_url}\n\n"
        "If you did not request this reset, you can ignore this message."
    )

    try:
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
        raise SMTPDeliveryError("SMTP delivery failed") from exc