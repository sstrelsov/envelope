"""MailboxLayer API email verification client."""

from typing import Optional

import requests

from .models import ApiResult


def call_mailboxlayer(email: str, api_key: Optional[str]) -> ApiResult:
    """Call MailboxLayer API to verify email deliverability."""
    if not api_key:
        return ApiResult("MailboxLayer", False, None, None, "No API key")

    # Try header-based endpoint first
    try:
        r = requests.get(
            "https://api.apilayer.com/email_verification/check",
            params={"email": email, "smtp": 1, "format": 1},
            headers={"apikey": api_key},
            timeout=12,
        )
        if r.status_code == 200:
            return _parse_mailboxlayer_payload(r.json(), used=True)
    except requests.RequestException:
        pass

    # Legacy endpoint
    try:
        r = requests.get(
            "https://apilayer.net/api/check",
            params={"access_key": api_key, "email": email, "smtp": 1, "format": 1},
            timeout=12,
        )
        r.raise_for_status()
        return _parse_mailboxlayer_payload(r.json(), used=True)

    except requests.RequestException as e:
        return ApiResult("MailboxLayer", True, None, None, f"HTTP error: {e}")
    except Exception as e:
        return ApiResult("MailboxLayer", True, None, None, f"Error: {e}")


def _parse_mailboxlayer_payload(data: dict, used: bool) -> ApiResult:
    """Parse MailboxLayer API response payload."""
    fmt = data.get("format_valid", False)
    mx_found = data.get("mx_found", False)
    smtp_ok = data.get("smtp_check", None)
    score = data.get("score", None)

    try:
        conf = float(score) if score is not None else None
    except Exception:
        conf = None

    if fmt and mx_found and smtp_ok is True:
        return ApiResult("MailboxLayer", used, True, conf, "Deliverable (SMTP ok)")
    if fmt and mx_found and smtp_ok is False:
        return ApiResult("MailboxLayer", used, False, conf, "Undeliverable (SMTP)")
    if not mx_found:
        return ApiResult("MailboxLayer", used, False, conf, "No MX")
    return ApiResult("MailboxLayer", used, None, conf, "Unknown/Risky")
