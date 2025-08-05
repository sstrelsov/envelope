"""Abstract API email verification client."""

from typing import Optional

import requests

from .models import ApiResult


def call_abstract(email: str, api_key: Optional[str]) -> ApiResult:
    """Call Abstract API to verify email deliverability."""
    if not api_key:
        return ApiResult("Abstract", False, None, None, "No API key")

    try:
        r = requests.get(
            "https://emailvalidation.abstractapi.com/v1/",
            params={"api_key": api_key, "email": email},
            timeout=12,
        )
        r.raise_for_status()
        data = r.json()

        deliverability = (data.get("deliverability") or "").upper()
        quality = data.get("quality_score")
        try:
            conf = float(quality) if quality is not None else None
        except Exception:
            conf = None

        if deliverability == "DELIVERABLE":
            return ApiResult("Abstract", True, True, conf, "Deliverable")
        if deliverability == "UNDELIVERABLE":
            return ApiResult("Abstract", True, False, conf, "Undeliverable")
        if deliverability == "RISKY":
            return ApiResult("Abstract", True, None, conf, "Risky")
        return ApiResult("Abstract", True, None, conf, "Unknown")

    except requests.RequestException as e:
        return ApiResult("Abstract", True, None, None, f"HTTP error: {e}")
    except Exception as e:
        return ApiResult("Abstract", True, None, None, f"Error: {e}")
