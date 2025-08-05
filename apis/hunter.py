"""Hunter.io API email finder and verifier client."""

from typing import Optional

import requests

from .models import ApiResult, EmailFinderResult


def find_email(
    domain: str, first_name: str, last_name: str, api_key: Optional[str]
) -> EmailFinderResult:
    """Find email address using Hunter.io Email Finder API."""
    if not api_key:
        return EmailFinderResult("Hunter", False, False, None, None, [], "No API key")

    try:
        r = requests.get(
            "https://api.hunter.io/v2/email-finder",
            params={
                "api_key": api_key,
                "domain": domain,
                "first_name": first_name,
                "last_name": last_name,
            },
            timeout=15,
        )
        r.raise_for_status()
        data = r.json()

        if "data" not in data:
            return EmailFinderResult(
                "Hunter", True, False, None, None, [], "No data returned"
            )

        result = data["data"]
        email = result.get("email")
        confidence = result.get("confidence")
        sources = []

        # Extract sources if available
        if "sources" in result and isinstance(result["sources"], list):
            sources = [s.get("uri", "") for s in result["sources"] if s.get("uri")]

        if email and confidence is not None:
            conf_score = confidence / 100.0 if confidence > 1 else confidence
            return EmailFinderResult(
                "Hunter",
                True,
                True,
                email,
                conf_score,
                sources,
                f"Found with {confidence}% confidence",
            )
        elif email:
            return EmailFinderResult(
                "Hunter",
                True,
                True,
                email,
                None,
                sources,
                "Found (no confidence score)",
            )
        else:
            return EmailFinderResult(
                "Hunter", True, False, None, None, [], "No email found"
            )

    except requests.RequestException as e:
        return EmailFinderResult(
            "Hunter", True, False, None, None, [], f"HTTP error: {e}"
        )
    except Exception as e:
        return EmailFinderResult("Hunter", True, False, None, None, [], f"Error: {e}")


def call_hunter(email: str, api_key: Optional[str]) -> ApiResult:
    """Call Hunter.io Email Verifier API to verify email deliverability."""
    if not api_key:
        return ApiResult("Hunter", False, None, None, "No API key")

    try:
        r = requests.get(
            "https://api.hunter.io/v2/email-verifier",
            params={
                "api_key": api_key,
                "email": email,
            },
            timeout=15,
        )
        r.raise_for_status()
        data = r.json()

        if "data" not in data:
            return ApiResult("Hunter", True, None, None, "No data returned")

        result = data["data"]
        status = result.get("status", "").lower()
        score = result.get("score", None)

        # Convert score to confidence (0-100 -> 0-1)
        try:
            conf = (
                float(score) / 100.0
                if score is not None and score > 1
                else float(score) if score is not None else None
            )
        except Exception:
            conf = None

        # Map Hunter status to our boolean system
        if status == "valid":
            return ApiResult("Hunter", True, True, conf, "Valid")
        elif status == "invalid":
            return ApiResult("Hunter", True, False, conf, "Invalid")
        elif status == "accept_all":
            return ApiResult("Hunter", True, None, conf, "Accept all (risky)")
        elif status == "webmail":
            return ApiResult("Hunter", True, True, conf, "Webmail")
        elif status == "disposable":
            return ApiResult("Hunter", True, False, conf, "Disposable")
        else:
            return ApiResult("Hunter", True, None, conf, f"Unknown status: {status}")

    except requests.RequestException as e:
        return ApiResult("Hunter", True, None, None, f"HTTP error: {e}")
    except Exception as e:
        return ApiResult("Hunter", True, None, None, f"Error: {e}")
