#!/usr/bin/env python3
"""
check_email.py — email verifier and finder

Features
- Syntax validation (email-validator)
- MX/DNS check (dnspython) — robust to varying dnspython RDATA shapes
- Three optional API fallbacks (Abstract + MailboxLayer + Hunter.io) loaded from .env
- Email finding via Hunter.io API
- Clear CLI output

Environment (.env)
  ABSTRACT_API_KEY=...
  MAILBOXLAYER_API_KEY=...
  HUNTER_API_KEY=...

Usage
  # Email verification
  python check_email.py EMAIL [--no-apis]

  # Email finding
  python check_email.py --find --domain DOMAIN --first-name FNAME --last-name LNAME
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from typing import List, Optional, Tuple

import click
import dns.resolver
from dns.exception import Timeout as DnsTimeout  # ✅ explicit import fixes Pylance
from dotenv import load_dotenv
from email_validator import EmailNotValidError, validate_email

from apis.abstract import call_abstract
from apis.hunter import call_hunter, find_email
from apis.mailboxlayer import call_mailboxlayer
from apis.models import ApiResult, EmailFinderResult

# --------------------------
# Data models
# --------------------------


@dataclass
class BasicChecks:
    syntax_valid: bool
    normalized_email: Optional[str]
    domain: Optional[str]
    mx_ok: bool
    primary_mx: Optional[str]
    notes: List[str]


# ApiResult is now imported from apis.models


# --------------------------
# Utilities
# --------------------------


def normalize_email(email: str) -> Tuple[bool, Optional[str], Optional[str], List[str]]:
    """Validate syntax only; return (valid, normalized, domain, notes)."""
    notes: List[str] = []
    try:
        v = validate_email(email, check_deliverability=False)
        return True, v.email, v.domain, notes
    except EmailNotValidError as e:
        notes.append(f"Syntax error: {e}")
        return False, None, None, notes


def _parse_mx_rdata(rdata) -> Tuple[Optional[int], Optional[str]]:
    """
    Return (preference, host) from an MX rdata entry, tolerating different dnspython shapes.
    """
    pref = None
    host = None

    if hasattr(rdata, "preference"):
        pref = getattr(rdata, "preference", None)
    if hasattr(rdata, "exchange"):
        exch = getattr(rdata, "exchange", None)
        if exch is not None:
            host = getattr(exch, "to_text", lambda **_: str(exch))()
    if host and host.endswith("."):
        host = host[:-1]

    if pref is None or host is None:
        try:
            parts = rdata.to_text().split()
            if len(parts) >= 2:
                try:
                    pref = int(parts[0])
                except Exception:
                    pass
                host = parts[1].rstrip(".")
        except Exception:
            pass

    return pref, host


def mx_lookup(
    domain: str, timeout_sec: float = 5.0
) -> Tuple[bool, Optional[str], List[str]]:
    """
    Look up MX records. Returns (mx_ok, primary_mx, notes).
    Primary MX is the lowest-preference (best) host.
    """
    notes: List[str] = []
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=timeout_sec)
        mx_rows: List[Tuple[int, str]] = []
        for r in answers:
            pref, host = _parse_mx_rdata(r)
            if pref is not None and host:
                mx_rows.append((pref, host))

        if not mx_rows:
            notes.append("MX lookup returned no usable records.")
            return False, None, notes

        mx_rows.sort(key=lambda t: t[0])
        primary = mx_rows[0][1]
        return True, primary, notes

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
        notes.append(f"MX lookup: {e.__class__.__name__}")
        return False, None, notes
    except DnsTimeout:  # ✅ explicit timeout class
        notes.append("MX lookup: timeout")
        return False, None, notes
    except Exception as e:
        notes.append(f"MX lookup error: {e}")
        return False, None, notes


# API clients are now in separate modules


# --------------------------
# Decision logic
# --------------------------


def combine_results(
    basic: BasicChecks, a1: ApiResult, a2: ApiResult
) -> Tuple[str, str]:
    if not basic.syntax_valid:
        return ("DO NOT SEND", "Invalid syntax.")
    if not basic.mx_ok:
        return ("DO NOT SEND", "Domain has no valid MX records.")
    if (a1.used and a1.ok is False) or (a2.used and a2.ok is False):
        return ("DO NOT SEND", "An API reported undeliverable.")
    if (a1.used and a1.ok is True) or (a2.used and a2.ok is True):
        return (
            "LIKELY OK TO SEND",
            "At least one API reported deliverable; basics passed.",
        )
    return (
        "RISKY / UNKNOWN",
        "Basics passed, but API confidence is unavailable or inconclusive.",
    )


def print_email_finder_results(
    result: EmailFinderResult, domain: str, first_name: str, last_name: str
) -> None:
    """Print email finder results in a formatted way."""
    print("\n================ Email Finder =================")
    print(f"🔍 Search:          {first_name} {last_name} @ {domain}")
    print(f"🏢 Service:         {result.name}")
    print(f"📊 Used:            {'yes' if result.used else 'no'}")

    if result.found and result.email:
        print(f"✅ Found:           {result.email}")
        if result.confidence is not None:
            print(f"🎯 Confidence:      {result.confidence:.1%}")
        if result.sources:
            print(f"📍 Sources:         {len(result.sources)} source(s)")
            for i, source in enumerate(result.sources[:3], 1):  # Show first 3 sources
                print(f"   {i}. {source}")
            if len(result.sources) > 3:
                print(f"   ... and {len(result.sources) - 3} more")
    else:
        print("❌ Found:           No")

    print(f"💡 Detail:          {result.detail}")
    print("============================================\n")


# --------------------------
# CLI
# --------------------------


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("email", required=False)
@click.option("--no-apis", is_flag=True, help="Skip API fallbacks; only run syntax+MX.")
@click.option(
    "--find",
    is_flag=True,
    help="Find emails instead of verifying (requires --domain, --first-name, --last-name)",
)
@click.option("--domain", help="Domain name for email finding")
@click.option("--first-name", help="First name for email finding")
@click.option("--last-name", help="Last name for email finding")
def main(
    email: Optional[str],
    no_apis: bool,
    find: bool,
    domain: Optional[str],
    first_name: Optional[str],
    last_name: Optional[str],
) -> None:
    load_dotenv()
    abstract_key = os.getenv("ABSTRACT_API_KEY")
    mailboxlayer_key = os.getenv("MAILBOXLAYER_API_KEY")
    hunter_key = os.getenv("HUNTER_IO_API_KEY")

    # Handle email finding mode
    if find:
        if not domain or not first_name or not last_name:
            print(
                "\n❌ Error: --find mode requires --domain, --first-name, and --last-name"
            )
            return

        result = find_email(domain, first_name, last_name, hunter_key)
        print_email_finder_results(result, domain, first_name, last_name)
        return

    # Handle email verification mode
    if not email:
        print("\n❌ Error: EMAIL argument is required for verification mode")
        return

    # At this point email is guaranteed to be non-None
    assert email is not None
    syntax_valid, normalized, domain, notes = normalize_email(email)
    mx_ok = False
    primary_mx = None
    mx_notes: List[str] = []
    if syntax_valid and domain:
        mx_ok, primary_mx, mx_notes = mx_lookup(domain)

    basic = BasicChecks(
        syntax_valid=syntax_valid,
        normalized_email=normalized,
        domain=domain,
        mx_ok=mx_ok,
        primary_mx=primary_mx,
        notes=[*notes, *mx_notes],
    )

    api1 = ApiResult("Abstract", False, None, None, "Skipped")
    api2 = ApiResult("MailboxLayer", False, None, None, "Skipped")

    hunter_api = ApiResult("Hunter", False, None, None, "Skipped")

    if not no_apis:
        # Try Hunter first if available
        if hunter_key:
            hunter_api = call_hunter(email, hunter_key)
            if hunter_api.ok is not None:
                # Hunter gave us a definitive answer, use it as primary
                api1 = hunter_api
                api2 = ApiResult(
                    "MailboxLayer", False, None, None, "Skipped (Hunter succeeded)"
                )
            else:
                # Hunter was inconclusive, try other APIs
                api1 = (
                    call_abstract(email, abstract_key)
                    if abstract_key
                    else ApiResult("Abstract", False, None, None, "No API key")
                )
                if api1.ok is None:
                    api2 = (
                        call_mailboxlayer(email, mailboxlayer_key)
                        if mailboxlayer_key
                        else ApiResult("MailboxLayer", False, None, None, "No API key")
                    )
                else:
                    api2 = ApiResult(
                        "MailboxLayer",
                        False,
                        None,
                        None,
                        "Skipped (Abstract succeeded)",
                    )
        else:
            # No Hunter key, use original flow
            api1 = (
                call_abstract(email, abstract_key)
                if abstract_key
                else ApiResult("Abstract", False, None, None, "No API key")
            )
            if api1.ok is None:
                api2 = (
                    call_mailboxlayer(email, mailboxlayer_key)
                    if mailboxlayer_key
                    else ApiResult("MailboxLayer", False, None, None, "No API key")
                )
            else:
                api2 = ApiResult(
                    "MailboxLayer", False, None, None, "Skipped (Abstract succeeded)"
                )

    verdict, rationale = combine_results(basic, api1, api2)

    print("\n================ Email Check =================")
    print(f"📧 Email:           {email}")
    if basic.normalized_email and basic.normalized_email != email:
        print(f"↪︎ Normalized:      {basic.normalized_email}")
    print(f"✅ Syntax:          {'valid' if basic.syntax_valid else 'invalid'}")
    print(f"🧩 Domain:          {basic.domain or '-'}")
    print(f"📮 MX records:      {'found' if basic.mx_ok else 'not found'}")
    if basic.primary_mx:
        print(f"   Primary MX:      {basic.primary_mx}")
    if basic.notes:
        for n in basic.notes:
            print(f"   note: {n}")

    print("\n---- API Fallbacks ----")

    def line(api: ApiResult) -> str:
        used = "used" if api.used else "skipped"
        ok_map = {True: "deliverable", False: "undeliverable", None: "unknown"}
        conf = (
            f", conf={api.confidence:.2f}" if isinstance(api.confidence, float) else ""
        )
        return f"{api.name:13s} {used:7s} → {ok_map[api.ok]}{conf} — {api.detail}"

    print(line(api1))
    print(line(api2))
    if hunter_api.used:
        print(line(hunter_api))

    print("\n============================================")
    icon = {"DO NOT SEND": "🚫", "LIKELY OK TO SEND": "✅", "RISKY / UNKNOWN": "⚠️"}[
        verdict
    ]
    print(f"{icon} Verdict: {verdict}")
    print(f"💡 Why:    {rationale}")
    print("============================================\n")


if __name__ == "__main__":
    # Keep HTTP from hanging forever
    socket.setdefaulttimeout(10)
    main()
