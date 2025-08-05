"""Shared data models for email verification APIs."""

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class ApiResult:
    name: str
    used: bool
    ok: Optional[bool]  # True deliverable, False undeliverable, None unknown
    confidence: Optional[float]  # 0..1 if provided
    detail: str  # short human-readable summary


@dataclass
class EmailFinderResult:
    name: str
    used: bool
    found: bool
    email: Optional[str]
    confidence: Optional[float]  # 0..1 if provided
    sources: List[str]  # sources where email was found
    detail: str  # short human-readable summary
