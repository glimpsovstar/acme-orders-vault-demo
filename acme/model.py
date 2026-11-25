"""Shared types for the Acme Orders secret sources."""
from dataclasses import dataclass
from typing import Literal

DOTS = "••••••"

STATES = (
    "ok", "refused", "deleted", "destroyed", "gone",
    "waiting", "unreachable", "login_failed", "not_configured",
)


def mask(pw: str) -> str:
    """First 8 characters plus dots, or just dots when 8 characters or fewer."""
    if len(pw) <= 8:
        return DOTS
    return pw[:8] + DOTS


@dataclass
class SecretView:
    """What the page and the JSON endpoints show. Never holds a full password."""
    source: Literal["vault", "aws"]
    state: str
    version: int | None
    latest: int | None
    masked: str | None
    changed: str | None
    message: str
