from __future__ import annotations

from collections import defaultdict
from time import time
from typing import Optional

from fastapi import Request
from fastapi.responses import JSONResponse, HTMLResponse


# Track attempts per IP: {ip: [(timestamp, ...], ...}
_attempts: dict[str, list[float]] = defaultdict(list)
MAX_ATTEMPTS = 10
WINDOW_SECONDS = 300  # 5 minutes


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _cleanup(ip: str) -> None:
    cutoff = time() - WINDOW_SECONDS
    _attempts[ip] = [t for t in _attempts[ip] if t > cutoff]
    if not _attempts[ip]:
        del _attempts[ip]


def check_rate_limit(request: Request) -> bool:
    """Returns True if the request should be allowed, False if rate limited."""
    ip = _get_client_ip(request)
    _cleanup(ip)
    if len(_attempts[ip]) >= MAX_ATTEMPTS:
        return False
    _attempts[ip].append(time())
    return True


def rate_limit_response_html() -> HTMLResponse:
    return HTMLResponse(
        "<p>Too many attempts. Please wait a few minutes and try again.</p>",
        status_code=429,
    )


def rate_limit_response_json() -> JSONResponse:
    return JSONResponse(
        {"status": "error", "message": "Too many attempts. Please wait a few minutes."},
        status_code=429,
    )
