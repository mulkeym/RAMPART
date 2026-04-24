from __future__ import annotations

import os


def tls_verify() -> bool:
    """Return False if RAMPART_TLS_VERIFY is set to a falsy value."""
    value = os.getenv("RAMPART_TLS_VERIFY", "true")
    return value.strip().lower() not in {"0", "false", "no", "off"}
