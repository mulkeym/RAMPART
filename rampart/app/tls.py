from __future__ import annotations

import os


def tls_verify() -> bool:
    """Return False if TLS verification is disabled via env var or runtime settings."""
    # Check env var first
    env_value = os.getenv("RAMPART_TLS_VERIFY")
    if env_value is not None:
        return env_value.strip().lower() not in {"0", "false", "no", "off"}
    # Check runtime settings
    try:
        from rampart.app.settings_store import load_settings
        from rampart.app.config import get_config
        settings = load_settings(get_config().settings.path)
        if settings.tls_verify is not None:
            return settings.tls_verify
    except Exception:
        pass
    return True
