"""Telegram Web App init-data verification without trusting browser identity."""

from __future__ import annotations

import hashlib
import hmac
import time
from urllib.parse import parse_qsl


def validate_init_data(init_data: str, bot_token: str, max_age_seconds: int = 3600) -> bool:
    """Validate Telegram's signed query string and reject stale payloads."""

    values = dict(parse_qsl(init_data, keep_blank_values=True))
    supplied_hash = values.pop("hash", "")
    if not supplied_hash or not values.get("auth_date", "").isdigit():
        return False
    if abs(time.time() - int(values["auth_date"])) > max_age_seconds:
        return False
    check_string = "\n".join(f"{key}={values[key]}" for key in sorted(values))
    secret = hmac.new(b"WebAppData", bot_token.encode(), hashlib.sha256).digest()
    expected = hmac.new(secret, check_string.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, supplied_hash)
