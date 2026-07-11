from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from suspicious_store import get_cached_ip_reputation, save_cached_ip_reputation

ABUSE_IPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def lookup_abuse_confidence_score(ip: str, cache_ttl_minutes: int) -> int | None:
    cached = get_cached_ip_reputation(ip)
    if cached:
        checked_at = datetime.fromisoformat(cached["checked_at"])
        if checked_at.tzinfo is None:
            checked_at = checked_at.replace(tzinfo=timezone.utc)
            
        if checked_at >= datetime.now(timezone.utc) - timedelta(minutes=cache_ttl_minutes):
            return int(cached["abuse_confidence_score"])

    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return None

    params = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
    request = urllib.request.Request(
        f"{ABUSE_IPDB_URL}?{params}",
        headers={"Accept": "application/json", "Key": api_key},
    )

    try:
        with urllib.request.urlopen(request, timeout=4) as response:
            payload = json.loads(response.read().decode("utf-8"))
            score = int(payload["data"]["abuseConfidenceScore"])
            save_cached_ip_reputation(ip, score)
            return score
    except (urllib.error.URLError, urllib.error.HTTPError, KeyError, ValueError, json.JSONDecodeError):
        return None
