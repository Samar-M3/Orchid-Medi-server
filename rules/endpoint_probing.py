from __future__ import annotations

from datetime import timedelta

from suspicious_models import ActivityEvent, RuleEvaluation


def detect_endpoint_probing(
    event: ActivityEvent,
    recent_events: list[ActivityEvent],
    config: dict,
) -> RuleEvaluation:
    window_minutes = int(config["window_minutes"])
    threshold = int(config["threshold"])
    status_codes = set(config["status_codes"])

    window_start = event.timestamp - timedelta(minutes=window_minutes)
    in_window = [
        item
        for item in recent_events
        if item.ip == event.ip and item.timestamp >= window_start and item.status_code in status_codes
    ]

    flagged = len(in_window) >= threshold
    details = {
        "window_minutes": window_minutes,
        "status_codes": sorted(status_codes),
        "error_count": len(in_window),
        "threshold": threshold,
    }
    return RuleEvaluation(flagged=flagged, details=details, event_ids=[item.id for item in in_window])
