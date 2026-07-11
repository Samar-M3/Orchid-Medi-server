from __future__ import annotations

from datetime import timedelta

from suspicious_models import ActivityEvent, RuleEvaluation


def detect_scraping_pattern(
    event: ActivityEvent,
    recent_events: list[ActivityEvent],
    config: dict,
) -> RuleEvaluation:
    window_minutes = config["window_minutes"]
    threshold = config["distinct_resource_threshold"]
    window_start = event.timestamp - timedelta(minutes=window_minutes)

    in_window = [
        item
        for item in recent_events
        if item.user_id == event.user_id and item.timestamp >= window_start
    ]
    distinct_resources = sorted({item.resource for item in in_window})
    flagged = len(distinct_resources) >= threshold

    details = {
        "window_minutes": window_minutes,
        "distinct_resource_count": len(distinct_resources),
        "distinct_resource_threshold": threshold,
    }
    return RuleEvaluation(flagged=flagged, details=details, event_ids=[item.id for item in in_window])
