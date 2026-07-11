from __future__ import annotations

from datetime import timedelta

from suspicious_models import ActivityEvent, RuleEvaluation


def detect_bulk_data_access(
    event: ActivityEvent,
    recent_events: list[ActivityEvent],
    config: dict,
) -> RuleEvaluation:
    window_minutes = config["window_minutes"]
    actions = set(config["actions"])
    threshold = config["count_threshold"]
    multiplier = float(config["historical_multiplier"])
    baseline_days = int(config["historical_window_days"])
    min_for_baseline = int(config["minimum_count_for_baseline"])

    window_start = event.timestamp - timedelta(minutes=window_minutes)
    in_window = [
        item
        for item in recent_events
        if item.user_id == event.user_id
        and item.timestamp >= window_start
        and item.action in actions
    ]

    current_count = len(in_window)

    baseline_start = event.timestamp - timedelta(days=baseline_days)
    baseline_events = [
        item
        for item in recent_events
        if item.user_id == event.user_id
        and baseline_start <= item.timestamp < window_start
        and item.action in actions
    ]

    hours = max(1.0, baseline_days * 24.0)
    baseline_hourly_avg = len(baseline_events) / hours
    baseline_threshold = max(min_for_baseline, int(baseline_hourly_avg * multiplier))

    baseline_triggered = (
        baseline_hourly_avg > 0
        and current_count >= baseline_threshold
        and current_count > min_for_baseline
    )
    flagged = current_count >= threshold or baseline_triggered
    details = {
        "window_minutes": window_minutes,
        "action_count": current_count,
        "count_threshold": threshold,
        "historical_hourly_avg": round(baseline_hourly_avg, 4),
        "historical_multiplier": multiplier,
        "baseline_threshold": baseline_threshold,
    }
    return RuleEvaluation(flagged=flagged, details=details, event_ids=[item.id for item in in_window])
