from __future__ import annotations

from suspicious_models import ActivityEvent, RuleEvaluation, safe_mean, safe_stddev


def detect_bot_like_timing(
    event: ActivityEvent,
    recent_events: list[ActivityEvent],
    config: dict,
) -> RuleEvaluation:
    last_n = int(config["last_n_actions"])
    min_required_gaps = int(config["min_required_gaps"])
    avg_threshold = float(config["avg_gap_threshold_seconds"])
    stddev_threshold = float(config["stddev_gap_threshold_seconds"])

    user_events = sorted(
        [item for item in recent_events if item.user_id == event.user_id],
        key=lambda item: item.timestamp,
    )[-last_n:]

    if len(user_events) < 2:
        return RuleEvaluation(flagged=False, details={"reason": "not_enough_events"}, event_ids=[])

    gaps = [
        (user_events[index].timestamp - user_events[index - 1].timestamp).total_seconds()
        for index in range(1, len(user_events))
    ]

    avg_gap = safe_mean(gaps)
    stddev_gap = safe_stddev(gaps)

    flagged = len(gaps) >= min_required_gaps and (
        avg_gap <= avg_threshold or stddev_gap <= stddev_threshold
    )

    details = {
        "avg_gap_seconds": round(avg_gap, 4),
        "stddev_gap_seconds": round(stddev_gap, 4),
        "avg_gap_threshold_seconds": avg_threshold,
        "stddev_gap_threshold_seconds": stddev_threshold,
        "sample_size": len(gaps),
    }
    return RuleEvaluation(flagged=flagged, details=details, event_ids=[item.id for item in user_events])
