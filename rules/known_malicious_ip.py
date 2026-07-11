from __future__ import annotations

from suspicious_models import ActivityEvent, RuleEvaluation


def detect_known_malicious_ip(
    event: ActivityEvent,
    _recent_events: list[ActivityEvent],
    config: dict,
    abuse_score: int | None,
) -> RuleEvaluation:
    if abuse_score is None:
        return RuleEvaluation(flagged=False, details={"checked": False, "reason": "no_threat_intel"}, event_ids=[])

    threshold = int(config["abuse_score_threshold"])
    flagged = abuse_score >= threshold
    details = {
        "checked": True,
        "abuse_confidence_score": abuse_score,
        "abuse_score_threshold": threshold,
    }
    return RuleEvaluation(flagged=flagged, details=details, event_ids=[event.id])
