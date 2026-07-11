from __future__ import annotations

from suspicious_models import ActivityEvent, RuleEvaluation


def detect_access_outside_role(
    event: ActivityEvent,
    _recent_events: list[ActivityEvent],
    config: dict,
    role_permissions: dict[str, list[str]],
) -> RuleEvaluation:
    allowed_actions = set(role_permissions.get(event.role, []))
    flagged = bool(allowed_actions) and event.action not in allowed_actions
    details = {
        "role": event.role,
        "action": event.action,
        "allowed_actions": sorted(allowed_actions),
    }
    return RuleEvaluation(flagged=flagged, details=details, event_ids=[event.id])
