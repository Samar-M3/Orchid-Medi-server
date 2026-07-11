from __future__ import annotations

from suspicious_models import ActivityEvent, RuleEvaluation


def detect_privilege_escalation(
    event: ActivityEvent,
    _recent_events: list[ActivityEvent],
    config: dict,
) -> RuleEvaluation:
    admin_only_actions = set(config["admin_only_actions"])
    endpoint_keywords = tuple(config["admin_endpoint_keywords"])
    touches_admin_resource = any(keyword in event.resource for keyword in endpoint_keywords)

    flagged = event.role != "admin" and (event.action in admin_only_actions or touches_admin_resource)
    details = {
        "role": event.role,
        "action": event.action,
        "resource": event.resource,
        "admin_only_actions": sorted(admin_only_actions),
    }
    return RuleEvaluation(flagged=flagged, details=details, event_ids=[event.id])
