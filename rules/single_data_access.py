from suspicious_models import ActivityEvent, RuleEvaluation

def detect_single_data_access(
    event: ActivityEvent, config: dict
) -> RuleEvaluation:
    if event.action in config.get("actions", ["view", "download"]):
        return RuleEvaluation(
            flagged=True,
            details={
                "action": event.action,
                "resource": event.resource,
                "user_agent": event.user_agent,
                "status_code": event.status_code,
            },
            event_ids=[event.id],
        )
    return RuleEvaluation(flagged=False)
