from __future__ import annotations

from datetime import datetime, timedelta

from suspicious_models import ActivityEvent


BASE_TIME = datetime(2026, 7, 11, 12, 0, 0)


def make_event(
    *,
    user_id: str = "user-1",
    role: str = "viewer",
    action: str = "view",
    resource: str = "reports/1",
    resource_type: str = "report",
    ip: str = "10.0.0.1",
    status_code: int = 200,
    seconds_offset: int = 0,
) -> ActivityEvent:
    return ActivityEvent(
        user_id=user_id,
        role=role,
        action=action,
        resource=resource,
        resource_type=resource_type,
        ip=ip,
        user_agent="pytest",
        status_code=status_code,
        timestamp=BASE_TIME + timedelta(seconds=seconds_offset),
    )
