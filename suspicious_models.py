from __future__ import annotations

from datetime import datetime, timezone
from statistics import mean
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field


EventAction = Literal[
    "login",
    "view",
    "edit",
    "download",
    "export",
    "delete",
    "manage_users",
    "change_role",
    "delete_user",
    "access_admin",
]
SuspiciousSeverity = Literal["low", "medium", "high"]
SuspiciousStatus = Literal["open", "reviewed", "dismissed"]


class ActivityEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    user_id: str
    role: str
    action: EventAction
    resource: str
    resource_type: str
    ip: str
    user_agent: str
    status_code: int
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SuspiciousActivity(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    user_id: str | None = None
    ip: str | None = None
    rule_id: str
    severity: SuspiciousSeverity
    details: dict
    event_ids: list[str]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: SuspiciousStatus = "open"
    window_start: datetime | None = None
    window_end: datetime | None = None


class RuleEvaluation(BaseModel):
    flagged: bool
    details: dict = Field(default_factory=dict)
    event_ids: list[str] = Field(default_factory=list)


def safe_mean(values: list[float]) -> float:
    return mean(values) if values else 0.0


def safe_stddev(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    avg = safe_mean(values)
    variance = sum((value - avg) ** 2 for value in values) / len(values)
    return variance ** 0.5
