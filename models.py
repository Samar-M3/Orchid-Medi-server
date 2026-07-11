from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field


AlertSource = Literal["insider", "ransomware", "phi_scanner", "override"]
AlertSeverity = Literal["low", "medium", "high", "critical"]
AlertStatus = Literal["new", "acknowledged", "resolved"]
AccessAction = Literal["view", "edit", "download", "print", "export"]


class Alert(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: AlertSource
    severity: AlertSeverity
    title: str
    description: str
    affected_user: str | None = None
    affected_device: str | None = None
    affected_file: str | None = None
    reason: str | None = None
    status: AlertStatus = "new"
    details: dict | None = None


class AccessLogEntry(BaseModel):
    timestamp: datetime
    user_id: str
    role: str
    department: str
    patient_id: str
    action: AccessAction
    record_count: int = 1
