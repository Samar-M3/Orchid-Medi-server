from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Callable

from models import Alert, AccessLogEntry


USER_DEPARTMENTS = {
    "dr-asha": "cardiology",
    "nurse-bikash": "emergency",
    "clerk-sita": "billing",
    "dr-karma": "oncology",
    "night-nabin": "icu",
}

SENSITIVE_PATIENT_IDS = {"P-SENSITIVE-001", "P-SENSITIVE-002", "P-SENSITIVE-003"}

AUTHORIZED_CARE_TEAM = {
    "P-SENSITIVE-001": {"dr-asha", "nurse-bikash"},
    "P-SENSITIVE-002": {"dr-karma"},
    "P-SENSITIVE-003": {"night-nabin"},
}


class RuleEngine:
    def __init__(
        self,
        historical_average_per_hour: dict[str, float] | None = None,
        trend_logger: Callable[[AccessLogEntry, list[str]], None] | None = None,
    ) -> None:
        self.historical_average_per_hour = historical_average_per_hour or {}
        self.trend_logger = trend_logger
        self.patient_access_window: dict[str, deque[tuple[datetime, str]]] = defaultdict(deque)
        self.access_rate_window: dict[str, deque[datetime]] = defaultdict(deque)

    def ingest(self, entry: AccessLogEntry) -> list[Alert]:
        triggered_rules = self._evaluate_rules(entry)

        if self.trend_logger:
            self.trend_logger(entry, [rule["name"] for rule in triggered_rules])

        if not triggered_rules:
            return []

        severity = "medium" if len(triggered_rules) == 1 else "high"
        if self._is_three_times_user_average(entry):
            severity = self._bump_severity(severity)
            triggered_rules.append(
                {
                    "name": "personal_baseline",
                    "reason": "current access rate is more than 3x this user's historical average",
                }
            )

        return [
            Alert(
                source="insider",
                severity=severity,
                title="Suspicious patient-record access",
                description=self._describe_alert(triggered_rules),
                affected_user=entry.user_id,
                details={"triggered_rules": triggered_rules},
            )
        ]

    def _evaluate_rules(self, entry: AccessLogEntry) -> list[dict[str, str]]:
        self._remember_entry(entry)
        triggered_rules: list[dict[str, str]] = []

        distinct_patients = {
            patient_id for _, patient_id in self.patient_access_window[entry.user_id]
        }
        if len(distinct_patients) > 40:
            triggered_rules.append(
                {
                    "name": "volume",
                    "reason": f"user accessed {len(distinct_patients)} distinct patients in 60 minutes",
                }
            )

        if (entry.timestamp.hour < 6 or entry.timestamp.hour > 22) and entry.role != "night_shift":
            triggered_rules.append(
                {
                    "name": "time",
                    "reason": f"access occurred at {entry.timestamp.hour:02d}:00 outside normal hours",
                }
            )

        expected_department = USER_DEPARTMENTS.get(entry.user_id)
        if expected_department and entry.department != expected_department:
            triggered_rules.append(
                {
                    "name": "department_mismatch",
                    "reason": f"user belongs to {expected_department}, not {entry.department}",
                }
            )

        if entry.action == "export" and entry.record_count > 20:
            triggered_rules.append(
                {
                    "name": "bulk_export",
                    "reason": f"single export included {entry.record_count} records",
                }
            )

        authorized_users = AUTHORIZED_CARE_TEAM.get(entry.patient_id, set())
        if entry.patient_id in SENSITIVE_PATIENT_IDS and entry.user_id not in authorized_users:
            triggered_rules.append(
                {
                    "name": "sensitive_category",
                    "reason": "sensitive patient category accessed by a user outside the care team",
                }
            )

        return triggered_rules

    def _remember_entry(self, entry: AccessLogEntry) -> None:
        one_hour_ago = entry.timestamp - timedelta(minutes=60)
        patient_window = self.patient_access_window[entry.user_id]
        access_window = self.access_rate_window[entry.user_id]

        patient_window.append((entry.timestamp, entry.patient_id))
        access_window.append(entry.timestamp)

        while patient_window and patient_window[0][0] < one_hour_ago:
            patient_window.popleft()
        while access_window and access_window[0] < one_hour_ago:
            access_window.popleft()

    def _is_three_times_user_average(self, entry: AccessLogEntry) -> bool:
        current_hourly_rate = len(self.access_rate_window[entry.user_id])
        historical_average = self.historical_average_per_hour.get(entry.user_id, 10.0)
        return current_hourly_rate >= historical_average * 3

    @staticmethod
    def _bump_severity(severity: str) -> str:
        order = ["low", "medium", "high", "critical"]
        return order[min(order.index(severity) + 1, len(order) - 1)]

    @staticmethod
    def _describe_alert(triggered_rules: list[dict[str, str]]) -> str:
        parts = [f"{rule['name']}: {rule['reason']}" for rule in triggered_rules]
        return "Triggered rules: " + "; ".join(parts)
