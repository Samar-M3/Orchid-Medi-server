from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from detection_config import DETECTION_CONFIG
from rules.access_outside_role import detect_access_outside_role
from rules.single_data_access import detect_single_data_access
from rules.bot_like_timing import detect_bot_like_timing
from rules.bulk_data_access import detect_bulk_data_access
from rules.endpoint_probing import detect_endpoint_probing
from rules.ip_traffic_spike import detect_ip_traffic_spike
from rules.known_malicious_ip import detect_known_malicious_ip
from rules.privilege_escalation import detect_privilege_escalation
from rules.scraping_pattern import detect_scraping_pattern
from suspicious_models import ActivityEvent, SuspiciousActivity
from suspicious_store import (
    find_open_duplicate,
    get_events_between,
    get_recent_events,
    save_suspicious_activity,
     update_suspicious_activity,
)
from threat_intel import lookup_abuse_confidence_score


class DetectionEvaluator:
    def __init__(self, config: dict | None = None) -> None:
        self.config = config or DETECTION_CONFIG

    def evaluate_event(
        self,
        event: ActivityEvent,
        recent_events_for_context: list[ActivityEvent],
    ) -> list[SuspiciousActivity]:
        results: list[SuspiciousActivity] = []

        immediate_rule_specs = [
            (
                "single_data_access",
                detect_single_data_access(
                    event,
                    self.config["rules"]["single_data_access"],
                ),
                event.user_id,
                event.ip,
                event.timestamp,
            ),
            (
                "access_outside_role",
                detect_access_outside_role(
                    event,
                    recent_events_for_context,
                    self.config["rules"]["access_outside_role"],
                    self.config["role_permissions"],
                ),
                event.user_id,
                event.ip,
                event.timestamp,
            ),
            (
                "privilege_escalation",
                detect_privilege_escalation(
                    event,
                    recent_events_for_context,
                    self.config["rules"]["privilege_escalation"],
                ),
                event.user_id,
                event.ip,
                event.timestamp,
            ),
        ]

        malicious_confidence = lookup_abuse_confidence_score(
            event.ip,
            self.config["rules"]["known_malicious_ip"]["cache_ttl_minutes"],
        )
        immediate_rule_specs.append(
            (
                "known_malicious_ip",
                detect_known_malicious_ip(
                    event,
                    recent_events_for_context,
                    self.config["rules"]["known_malicious_ip"],
                    malicious_confidence,
                ),
                event.user_id,
                event.ip,
                event.timestamp,
            )
        )

        for rule_id, evaluation, user_id, ip, event_time in immediate_rule_specs:
            if evaluation.flagged:
                activity = self._store_if_new(
                    rule_id=rule_id,
                    severity=self.config["rules"][rule_id]["severity"],
                    user_id=user_id,
                    ip=ip,
                    details=evaluation.details,
                    event_ids=evaluation.event_ids,
                    window_start=event_time,
                    window_end=event_time,
                )
                if activity:
                    results.append(activity)

        return results

    def run_scheduled_scan(self, now: datetime | None = None) -> list[SuspiciousActivity]:
        scan_time = now or datetime.now(timezone.utc)
        max_window = max(
            self.config["rules"]["bulk_data_access"]["window_minutes"],
            self.config["rules"]["scraping_pattern"]["window_minutes"],
            self.config["rules"]["endpoint_probing"]["window_minutes"],
            self.config["rules"]["ip_traffic_spike"]["window_minutes"],
        )
        window_start = scan_time - timedelta(minutes=max_window)

        recent_events = get_events_between(window_start, scan_time)
        if not recent_events:
            return []

        by_user: dict[str, list[ActivityEvent]] = defaultdict(list)
        by_ip: dict[str, list[ActivityEvent]] = defaultdict(list)
        for event in recent_events:
            by_user[event.user_id].append(event)
            by_ip[event.ip].append(event)

        activities: list[SuspiciousActivity] = []

        for user_id, events in by_user.items():
            latest_event = events[-1]
            user_rules = [
                ("bulk_data_access", detect_bulk_data_access(latest_event, recent_events, self.config["rules"]["bulk_data_access"])),
                ("scraping_pattern", detect_scraping_pattern(latest_event, recent_events, self.config["rules"]["scraping_pattern"])),
                ("bot_like_timing", detect_bot_like_timing(latest_event, recent_events, self.config["rules"]["bot_like_timing"])),
            ]
            for rule_id, evaluation in user_rules:
                if evaluation.flagged:
                    activity = self._store_if_new(
                        rule_id=rule_id,
                        severity=self.config["rules"][rule_id]["severity"],
                        user_id=user_id,
                        ip=latest_event.ip,
                        details=evaluation.details,
                        event_ids=evaluation.event_ids,
                        window_start=window_start,
                        window_end=scan_time,
                    )
                    if activity:
                        activities.append(activity)

        for ip, events in by_ip.items():
            latest_event = events[-1]
            ip_rules = [
                ("endpoint_probing", detect_endpoint_probing(latest_event, recent_events, self.config["rules"]["endpoint_probing"])),
                ("ip_traffic_spike", detect_ip_traffic_spike(latest_event, recent_events, self.config["rules"]["ip_traffic_spike"])),
            ]
            for rule_id, evaluation in ip_rules:
                if evaluation.flagged:
                    activity = self._store_if_new(
                        rule_id=rule_id,
                        severity=self.config["rules"][rule_id]["severity"],
                        user_id=latest_event.user_id,
                        ip=ip,
                        details=evaluation.details,
                        event_ids=evaluation.event_ids,
                        window_start=window_start,
                        window_end=scan_time,
                    )
                    if activity:
                        activities.append(activity)

        return activities

    def _store_if_new(
        self,
        rule_id: str,
        severity: str,
        user_id: str | None,
        ip: str | None,
        details: dict,
        event_ids: list[str],
        window_start: datetime | None,
        window_end: datetime | None,
    ) -> SuspiciousActivity | None:
        duplicate = find_open_duplicate(rule_id, user_id, ip)
        if duplicate:
         return update_suspicious_activity(
        activity_id=duplicate.id,
        details=details,
        event_ids=event_ids,
        window_end=window_end,
    )

        activity = SuspiciousActivity(
            user_id=user_id,
            ip=ip,
            rule_id=rule_id,
            severity=severity,
            details=details,
            event_ids=event_ids,
            window_start=window_start,
            window_end=window_end,
        )
        return save_suspicious_activity(activity)


def get_context_events(limit: int = 5000) -> list[ActivityEvent]:
    return get_recent_events(limit=limit)


# Port scanning belongs at the network/WAF layer (for example Cloudflare, WAF logs, or fail2ban),
# not in this application-layer event detector.
