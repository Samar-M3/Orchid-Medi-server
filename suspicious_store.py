from __future__ import annotations

import json
from datetime import datetime

from alert_store import get_connection
from suspicious_models import ActivityEvent, SuspiciousActivity


def init_detection_db() -> None:
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                role TEXT NOT NULL,
                action TEXT NOT NULL,
                resource TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                ip TEXT NOT NULL,
                user_agent TEXT NOT NULL,
                status_code INTEGER NOT NULL,
                timestamp TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_events_user_timestamp ON events(user_id, timestamp)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_events_ip_timestamp ON events(ip, timestamp)
            """
        )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS suspicious_activity (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                ip TEXT,
                rule_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                details TEXT NOT NULL,
                event_ids TEXT NOT NULL,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL,
                window_start TEXT,
                window_end TEXT
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_suspicious_created ON suspicious_activity(created_at)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_suspicious_status ON suspicious_activity(status)
            """
        )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS malicious_ip_cache (
                ip TEXT PRIMARY KEY,
                abuse_confidence_score INTEGER NOT NULL,
                checked_at TEXT NOT NULL
            )
            """
        )


def save_event(event: ActivityEvent) -> ActivityEvent:
    with get_connection() as connection:
        connection.execute(
            """
            INSERT OR REPLACE INTO events (
                id, user_id, role, action, resource, resource_type, ip, user_agent, status_code, timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.id,
                event.user_id,
                event.role,
                event.action,
                event.resource,
                event.resource_type,
                event.ip,
                event.user_agent,
                event.status_code,
                event.timestamp.isoformat(),
            ),
        )
    return event


def get_recent_events(limit: int = 5000) -> list[ActivityEvent]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT * FROM events
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [row_to_event(row) for row in reversed(rows)]


def get_events_between(start: datetime, end: datetime) -> list[ActivityEvent]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT * FROM events
            WHERE timestamp >= ? AND timestamp <= ?
            ORDER BY timestamp ASC
            """,
            (start.isoformat(), end.isoformat()),
        ).fetchall()
    return [row_to_event(row) for row in rows]


def save_suspicious_activity(activity: SuspiciousActivity) -> SuspiciousActivity:
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO suspicious_activity (
                id, user_id, ip, rule_id, severity, details, event_ids, created_at, status, window_start, window_end
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                activity.id,
                activity.user_id,
                activity.ip,
                activity.rule_id,
                activity.severity,
                json.dumps(activity.details),
                json.dumps(activity.event_ids),
                activity.created_at.isoformat(),
                activity.status,
                activity.window_start.isoformat() if activity.window_start else None,
                activity.window_end.isoformat() if activity.window_end else None,
            ),
        )
    return activity


def find_open_duplicate(
    rule_id: str,
    user_id: str | None,
    ip: str | None,
) -> SuspiciousActivity | None:
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT * FROM suspicious_activity
            WHERE rule_id = ?
              AND status = 'open'
              AND (user_id IS ? OR user_id = ?)
              AND (ip IS ? OR ip = ?)
            LIMIT 1
            """,
            (rule_id, user_id, user_id, ip, ip),
        ).fetchone()
    return row_to_suspicious(row) if row else None


def update_suspicious_activity(
    activity_id: str,
    details: dict,
    event_ids: list[str],
    window_end: datetime | None,
) -> SuspiciousActivity | None:
    with get_connection() as connection:
        connection.execute(
            """
            UPDATE suspicious_activity
            SET details = ?, event_ids = ?, window_end = ?
            WHERE id = ?
            """,
            (
                json.dumps(details),
                json.dumps(event_ids),
                window_end.isoformat() if window_end else None,
                activity_id,
            ),
        )
        row = connection.execute(
            "SELECT * FROM suspicious_activity WHERE id = ?", (activity_id,)
        ).fetchone()
    return row_to_suspicious(row) if row else None


def query_suspicious_activity(filters: dict) -> list[SuspiciousActivity]:
    where_clauses = []
    params: list[str] = []

    if filters.get("status"):
        where_clauses.append("status = ?")
        params.append(filters["status"])
    if filters.get("severity"):
        where_clauses.append("severity = ?")
        params.append(filters["severity"])
    if filters.get("user_id"):
        where_clauses.append("user_id = ?")
        params.append(filters["user_id"])
    if filters.get("rule_id"):
        where_clauses.append("rule_id = ?")
        params.append(filters["rule_id"])
    if filters.get("date_from"):
        where_clauses.append("created_at >= ?")
        params.append(filters["date_from"])
    if filters.get("date_to"):
        where_clauses.append("created_at <= ?")
        params.append(filters["date_to"])
    if filters.get("search"):
        search_pattern = f"%{filters['search']}%"
        where_clauses.append("(COALESCE(user_id, '') LIKE ? OR COALESCE(ip, '') LIKE ? OR rule_id LIKE ? OR details LIKE ?)")
        params.extend([search_pattern] * 4)

    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

    with get_connection() as connection:
        rows = connection.execute(
            f"""
            SELECT * FROM suspicious_activity
            {where_sql}
            ORDER BY created_at DESC
            LIMIT 500
            """,
            params,
        ).fetchall()
    return [row_to_suspicious(row) for row in rows]


def get_suspicious_activity_by_id(activity_id: str) -> SuspiciousActivity | None:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM suspicious_activity WHERE id = ?",
            (activity_id,),
        ).fetchone()
    return row_to_suspicious(row) if row else None

def update_suspicious_window(activity_id: str, details: dict, event_ids: list[str], window_end: datetime) -> SuspiciousActivity | None:
    with get_connection() as connection:
        connection.execute(
            """
            UPDATE suspicious_activity
            SET details = ?, event_ids = ?, window_end = ?
            WHERE id = ?
            """,
            (json.dumps(details), json.dumps(event_ids), window_end.isoformat(), activity_id),
        )
        row = connection.execute(
            "SELECT * FROM suspicious_activity WHERE id = ?", (activity_id,)
        ).fetchone()
    return row_to_suspicious(row) if row else None

def update_suspicious_status(activity_id: str, status: str) -> SuspiciousActivity | None:
    with get_connection() as connection:
        connection.execute(
            "UPDATE suspicious_activity SET status = ? WHERE id = ?",
            (status, activity_id),
        )
        row = connection.execute(
            "SELECT * FROM suspicious_activity WHERE id = ?",
            (activity_id,),
        ).fetchone()
    return row_to_suspicious(row) if row else None


def save_cached_ip_reputation(ip: str, score: int) -> None:
    with get_connection() as connection:
        connection.execute(
            """
            INSERT OR REPLACE INTO malicious_ip_cache (ip, abuse_confidence_score, checked_at)
            VALUES (?, ?, ?)
            """,
            (ip, score, datetime.utcnow().isoformat()),
        )


def get_cached_ip_reputation(ip: str) -> dict | None:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM malicious_ip_cache WHERE ip = ?",
            (ip,),
        ).fetchone()
    if not row:
        return None
    return {
        "ip": row["ip"],
        "abuse_confidence_score": row["abuse_confidence_score"],
        "checked_at": row["checked_at"],
    }


def row_to_event(row) -> ActivityEvent:
    return ActivityEvent(
        id=row["id"],
        user_id=row["user_id"],
        role=row["role"],
        action=row["action"],
        resource=row["resource"],
        resource_type=row["resource_type"],
        ip=row["ip"],
        user_agent=row["user_agent"],
        status_code=row["status_code"],
        timestamp=datetime.fromisoformat(row["timestamp"]),
    )


def row_to_suspicious(row) -> SuspiciousActivity:
    return SuspiciousActivity(
        id=row["id"],
        user_id=row["user_id"],
        ip=row["ip"],
        rule_id=row["rule_id"],
        severity=row["severity"],
        details=json.loads(row["details"]),
        event_ids=json.loads(row["event_ids"]),
        created_at=datetime.fromisoformat(row["created_at"]),
        status=row["status"],
        window_start=datetime.fromisoformat(row["window_start"]) if row["window_start"] else None,
        window_end=datetime.fromisoformat(row["window_end"]) if row["window_end"] else None,
    )
