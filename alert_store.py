import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

from models import Alert, AccessLogEntry


DB_PATH = Path(__file__).resolve().parent / "medishield.db"

def get_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    return connection

def init_db() -> None:
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                affected_user TEXT,
                affected_device TEXT,
                affected_file TEXT,
                reason TEXT,
                status TEXT NOT NULL
            )
            """
        )
        ensure_alerts_schema(connection)
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS access_trends (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user_id TEXT NOT NULL,
                role TEXT NOT NULL,
                department TEXT NOT NULL,
                patient_id TEXT NOT NULL,
                action TEXT NOT NULL,
                record_count INTEGER NOT NULL,
                triggered_rules TEXT NOT NULL
            )
            """
        )


def save_alert(alert: Alert) -> Alert:
    with get_connection() as connection:
        connection.execute(
            """
            INSERT OR REPLACE INTO alerts (
                id, timestamp, source, severity, title, description,
                affected_user, affected_device, affected_file, reason, status, details
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.id,
                alert.timestamp.isoformat(),
                alert.source,
                alert.severity,
                alert.title,
                alert.description,
                alert.affected_user,
                alert.affected_device,
                alert.affected_file,
                alert.reason,
                alert.status,
                json.dumps(alert.details) if alert.details else None,
            ),
        )
    return alert


def get_all_alerts(
    limit: int = 100,
    severity: str | None = None,
    status: str | None = None,
) -> list[Alert]:
    filters = []
    params: list[str | int] = []
    if severity:
        filters.append("severity = ?")
        params.append(severity)
    if status:
        filters.append("status = ?")
        params.append(status)

    where_clause = f"WHERE {' AND '.join(filters)}" if filters else ""
    params.append(limit)

    with get_connection() as connection:
        rows = connection.execute(
            f"""
            SELECT * FROM alerts
            {where_clause}
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            params,
        ).fetchall()

    return [row_to_alert(row) for row in rows]


def get_alert_summary_24h() -> dict[str, dict[str, int]]:
    cutoff = (datetime.utcnow() - timedelta(hours=24)).isoformat()
    with get_connection() as connection:
        severity_rows = connection.execute(
            """
            SELECT severity, COUNT(*) AS count
            FROM alerts
            WHERE timestamp >= ?
            GROUP BY severity
            """,
            (cutoff,),
        ).fetchall()
        source_rows = connection.execute(
            """
            SELECT source, COUNT(*) AS count
            FROM alerts
            WHERE timestamp >= ?
            GROUP BY source
            """,
            (cutoff,),
        ).fetchall()

    return {
        "by_severity": {row["severity"]: row["count"] for row in severity_rows},
        "by_source": {row["source"]: row["count"] for row in source_rows},
    }


def update_alert_status(id: str, new_status: str) -> Alert | None:
    with get_connection() as connection:
        connection.execute(
            "UPDATE alerts SET status = ? WHERE id = ?",
            (new_status, id),
        )
        row = connection.execute("SELECT * FROM alerts WHERE id = ?", (id,)).fetchone()

    return row_to_alert(row) if row else None


def save_access_trend(entry: AccessLogEntry, triggered_rules: list[str]) -> None:
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO access_trends (
                timestamp, user_id, role, department, patient_id, action,
                record_count, triggered_rules
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry.timestamp.isoformat(),
                entry.user_id,
                entry.role,
                entry.department,
                entry.patient_id,
                entry.action,
                entry.record_count,
                ",".join(triggered_rules),
            ),
        )


def row_to_alert(row: sqlite3.Row) -> Alert:
    details_val = None
    try:
        if "details" in row.keys() and row["details"]:
            details_val = json.loads(row["details"])
    except (IndexError, KeyError, sqlite3.OperationalError, json.JSONDecodeError):
        pass
    return Alert(
        id=row["id"],
        timestamp=datetime.fromisoformat(row["timestamp"]),
        source=row["source"],
        severity=row["severity"],
        title=row["title"],
        description=row["description"],
        affected_user=row["affected_user"],
        affected_device=row["affected_device"],
        affected_file=row["affected_file"],
        reason=row["reason"],
        status=row["status"],
        details=details_val,
    )


def ensure_alerts_schema(connection: sqlite3.Connection) -> None:
    columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(alerts)").fetchall()
    }
    if "reason" not in columns:
        connection.execute("ALTER TABLE alerts ADD COLUMN reason TEXT")
    if "details" not in columns:
        connection.execute("ALTER TABLE alerts ADD COLUMN details TEXT")


def query_alerts(filters: dict, page: int, page_size: int) -> tuple[list[Alert], int]:
    where_clauses = []
    params = []
    
    if filters.get("date_from"):
        where_clauses.append("timestamp >= ?")
        params.append(filters["date_from"])
    if filters.get("date_to"):
        where_clauses.append("timestamp <= ?")
        params.append(filters["date_to"])
    if filters.get("source"):
        where_clauses.append("source = ?")
        params.append(filters["source"])
    if filters.get("severity"):
        where_clauses.append("severity = ?")
        params.append(filters["severity"])
    if filters.get("status"):
        where_clauses.append("status = ?")
        params.append(filters["status"])
    if filters.get("search"):
        search_pattern = f"%{filters['search']}%"
        where_clauses.append("(title LIKE ? OR description LIKE ? OR affected_user LIKE ? OR affected_file LIKE ? OR affected_device LIKE ?)")
        params.extend([search_pattern] * 5)
        
    where_str = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
    
    count_query = f"SELECT COUNT(*) FROM alerts {where_str}"
    results_query = f"""
        SELECT * FROM alerts
        {where_str}
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
    """
    
    offset = (page - 1) * page_size
    
    with get_connection() as connection:
        total = connection.execute(count_query, params).fetchone()[0]
        rows = connection.execute(results_query, params + [page_size, offset]).fetchall()
        
    return [row_to_alert(row) for row in rows], total
