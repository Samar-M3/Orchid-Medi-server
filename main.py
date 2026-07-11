import asyncio
import csv
import io
from collections import Counter
from datetime import datetime
import json
from pathlib import Path
from routes.files import router as files_router
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from alert_store import (
    get_alert_summary_24h,
    get_all_alerts,
    init_db,
    save_access_trend,
    save_alert,
    update_alert_status,
    query_alerts,
    get_connection,
    row_to_alert,
)
from file_watcher import RansomwareFileWatcher, ensure_demo_downloads, start_watcher_in_thread
from evaluate import DetectionEvaluator, get_context_events
from models import Alert, AlertSeverity, AlertStatus, AccessLogEntry
from phi_scanner import scan_text
from response_manager import ResponseManager
from rule_engine import RuleEngine
from suspicious_models import ActivityEvent, SuspiciousActivity, SuspiciousStatus
from suspicious_store import (
    get_suspicious_activity_by_id,
    init_detection_db,
    query_suspicious_activity,
    save_event,
    update_suspicious_status,
)
from detection_config import DETECTION_CONFIG

APP_ROOT = Path(__file__).resolve().parent
SEED_LOG_PATH = APP_ROOT / "seed_data" / "fake_access_log.csv"

app = FastAPI(title="MediShield Backend", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

connected_websockets: list[WebSocket] = []
rule_engine: RuleEngine | None = None
file_watcher: RansomwareFileWatcher | None = None
response_manager = ResponseManager()
main_loop: asyncio.AbstractEventLoop | None = None
detection_evaluator: DetectionEvaluator | None = None
suspicious_scan_task: asyncio.Task | None = None


class StatusUpdate(BaseModel):
    status: AlertStatus


class OutboundScanRequest(BaseModel):
    filename: str
    content: str


class OverrideRequest(BaseModel):
    reason: str


class SuspiciousStatusUpdate(BaseModel):
    status: SuspiciousStatus


@app.on_event("startup")
async def startup() -> None:
    """Initialize storage, rule baselines, and the protected-file watcher."""
    global rule_engine, file_watcher, main_loop, detection_evaluator, suspicious_scan_task
    init_db()
    init_detection_db()
    ensure_demo_downloads()
    main_loop = asyncio.get_running_loop()
    historical_average = load_historical_average_per_hour()
    rule_engine = RuleEngine(
        historical_average_per_hour=historical_average,
        trend_logger=save_access_trend,
    )
    detection_evaluator = DetectionEvaluator()
    suspicious_scan_task = asyncio.create_task(run_suspicious_scan_loop())
    file_watcher = start_watcher_in_thread(handle_new_alert_from_thread)


@app.on_event("shutdown")
async def shutdown() -> None:
    """Stop the background file watcher when the API process exits."""
    if suspicious_scan_task:
        suspicious_scan_task.cancel()
        try:
            await suspicious_scan_task
        except asyncio.CancelledError:
            pass
    if file_watcher:
        file_watcher.stop()


@app.get("/alerts", response_model=list[Alert])
async def alerts(
    limit: int = 100,
    severity: AlertSeverity | None = Query(default=None),
    status: AlertStatus | None = Query(default=None),
) -> list[Alert]:
    """Return recent alerts, optionally filtered by severity and status."""
    return get_all_alerts(limit=limit, severity=severity, status=status)


@app.post("/alerts/{id}/status", response_model=Alert)
async def alert_status(id: str, payload: StatusUpdate) -> Alert:
    """Update an alert status to new, acknowledged, or resolved."""
    alert = update_alert_status(id, payload.status)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert
app.include_router(files_router)


@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket) -> None:
    """Stream new alert objects to connected dashboard clients."""
    await websocket.accept()
    connected_websockets.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        connected_websockets.remove(websocket)


@app.post("/simulate/access-log", response_model=list[Alert])
async def simulate_access_log(entry: AccessLogEntry) -> list[Alert]:
    """Evaluate one access-log entry with the insider rule engine."""
    if not rule_engine:
        raise HTTPException(status_code=503, detail="Rule engine is not ready")

    alerts = rule_engine.ingest(entry)
    for alert in alerts:
        await save_escalate_and_broadcast(alert)
    return alerts


@app.post("/api/events", response_model=dict)
async def ingest_activity_event(event: ActivityEvent) -> dict:
    """Ingest one activity event and evaluate immediate suspicious-activity rules."""
    if not detection_evaluator:
        raise HTTPException(status_code=503, detail="Detection evaluator is not ready")

    save_event(event)
    context_events = get_context_events()
    flagged = detection_evaluator.evaluate_event(event, context_events)
    return {
        "event": event.model_dump(mode="json"),
        "flagged": [item.model_dump(mode="json") for item in flagged],
    }


@app.get("/api/suspicious-activity", response_model=list[SuspiciousActivity])
async def list_suspicious_activity(
    status: SuspiciousStatus | None = Query(default=None),
    severity: str | None = Query(default=None),
    userId: str | None = Query(default=None),
    ruleId: str | None = Query(default=None),
    date_from: str | None = Query(default=None),
    date_to: str | None = Query(default=None),
    search: str | None = Query(default=None),
) -> list[SuspiciousActivity]:
    filters = {
        "status": status,
        "severity": severity,
        "user_id": userId,
        "rule_id": ruleId,
        "date_from": date_from,
        "date_to": date_to,
        "search": search,
    }
    return query_suspicious_activity(filters)


@app.patch("/api/suspicious-activity/{activity_id}", response_model=SuspiciousActivity)
async def patch_suspicious_activity(activity_id: str, payload: SuspiciousStatusUpdate) -> SuspiciousActivity:
    updated = update_suspicious_status(activity_id, payload.status)
    if not updated:
        raise HTTPException(status_code=404, detail="Suspicious activity not found")
    return updated


@app.get("/api/suspicious-activity/item/{activity_id}", response_model=SuspiciousActivity)
async def get_suspicious_activity(activity_id: str) -> SuspiciousActivity:
    activity = get_suspicious_activity_by_id(activity_id)
    if not activity:
        raise HTTPException(status_code=404, detail="Suspicious activity not found")
    return activity


@app.get("/api/suspicious-activity/stats")
async def suspicious_activity_stats(
    status: SuspiciousStatus | None = Query(default=None),
    severity: str | None = Query(default=None),
    userId: str | None = Query(default=None),
    ruleId: str | None = Query(default=None),
    date_from: str | None = Query(default=None),
    date_to: str | None = Query(default=None),
    search: str | None = Query(default=None),
) -> dict:
    filters = {
        "status": status,
        "severity": severity,
        "user_id": userId,
        "rule_id": ruleId,
        "date_from": date_from,
        "date_to": date_to,
        "search": search,
    }
    rows = query_suspicious_activity(filters)

    by_severity = Counter(item.severity for item in rows)
    by_status = Counter(item.status for item in rows)
    by_rule = Counter(item.rule_id for item in rows)

    return {
        "total": len(rows),
        "by_severity": dict(by_severity),
        "by_status": dict(by_status),
        "by_rule": dict(by_rule),
    }


@app.get("/api/suspicious-activity/export")
async def export_suspicious_activity(
    status: SuspiciousStatus | None = Query(default=None),
    severity: str | None = Query(default=None),
    userId: str | None = Query(default=None),
    ruleId: str | None = Query(default=None),
    date_from: str | None = Query(default=None),
    date_to: str | None = Query(default=None),
    search: str | None = Query(default=None),
):
    filters = {
        "status": status,
        "severity": severity,
        "user_id": userId,
        "rule_id": ruleId,
        "date_from": date_from,
        "date_to": date_to,
        "search": search,
    }
    rows = query_suspicious_activity(filters)

    def iter_csv():
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "created_at",
            "user_id",
            "ip",
            "rule_id",
            "severity",
            "status",
            "event_ids",
            "details",
        ])
        yield output.getvalue()
        output.seek(0)
        output.truncate(0)

        for item in rows:
            writer.writerow([
                item.created_at.isoformat(),
                item.user_id or "",
                item.ip or "",
                item.rule_id,
                item.severity,
                item.status,
                ";".join(item.event_ids),
                json.dumps(item.details),
            ])
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)

    headers = {
        "Content-Disposition": 'attachment; filename="suspicious_activity.csv"'
    }
    return StreamingResponse(iter_csv(), media_type="text/csv", headers=headers)


@app.post("/scan/outbound", response_model=Alert | None)
async def scan_outbound(payload: OutboundScanRequest) -> Alert | None:
    """Scan outbound text for PHI and emit an alert when risky content appears."""
    matches = scan_text(payload.content)
    if not matches:
        return None

    has_sensitive_match = any(
        match["matched_pattern_type"] == "sensitive_term" for match in matches
    )
    severity = "high" if has_sensitive_match or len(matches) >= 2 else "medium"
    alert = Alert(
        source="phi_scanner",
        severity=severity,
        title="Possible PHI in outbound content",
        description=(
            f"{len(matches)} PHI indicator(s) found in {payload.filename}: "
            + ", ".join(match["matched_pattern_type"] for match in matches)
        ),
        affected_file=payload.filename,
        details={"matches": matches},
    )
    await save_escalate_and_broadcast(alert)
    return alert


@app.get("/stats/summary")
async def stats_summary() -> dict[str, dict[str, int]]:
    """Return alert counts by severity and source over the last 24 hours."""
    return get_alert_summary_24h()


@app.get("/devices")
async def devices() -> dict:
    """Return isolated devices and active throttles for dashboard display."""
    return response_manager.get_devices()


@app.get("/status/{user_or_device}")
async def status(user_or_device: str) -> dict:
    """Return the simulated response state for one user or device."""
    return response_manager.get_status(user_or_device)


@app.post("/devices/{device_id}/isolate")
async def isolate_device(device_id: str) -> dict:
    """Manually isolate a device in the simulated response manager."""
    response_manager.isolate_device(device_id)
    return response_manager.get_status(device_id)


@app.post("/devices/{device_id}/release")
async def release_device(device_id: str) -> dict:
    """Release a manually or automatically isolated device."""
    response_manager.release_device(device_id)
    return response_manager.get_status(device_id)


@app.post("/override/{device_id}", response_model=Alert)
async def override_device(device_id: str, payload: OverrideRequest) -> Alert:
    """Release an isolated device and create an auditable break-glass alert."""
    response_manager.release_device(device_id)
    alert = Alert(
        source="override",
        severity="high",
        title="Break-glass override used",
        description=f"Device {device_id} was released by break-glass override.",
        affected_device=device_id,
        reason=payload.reason,
        details={"device_id": device_id, "reason": payload.reason},
    )
    await save_escalate_and_broadcast(alert)
    return alert


@app.get("/admin/audit-log")
async def get_admin_audit_log(
    date_from: str | None = Query(default=None),
    date_to: str | None = Query(default=None),
    source: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    search: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1),
):
    filters = {
        "date_from": date_from,
        "date_to": date_to,
        "source": source,
        "severity": severity,
        "status": status,
        "search": search,
    }
    results, total = query_alerts(filters, page, page_size)
    return {
        "results": results,
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@app.get("/admin/audit-log/stats")
async def get_admin_audit_log_stats(
    date_from: str | None = Query(default=None),
    date_to: str | None = Query(default=None),
    source: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    search: str | None = Query(default=None),
):
    where_clauses = []
    params = []
    
    if date_from:
        where_clauses.append("timestamp >= ?")
        params.append(date_from)
    if date_to:
        where_clauses.append("timestamp <= ?")
        params.append(date_to)
    if source:
        where_clauses.append("source = ?")
        params.append(source)
    if severity:
        where_clauses.append("severity = ?")
        params.append(severity)
    if status:
        where_clauses.append("status = ?")
        params.append(status)
    if search:
        search_pattern = f"%{search}%"
        where_clauses.append("(title LIKE ? OR description LIKE ? OR affected_user LIKE ? OR affected_file LIKE ? OR affected_device LIKE ?)")
        params.extend([search_pattern] * 5)
        
    where_str = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
    
    query = f"""
        SELECT source, severity, status, (source = 'override') as is_override
        FROM alerts
        {where_str}
    """
    
    with get_connection() as connection:
        rows = connection.execute(query, params).fetchall()
        
    total = len(rows)
    sources = Counter()
    severities = Counter()
    statuses = Counter()
    override_count = 0
    
    for row in rows:
        sources[row["source"]] += 1
        severities[row["severity"]] += 1
        statuses[row["status"]] += 1
        if row["is_override"]:
            override_count += 1
            
    return {
        "total": total,
        "by_source": dict(sources),
        "by_severity": dict(severities),
        "by_status": dict(statuses),
        "override_count": override_count,
    }


@app.get("/admin/audit-log/export")
async def export_admin_audit_log(
    date_from: str | None = Query(default=None),
    date_to: str | None = Query(default=None),
    source: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    search: str | None = Query(default=None),
):
    filters = {
        "date_from": date_from,
        "date_to": date_to,
        "source": source,
        "severity": severity,
        "status": status,
        "search": search,
    }
    
    results, _ = query_alerts(filters, page=1, page_size=1000000)
    
    def iter_csv():
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["timestamp", "source", "severity", "title", "affected_user", "affected_device", "affected_file", "status"])
        yield output.getvalue()
        output.seek(0)
        output.truncate(0)
        
        for alert in results:
            writer.writerow([
                alert.timestamp.isoformat(),
                alert.source,
                alert.severity,
                alert.title,
                alert.affected_user or "",
                alert.affected_device or "",
                alert.affected_file or "",
                alert.status,
            ])
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)

    headers = {
        "Content-Disposition": 'attachment; filename="medishield_audit_log.csv"'
    }
    return StreamingResponse(iter_csv(), media_type="text/csv", headers=headers)


@app.get("/admin/audit-log/{alert_id}", response_model=dict)
async def get_admin_audit_log_detail(alert_id: str):
    with get_connection() as connection:
        row = connection.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    alert = row_to_alert(row)
    
    override_info = None
    response_action = alert.details.get("response_action") if alert.details else None
    
    target = alert.affected_device or alert.affected_user
    if target and response_action in ("isolate", "throttle"):
        with get_connection() as connection:
            override_row = connection.execute(
                """
                SELECT * FROM alerts
                WHERE source = 'override'
                  AND (affected_device = ? OR affected_user = ?)
                  AND timestamp > ?
                ORDER BY timestamp ASC
                LIMIT 1
                """,
                (target, target, alert.timestamp.isoformat()),
            ).fetchone()
            if override_row:
                override_alert = row_to_alert(override_row)
                override_info = {
                    "id": override_alert.id,
                    "timestamp": override_alert.timestamp.isoformat(),
                    "reason": override_alert.reason or override_alert.description,
                }
                
    alert_dict = alert.model_dump(mode="json")
    alert_dict["override"] = override_info
    return alert_dict


def handle_new_alert_from_thread(alert: Alert) -> None:
    action = response_manager.escalate(alert)
    if not alert.details:
        alert.details = {}
    alert.details["response_action"] = action
    save_alert(alert)
    if main_loop:
        asyncio.run_coroutine_threadsafe(broadcast_alert(alert), main_loop)


async def save_escalate_and_broadcast(alert: Alert) -> Alert:
    action = response_manager.escalate(alert)
    if not alert.details:
        alert.details = {}
    alert.details["response_action"] = action
    save_alert(alert)
    await broadcast_alert(alert)
    return alert


async def broadcast_alert(alert: Alert) -> None:
    """Send an alert to all currently connected WebSocket clients."""
    stale_connections: list[WebSocket] = []
    for websocket in connected_websockets:
        try:
            await websocket.send_json(alert.model_dump(mode="json"))
        except Exception:
            stale_connections.append(websocket)

    for websocket in stale_connections:
        if websocket in connected_websockets:
            connected_websockets.remove(websocket)


def load_historical_average_per_hour() -> dict[str, float]:
    if not SEED_LOG_PATH.exists():
        return {}

    counts: Counter[str] = Counter()
    with SEED_LOG_PATH.open(newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            counts[row["user_id"]] += 1

    # Keep the baseline intentionally simple for the hackathon MVP. Treat the
    # seed file as one week of normal behavior and use a minimum to avoid noisy
    # one-off demo alerts.
    return {user_id: max(10.0, count / 168) for user_id, count in counts.items()}


async def run_suspicious_scan_loop() -> None:
    """Run periodic rescans for rate/volume-based suspicious activity rules."""
    if not detection_evaluator:
        return

    interval = DETECTION_CONFIG["scheduler"]["rescan_interval_seconds"]
    while True:
        try:
            detection_evaluator.run_scheduled_scan(datetime.utcnow())
        except Exception:
            # Keep the loop alive even if one scan iteration fails.
            pass
        await asyncio.sleep(interval)
