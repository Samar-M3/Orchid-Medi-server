from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
from pathlib import Path
from datetime import datetime, timezone

from suspicious_models import ActivityEvent
from suspicious_store import save_event, get_recent_events
from evaluate import DetectionEvaluator

router = APIRouter()

DEMO_FILES_DIR = Path(__file__).resolve().parent.parent / "demo_files"

# Shared evaluator instance for immediate detection on download
_evaluator = DetectionEvaluator()

from datetime import timedelta

def _process_file_access(filename: str, request: Request, action_type: str):
    filepath = DEMO_FILES_DIR / filename
 
    client_ip = request.client.host if request.client else "unknown"
    user_id = request.headers.get("x-user-id", "external-client")
    
    # ── Check for > 20 accesses (Block session) ──
    recent_events = get_recent_events(limit=5000)
    time_limit = datetime.now(timezone.utc) - timedelta(minutes=15)
    user_recent_events = [e for e in recent_events if e.user_id == user_id and e.timestamp >= time_limit]
    
    is_blocked = len(user_recent_events) > 20
    
    if is_blocked:
        from main import response_manager
        response_manager.isolate_device(user_id)
        status_code = 403
    else:
        status_code = 200 if filepath.exists() and filepath.is_file() else 404

    event = ActivityEvent(
        user_id=user_id,
        role=request.headers.get("x-user-role", "viewer"),
        action=action_type,
        resource=f"files/{filename}",
        resource_type="file",
        ip=client_ip,
        user_agent=request.headers.get("user-agent", "unknown"),
        status_code=status_code,
        timestamp=datetime.now(timezone.utc),
    )
    save_event(event)

    try:
        # Generate Suspicious Activity for Audit Log
        flagged_activities = _evaluator.evaluate_event(event, recent_events)
        _evaluator.run_scheduled_scan(datetime.now(timezone.utc))
        
        # Broadcast Live Alert to Dashboard
        from main import save_escalate_and_broadcast
        from models import Alert
        
        # We also want to manually emit a live alert for the Single Data Access
        for flagged in flagged_activities:
            if flagged.rule_id == "single_data_access":
                status_str = " (Blocked)" if status_code == 403 else " (Success)" if status_code == 200 else ""
                alert = Alert(
                    source="insider",
                    severity="medium",
                    title="Sensitive Data Accessed",
                    description=f"User {user_id} {event.action}ed sensitive file {filename}{status_str}",
                    affected_user=user_id,
                    affected_file=filename,
                    details={"action": event.action, "rule_id": "single_data_access", "status_code": status_code}
                )
                import asyncio
                # save_escalate_and_broadcast is an async function
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(save_escalate_and_broadcast(alert))
                else:
                    asyncio.run(save_escalate_and_broadcast(alert))

    except Exception as e:
        print(f"Error processing detection: {e}")
        # Never let detection failures block the file download
        pass

    if status_code == 403:
        raise HTTPException(status_code=403, detail="Session Invalidated: Data access limit exceeded. Your session has been removed.")

    if status_code == 404:
        raise HTTPException(status_code=404, detail="File not found")

    return FileResponse(filepath, filename=filename)


@router.get("/files/{filename}")
def download_file(filename: str, request: Request):
    return _process_file_access(filename, request, "download")

@router.get("/files/view/{filename}")
def view_file(filename: str, request: Request):
    return _process_file_access(filename, request, "view")