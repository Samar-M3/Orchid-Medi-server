from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
from pathlib import Path
from datetime import datetime
import uuid

from suspicious_models import ActivityEvent
from suspicious_store import save_event

router = APIRouter()

DEMO_FILES_DIR = Path(__file__).resolve().parent.parent / "demo_files"

@router.get("/files/{filename}")
def download_file(filename: str, request: Request):
    filepath = DEMO_FILES_DIR / filename

    client_ip = request.client.host if request.client else "unknown"
    status_code = 200 if filepath.exists() and filepath.is_file() else 404

    event = ActivityEvent(
        id=str(uuid.uuid4()),
        user_id=request.headers.get("x-user-id", "external-client"),
        role=request.headers.get("x-user-role", "viewer"),
        action="download",
        resource=f"files/{filename}",
        resource_type="file",
        ip=client_ip,
        user_agent=request.headers.get("user-agent", "unknown"),
        status_code=status_code,
        timestamp=datetime.utcnow(),
    )
    save_event(event)

    if status_code == 404:
        raise HTTPException(status_code=404, detail="File not found")

    return FileResponse(filepath, filename=filename)