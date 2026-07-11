from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pathlib import Path

router = APIRouter()

DEMO_FILES_DIR = Path(__file__).resolve().parent.parent / "demo_files"

@router.get("/files/{filename}")
def download_file(filename: str):
    filepath = DEMO_FILES_DIR / filename
    if not filepath.exists() or not filepath.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(filepath, filename=filename)