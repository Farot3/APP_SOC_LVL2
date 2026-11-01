from collections import Counter
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, File, HTTPException, Query, UploadFile

from .detections import run_detections
from .ingest import EXPECTED_COLUMNS, WorkbookValidationError, read_events
from .normalize import normalize_events, quality_warnings

app = FastAPI(title="SOC L2 Incident Analyzer API", version="0.1.0")
app.state.events = []
app.state.source_filename = None
app.state.findings = []


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/upload")
def upload_workbook(file: Annotated[UploadFile, File()]) -> dict[str, Any]:
    filename = file.filename or ""
    if Path(filename).suffix.casefold() != ".xlsx":
        raise HTTPException(status_code=400, detail="El archivo debe tener extensión .xlsx.")

    try:
        source_events = read_events(file.file)
    except WorkbookValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    events = normalize_events(source_events)
    app.state.events = events
    app.state.source_filename = filename
    app.state.findings = []
    return {
        "filename": filename,
        "event_count": len(events),
        "columns": list(EXPECTED_COLUMNS),
        "warnings": quality_warnings(events),
    }


@app.post("/api/analyze")
def analyze_events() -> dict[str, Any]:
    if not app.state.events:
        raise HTTPException(status_code=400, detail="Primero debe cargar un archivo Excel.")

    findings = run_detections(app.state.events)
    app.state.findings = findings
    return {
        "event_count": len(app.state.events),
        "finding_count": len(findings),
        "findings_by_rule": dict(sorted(Counter(item["rule_id"] for item in findings).items())),
        "findings": findings,
    }


@app.get("/api/events")
def get_events(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
) -> dict[str, Any]:
    events = app.state.events
    start = (page - 1) * page_size
    return {
        "total": len(events),
        "page": page,
        "page_size": page_size,
        "items": events[start : start + page_size],
    }
