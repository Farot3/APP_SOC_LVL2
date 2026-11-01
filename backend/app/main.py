from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, File, HTTPException, Query, UploadFile

from .correlate import correlate_findings
from .detections import run_detections
from .ingest import EXPECTED_COLUMNS, WorkbookValidationError, read_events
from .normalize import normalize_events, quality_warnings
from .scoring import RULE_TACTICS, score_incidents

app = FastAPI(title="SOC L2 Incident Analyzer API", version="0.1.0")
app.state.events = []
app.state.source_filename = None
app.state.findings = []
app.state.incidents = []
app.state.informational_findings = []
app.state.hypotheses = []
app.state.analysis_ready = False


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
    app.state.incidents = []
    app.state.informational_findings = []
    app.state.hypotheses = []
    app.state.analysis_ready = False
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
    correlation = correlate_findings(findings, app.state.events)
    incidents = score_incidents(correlation["incidents"])
    app.state.findings = findings
    app.state.incidents = incidents
    app.state.informational_findings = correlation["informational_findings"]
    app.state.hypotheses = correlation["hypotheses"]
    app.state.analysis_ready = True
    return {
        "event_count": len(app.state.events),
        "finding_count": len(findings),
        "findings_by_rule": dict(sorted(Counter(item["rule_id"] for item in findings).items())),
        "incident_count": len(incidents),
        "incidents": incidents,
        "informational_finding_count": len(correlation["informational_findings"]),
        "informational_findings": correlation["informational_findings"],
        "hypotheses": correlation["hypotheses"],
        "findings": findings,
    }


@app.get("/api/incidents")
def get_incidents(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
    risk_level: str | None = None,
    rule_id: str | None = None,
    user: str | None = None,
    host: str | None = None,
) -> dict[str, Any]:
    if not app.state.analysis_ready:
        raise HTTPException(status_code=409, detail="Ejecute /api/analyze antes de consultar incidentes.")

    filtered = app.state.incidents
    if risk_level:
        filtered = [
            incident
            for incident in filtered
            if incident.get("risk", {}).get("level", "").casefold() == risk_level.casefold()
        ]
    if rule_id:
        filtered = [
            incident
            for incident in filtered
            if any(value.casefold() == rule_id.casefold() for value in incident.get("rule_ids", []))
        ]
    if user:
        filtered = [
            incident
            for incident in filtered
            if any(value.casefold() == user.casefold() for value in incident.get("entities", {}).get("users", []))
        ]
    if host:
        filtered = [
            incident
            for incident in filtered
            if any(value.casefold() == host.casefold() for value in incident.get("entities", {}).get("hosts", []))
        ]

    start = (page - 1) * page_size
    return {
        "total": len(filtered),
        "page": page,
        "page_size": page_size,
        "filters": {"risk_level": risk_level, "rule_id": rule_id, "user": user, "host": host},
        "items": filtered[start : start + page_size],
    }


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str) -> dict[str, Any]:
    if not app.state.analysis_ready:
        raise HTTPException(status_code=409, detail="Ejecute /api/analyze antes de consultar incidentes.")
    incident = next(
        (item for item in app.state.incidents if item["incident_id"].casefold() == incident_id.casefold()),
        None,
    )
    if incident is None:
        raise HTTPException(status_code=404, detail=f"No existe el incidente '{incident_id}'.")
    return incident


@app.get("/api/dashboard")
def get_dashboard() -> dict[str, Any]:
    if not app.state.events:
        raise HTTPException(status_code=409, detail="Primero debe cargar un archivo Excel.")

    events = app.state.events
    incidents = app.state.incidents
    by_source = Counter(str(event.get("Log_Source") or "Sin fuente") for event in events)
    by_severity = Counter(str(event.get("Severity") or "Sin severidad") for event in events)
    by_host = Counter(str(event.get("Hostname")) for event in events if event.get("Hostname"))
    by_user = Counter(str(event.get("User")) for event in events if event.get("User"))
    by_ip = Counter(str(event.get("Source_IP")) for event in events if event.get("Source_IP"))
    findings_by_rule = Counter(finding["rule_id"] for finding in app.state.findings)
    incidents_by_risk = Counter(
        incident.get("risk", {}).get("level", "Sin clasificar") for incident in incidents
    )
    techniques = Counter(
        technique
        for incident in incidents
        for technique in incident.get("technique_ids", [])
    )
    tactics = Counter(
        tactic
        for incident in incidents
        for tactic in {
            tactic
            for rule_id in incident.get("rule_ids", [])
            for tactic in RULE_TACTICS.get(rule_id, set())
        }
    )
    tactic_labels = {
        "credential_access": "Acceso a credenciales",
        "initial_access": "Acceso inicial",
        "privilege_escalation": "Escalamiento de privilegios",
        "execution": "Ejecución",
        "defense_evasion": "Evasión de defensas",
        "discovery": "Descubrimiento",
        "lateral_movement": "Movimiento lateral",
        "collection": "Recolección",
        "data_staging": "Preparación de datos",
        "exfiltration": "Exfiltración",
        "command_and_control": "Mando y control",
        "persistence": "Persistencia",
        "impact": "Impacto",
    }
    hourly = Counter()
    for event in events:
        timestamp = _event_timestamp(event.get("Timestamp"))
        if timestamp is not None:
            bucket = timestamp.replace(minute=0, second=0, microsecond=0).isoformat()
            hourly[bucket] += 1

    return {
        "loaded": True,
        "analysis_ready": app.state.analysis_ready,
        "event_count": len(events),
        "finding_count": len(app.state.findings),
        "incident_count": len(incidents),
        "events_by_log_source": _counter_items(by_source),
        "events_by_siem_severity": _counter_items(by_severity),
        "top_hosts": _counter_items(by_host, limit=5),
        "top_users": _counter_items(by_user, limit=5),
        "top_source_ips": _counter_items(by_ip, limit=5),
        "findings_by_rule": _counter_items(findings_by_rule),
        "incidents_by_risk": [
            {"level": level, "count": incidents_by_risk.get(level, 0)}
            for level in ("Crítico", "Alto", "Medio", "Bajo")
        ],
        "attack_tactics": [
            {"id": tactic, "name": tactic_labels.get(tactic, tactic), "count": count}
            for tactic, count in tactics.most_common()
        ],
        "attack_techniques": _counter_items(techniques),
        "risk_matrix": [
            {
                "incident_id": incident["incident_id"],
                "impact": incident["risk"]["impact"],
                "confidence": incident["risk"]["confidence"],
                "score": incident["risk"]["score"],
                "level": incident["risk"]["level"],
            }
            for incident in incidents
        ],
        "events_by_hour": [
            {"hour": hour, "count": count} for hour, count in sorted(hourly.items())
        ],
    }


def _counter_items(counter: Counter[str], limit: int | None = None) -> list[dict[str, Any]]:
    entries = counter.most_common(limit)
    return [{"name": name, "count": count} for name, count in entries]


def _event_timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if value is None:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


@app.get("/api/events")
def get_events(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
    host: str | None = None,
    user: str | None = None,
    source_ip: str | None = None,
    event_id: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> dict[str, Any]:
    if start_time and start_time.utcoffset() is not None:
        raise HTTPException(status_code=400, detail="Use start_time sin zona horaria (hora local del Excel).")
    if end_time and end_time.utcoffset() is not None:
        raise HTTPException(status_code=400, detail="Use end_time sin zona horaria (hora local del Excel).")
    if start_time and end_time and start_time > end_time:
        raise HTTPException(status_code=400, detail="start_time no puede ser posterior a end_time.")

    filtered = app.state.events
    if host:
        filtered = [event for event in filtered if str(event.get("Hostname", "")).casefold() == host.casefold()]
    if user:
        filtered = [event for event in filtered if str(event.get("User", "")).casefold() == user.casefold()]
    if source_ip:
        filtered = [event for event in filtered if str(event.get("Source_IP", "")).casefold() == source_ip.casefold()]
    if event_id:
        filtered = [event for event in filtered if str(event.get("Event_ID", "")).casefold() == event_id.casefold()]
    if start_time or end_time:
        filtered = [
            event
            for event in filtered
            if (timestamp := _event_timestamp(event.get("Timestamp"))) is not None
            and (start_time is None or timestamp >= start_time)
            and (end_time is None or timestamp <= end_time)
        ]

    start = (page - 1) * page_size
    return {
        "total": len(filtered),
        "page": page,
        "page_size": page_size,
        "filters": {
            "host": host,
            "user": user,
            "source_ip": source_ip,
            "event_id": event_id,
            "start_time": start_time.isoformat() if start_time else None,
            "end_time": end_time.isoformat() if end_time else None,
        },
        "items": filtered[start : start + page_size],
    }
