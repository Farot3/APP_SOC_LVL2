import json
from io import BytesIO
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from openpyxl import Workbook

from app import gemini
from app.correlate import correlate_findings
from app.detections import run_detections
from app.ingest import EXPECTED_COLUMNS, WorkbookValidationError, read_events
from app.main import app
from app.normalize import normalize_event, normalize_events
from app.scoring import score_incidents

PROJECT_ROOT = Path(__file__).resolve().parents[2]
REAL_WORKBOOK = PROJECT_ROOT / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"
client = TestClient(app)


def _workbook_bytes(headers: tuple[str, ...], row: tuple[object, ...] | None = None) -> BytesIO:
    workbook = Workbook()
    worksheet = workbook.active
    worksheet.title = "SIEM Export"
    worksheet.append(headers)
    if row is not None:
        worksheet.append(row)
    output = BytesIO()
    workbook.save(output)
    output.seek(0)
    return output


def _alternate_workbook_bytes() -> BytesIO:
    workbook = Workbook()
    worksheet = workbook.active
    worksheet.title = "Windows Events"
    worksheet.append(["Security event export"])
    worksheet.append(("Time Created", "Computer Name", "Event Code", "Account Name", "Client IP", "Message", "Outcome", "Command Line"))
    worksheet.append(("2026-10-23 10:00:00", "APP-SRV01", 4624, r"CORP\alice", "10.1.2.3", "An account was successfully logged on (LogonType=10; RDP)", "Success", "powershell.exe -NoProfile"))
    output = BytesIO()
    workbook.save(output)
    output.seek(0)
    return output


def test_reads_real_workbook_and_validates_dataset_shape() -> None:
    with REAL_WORKBOOK.open("rb") as source:
        events = read_events(source)

    assert len(events) == 715
    assert tuple(events[0]) == EXPECTED_COLUMNS
    assert events[0]["Log_ID"] == "EVT-00001"


def test_reports_missing_required_columns() -> None:
    workbook = _workbook_bytes(("Log_ID", "Timestamp"))

    with pytest.raises(WorkbookValidationError, match="Faltan columnas obligatorias"):
        read_events(workbook)


def test_rejects_workbook_without_expected_sheet() -> None:
    workbook = Workbook()
    workbook.active.title = "Otra hoja"
    output = BytesIO()
    workbook.save(output)
    output.seek(0)

    with pytest.raises(WorkbookValidationError, match="Falta la hoja 'SIEM Export'"):
        read_events(output)


def test_normalizes_fields_without_losing_source_values() -> None:
    normalized = normalize_event(
        {
            "Log_ID": "EVT-TEST",
            "Hostname": "DC01",
            "Event_ID": 4625,
            "User": "-",
            "Source_IP": "10.10.1.22",
            "Destination": " ",
            "Result": "404",
            "Process_CommandLine": "powershell.exe bytes_out=1,024 https://example.test/path",
        }
    )

    assert normalized["Hostname"] == "DC-01"
    assert normalized["Hostname_original"] == "DC01"
    assert normalized["Event_ID"] == "4625"
    assert normalized["User"] == "Anónimo/no autenticado"
    assert normalized["User_original"] == "-"
    assert normalized["Destination"] is None
    assert normalized["http_status"] == 404
    assert normalized["result_class"] == "failure"
    assert normalized["ip_scope"] == "internal"
    assert normalized["command"] == "powershell.exe"
    assert normalized["bytes_out"] == 1024
    assert normalized["uri"] == "https://example.test/path"


def test_upload_endpoint_loads_real_workbook_and_paginates_events() -> None:
    with REAL_WORKBOOK.open("rb") as source:
        response = client.post(
            "/api/upload",
            files={
                "file": (
                    REAL_WORKBOOK.name,
                    source,
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                )
            },
        )

    assert response.status_code == 200
    assert response.json()["event_count"] == 715

    events_response = client.get("/api/events?page=1&page_size=2")
    assert events_response.status_code == 200
    payload = events_response.json()
    assert payload["total"] == 715
    assert len(payload["items"]) == 2
    assert payload["items"][0]["Log_ID"] == "EVT-00001"

    filtered_response = client.get(
        "/api/events",
        params={
            "host": "WEB-01",
            "source_ip": "192.0.2.91",
            "event_id": "HTTP_ACCESS",
            "start_time": "2026-10-23T12:10:00",
            "end_time": "2026-10-23T12:14:00",
            "page_size": 30,
        },
    )
    assert filtered_response.status_code == 200
    assert filtered_response.json()["total"] == 21
    assert all(item["Hostname"] == "WEB-01" for item in filtered_response.json()["items"])

    dashboard_before_analysis = client.get("/api/dashboard")
    assert dashboard_before_analysis.status_code == 200
    assert dashboard_before_analysis.json()["analysis_ready"] is False
    assert dashboard_before_analysis.json()["incident_count"] == 0
    assert client.get("/api/incidents").status_code == 409

    analysis_response = client.post("/api/analyze")
    assert analysis_response.status_code == 200
    analysis = analysis_response.json()
    assert analysis["event_count"] == 715
    assert analysis["finding_count"] == 35
    assert analysis["incident_count"] == 6
    assert analysis["informational_finding_count"] == 15

    incidents_response = client.get("/api/incidents")
    assert incidents_response.status_code == 200
    assert incidents_response.json()["total"] == 6

    high_risk = client.get("/api/incidents", params={"risk_level": "Alto"})
    assert high_risk.status_code == 200
    assert high_risk.json()["total"] == 2
    lateral_incidents = client.get("/api/incidents", params={"rule_id": "R07"})
    assert lateral_incidents.status_code == 200
    assert lateral_incidents.json()["total"] == 1

    incident_detail = client.get("/api/incidents/I-06")
    assert incident_detail.status_code == 200
    assert incident_detail.json()["incident_id"] == "I-06"
    assert "EVT-00599" in incident_detail.json()["event_ids"]
    assert client.get("/api/incidents/I-99").status_code == 404

    dashboard = client.get("/api/dashboard")
    assert dashboard.status_code == 200
    dashboard_data = dashboard.json()
    assert dashboard_data["analysis_ready"] is True
    assert dashboard_data["event_count"] == 715
    assert len(dashboard_data["risk_matrix"]) == 6
    assert dashboard_data["attack_tactics"]
    risk_counts = {entry["level"]: entry["count"] for entry in dashboard_data["incidents_by_risk"]}
    assert risk_counts == {"Crítico": 4, "Alto": 2, "Medio": 0, "Bajo": 0}


def test_event_filters_reject_invalid_time_ranges() -> None:
    response = client.get(
        "/api/events",
        params={
            "start_time": "2026-10-23T13:00:00",
            "end_time": "2026-10-23T12:00:00",
        },
    )

    assert response.status_code == 400
    assert "posterior" in response.json()["detail"]


def test_data_routes_report_missing_upload_or_analysis() -> None:
    previous_state = (
        app.state.events,
        app.state.incidents,
        app.state.analysis_ready,
    )
    app.state.events = []
    app.state.incidents = []
    app.state.analysis_ready = False
    try:
        assert client.get("/api/dashboard").status_code == 409
        assert client.get("/api/incidents").status_code == 409
        assert client.get("/api/incidents/I-01").status_code == 409
    finally:
        app.state.events, app.state.incidents, app.state.analysis_ready = previous_state


def test_upload_endpoint_rejects_non_xlsx_file() -> None:
    response = client.post(
        "/api/upload",
        files={"file": ("logs.csv", b"not an xlsx", "text/csv")},
    )

    assert response.status_code == 400
    assert ".xlsx" in response.json()["detail"]


def test_rules_detect_expected_incident_evidence() -> None:
    with REAL_WORKBOOK.open("rb") as source:
        events = normalize_events(read_events(source))

    findings = run_detections(events)
    evidence_by_rule: dict[str, set[str]] = {}
    for finding in findings:
        evidence_by_rule.setdefault(finding["rule_id"], set()).update(finding["event_ids"])

    expected_evidence = {
        "R01": {"EVT-00110", "EVT-00174"},
        "R02": {"EVT-00123", "EVT-00188"},
        "R03": {"EVT-00123", "EVT-00188"},
        "R04": {"EVT-00126", "EVT-00193"},
        "R05": {"EVT-00198", "EVT-00280"},
        "R06": {"EVT-00207", "EVT-00214"},
        "R07": {"EVT-00225"},
        "R08": {"EVT-00284", "EVT-00309"},
        "R09": {"EVT-00232", "EVT-00428"},
        "R10": {"EVT-00430", "EVT-00461"},
        "R11": {"EVT-00235"},
        "R12": {"EVT-00523", "EVT-00524", "EVT-00528", "EVT-00564"},
        "R13": {"EVT-00314"},
        "R14": {"EVT-00571", "EVT-00596", "EVT-00599"},
    }

    assert set(evidence_by_rule) == set(expected_evidence)
    for rule_id, log_ids in expected_evidence.items():
        assert log_ids <= evidence_by_rule[rule_id], rule_id

    r10 = next(finding for finding in findings if finding["rule_id"] == "R10")
    events_by_id = {event["Log_ID"]: event for event in events}
    assert len(r10["event_ids"]) == 22
    assert sum(events_by_id[log_id]["bytes_out"] for log_id in r10["event_ids"]) == 253_305_558

    r14 = next(finding for finding in findings if finding["rule_id"] == "R14")
    assert sum(events_by_id[log_id]["Event_ID"] == "HTTP_ACCESS" for log_id in r14["event_ids"]) == 21


def test_detection_evidence_only_references_existing_logs() -> None:
    with REAL_WORKBOOK.open("rb") as source:
        events = normalize_events(read_events(source))

    valid_log_ids = {event["Log_ID"] for event in events}
    findings = run_detections(events)

    assert all(set(finding["event_ids"]) <= valid_log_ids for finding in findings)


def test_detection_finding_ids_are_unique_when_a_rule_reuses_first_evidence_log() -> None:
    with REAL_WORKBOOK.open("rb") as source:
        events = normalize_events(read_events(source))

    findings = run_detections(events)
    finding_ids = [finding["finding_id"] for finding in findings]
    repeated_r02 = [finding for finding in findings if finding["finding_id"].startswith("R02-EVT-00199")]

    assert len(finding_ids) == len(set(finding_ids))
    assert {finding["finding_id"] for finding in repeated_r02} == {
        "R02-EVT-00199-EVT-00206",
        "R02-EVT-00199-EVT-00287",
    }


def test_internal_baseline_does_not_trigger_brute_force_rule() -> None:
    with REAL_WORKBOOK.open("rb") as source:
        events = normalize_events(read_events(source))

    r01_findings = [finding for finding in run_detections(events) if finding["rule_id"] == "R01"]

    assert len(r01_findings) == 2
    assert all("10.10.1.22" not in finding["entities"]["source_ips"] for finding in r01_findings)


def test_brute_force_threshold_is_lower_for_external_ips() -> None:
    events = []
    for index in range(4):
        events.append(
            {
                "Log_ID": f"EXT-{index}",
                "Timestamp": f"2026-10-23 08:{index:02d}:00",
                "Event_ID": "4625",
                "User": f"user{index}",
                "Source_IP": "203.0.113.10",
                "Hostname": "DC-01",
                "result_class": "failure",
            }
        )
        events.append(
            {
                "Log_ID": f"INT-{index}",
                "Timestamp": f"2026-10-23 08:{index:02d}:30",
                "Event_ID": "4625",
                "User": f"internal{index}",
                "Source_IP": "10.10.1.22",
                "Hostname": "DC-01",
                "result_class": "failure",
            }
        )

    r01_findings = [finding for finding in run_detections(events) if finding["rule_id"] == "R01"]

    assert len(r01_findings) == 1
    assert r01_findings[0]["entities"]["source_ips"] == ["203.0.113.10"]


def test_correlation_groups_six_incidents_and_keeps_subnet_links_as_hypotheses() -> None:
    with REAL_WORKBOOK.open("rb") as source:
        events = normalize_events(read_events(source))

    findings = run_detections(events)
    result = correlate_findings(findings, events)
    incidents = score_incidents(result["incidents"])

    expected_rules = {
        "I-01": {"R01", "R02", "R03", "R04"},
        "I-02": {"R01", "R02", "R03", "R04", "R05", "R06", "R07", "R09", "R11"},
        "I-03": {"R05", "R08", "R13"},
        "I-04": {"R09", "R10"},
        "I-05": {"R12"},
        "I-06": {"R14"},
    }
    assert len(incidents) == 6
    assert len(result["informational_findings"]) == 15
    assert {incident["incident_id"]: set(incident["rule_ids"]) for incident in incidents} == expected_rules
    assert all("R02" not in incident["rule_ids"] or incident["incident_id"] in {"I-01", "I-02"} for incident in incidents)

    scores = {incident["incident_id"]: incident["risk"] for incident in incidents}
    assert (scores["I-01"]["impact"], scores["I-01"]["confidence"], scores["I-01"]["score"]) == (5, 4, 20)
    assert (scores["I-02"]["impact"], scores["I-02"]["confidence"], scores["I-02"]["score"]) == (4, 5, 20)
    assert (scores["I-03"]["impact"], scores["I-03"]["confidence"], scores["I-03"]["score"]) == (5, 4, 20)
    assert (scores["I-04"]["impact"], scores["I-04"]["confidence"], scores["I-04"]["score"]) == (5, 4, 20)
    assert (scores["I-05"]["impact"], scores["I-05"]["confidence"], scores["I-05"]["score"]) == (5, 3, 15)
    assert (scores["I-06"]["impact"], scores["I-06"]["confidence"], scores["I-06"]["score"]) == (3, 4, 12)

    hypothesis_pairs = {
        (hypothesis["incident_ids"][0], hypothesis["incident_ids"][1], tuple(hypothesis["ip_pairs"][0]))
        for hypothesis in result["hypotheses"]
    }
    assert hypothesis_pairs == {
        ("I-01", "I-02", ("203.0.113.74", "203.0.113.88")),
        ("I-02", "I-04", ("198.51.100.77", "198.51.100.88")),
    }


def _stub_incident() -> dict[str, Any]:
    return {
        "incident_id": "I-TEST",
        "title": "Incidente de prueba",
        "rule_ids": ["R01"],
        "risk": {"level": "Alto", "score": 12},
        "findings": [],
        "events": [{"Log_ID": "LOG-001", "Event_ID": "4625", "Source_IP": "203.0.113.10"}],
    }


def test_gemini_status_reports_disabled_without_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_MODEL", raising=False)

    response = client.get("/api/ai/status")

    assert response.status_code == 200
    assert response.json() == {"enabled": False, "model": "gemini-3.6-flash"}


def test_interpret_endpoint_reports_missing_gemini_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr(app.state, "analysis_ready", True)
    monkeypatch.setattr(app.state, "incidents", [_stub_incident()])
    monkeypatch.setattr(app.state, "gemini_interpretations", {})

    response = client.post("/api/incidents/I-TEST/interpret")

    assert response.status_code == 503
    assert "GEMINI_API_KEY" in response.json()["detail"]


def test_interpret_endpoint_returns_structured_result_with_valid_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.6-flash")
    monkeypatch.setattr(app.state, "analysis_ready", True)
    monkeypatch.setattr(app.state, "incidents", [_stub_incident()])
    monkeypatch.setattr(app.state, "gemini_interpretations", {})
    model_result = {
        "conclusion": "sospechoso",
        "evidence_ids": ["LOG-001"],
        "origenes": [{
            "ip": "203.0.113.10",
            "analisis": "La IP aparece como origen del evento fallido.",
            "evidence_ids": ["LOG-001"],
        }],
        "comprobaciones_recomendadas": [{
            "comprobacion": "Confirmar con el propietario si el intento era esperado.",
            "evidence_ids": ["LOG-001"],
        }],
        "explicacion": "El intento fallido merece revisión.",
        "limitacion": "Un evento no confirma un ataque.",
    }
    monkeypatch.setattr(
        gemini.httpx,
        "post",
        lambda *args, **kwargs: httpx.Response(200, json={"output_text": json.dumps(model_result)}),
    )

    response = client.post("/api/incidents/I-TEST/interpret")

    assert response.status_code == 200
    assert response.json()["conclusion"] == "sospechoso"
    assert response.json()["evidence_ids"] == ["LOG-001"]
    assert response.json()["origenes"][0]["ip"] == "203.0.113.10"
    assert response.json()["comprobaciones_recomendadas"][0]["evidence_ids"] == ["LOG-001"]
    assert response.json()["model"] == "gemini-3.6-flash"
    assert response.json()["cache_hit"] is False


def test_interpret_endpoint_rejects_unknown_evidence_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(app.state, "analysis_ready", True)
    monkeypatch.setattr(app.state, "incidents", [_stub_incident()])
    monkeypatch.setattr(app.state, "gemini_interpretations", {})
    model_result = {
        "conclusion": "sospechoso",
        "evidence_ids": ["NOT-A-REAL-LOG"],
        "origenes": [{
            "ip": "203.0.113.10",
            "analisis": "La IP aparece como origen.",
            "evidence_ids": ["NOT-A-REAL-LOG"],
        }],
        "comprobaciones_recomendadas": [],
        "explicacion": "Texto de prueba.",
        "limitacion": "Limitación de prueba.",
    }
    monkeypatch.setattr(
        gemini.httpx,
        "post",
        lambda *args, **kwargs: httpx.Response(200, json={"output_text": json.dumps(model_result)}),
    )

    response = client.post("/api/incidents/I-TEST/interpret")

    assert response.status_code == 502
    assert "no pertenecen" in response.json()["detail"]


def test_interpret_endpoint_rejects_unobserved_source_ips(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(app.state, "analysis_ready", True)
    monkeypatch.setattr(app.state, "incidents", [_stub_incident()])
    monkeypatch.setattr(app.state, "gemini_interpretations", {})
    model_result = {
        "conclusion": "sospechoso",
        "evidence_ids": ["LOG-001"],
        "origenes": [{
            "ip": "198.51.100.8",
            "analisis": "La IP parece externa.",
            "evidence_ids": ["LOG-001"],
        }],
        "comprobaciones_recomendadas": [],
        "explicacion": "Los datos merecen revisión.",
        "limitacion": "No se conoce el titular de la IP.",
    }
    monkeypatch.setattr(
        gemini.httpx,
        "post",
        lambda *args, **kwargs: httpx.Response(200, json={"output_text": json.dumps(model_result)}),
    )

    response = client.post("/api/incidents/I-TEST/interpret")

    assert response.status_code == 502
    assert "IP de origen" in response.json()["detail"]


def test_interpret_endpoint_rejects_evidence_from_a_different_source_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    incident = _stub_incident()
    incident["events"].append({"Log_ID": "LOG-002", "Event_ID": "4625", "Source_IP": "198.51.100.8"})
    monkeypatch.setattr(app.state, "analysis_ready", True)
    monkeypatch.setattr(app.state, "incidents", [incident])
    monkeypatch.setattr(app.state, "gemini_interpretations", {})
    model_result = {
        "conclusion": "sospechoso",
        "evidence_ids": ["LOG-001"],
        "origenes": [{
            "ip": "198.51.100.8",
            "analisis": "Análisis de prueba.",
            "evidence_ids": ["LOG-001"],
        }],
        "comprobaciones_recomendadas": [],
        "explicacion": "Los eventos requieren revisión.",
        "limitacion": "Datos de prueba.",
    }
    monkeypatch.setattr(
        gemini.httpx,
        "post",
        lambda *args, **kwargs: httpx.Response(200, json={"output_text": json.dumps(model_result)}),
    )

    response = client.post("/api/incidents/I-TEST/interpret")

    assert response.status_code == 502
    assert "no respalda la IP" in response.json()["detail"]


def test_interpret_endpoint_rejects_unverified_recommended_check_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(app.state, "analysis_ready", True)
    monkeypatch.setattr(app.state, "incidents", [_stub_incident()])
    monkeypatch.setattr(app.state, "gemini_interpretations", {})
    model_result = {
        "conclusion": "sospechoso",
        "evidence_ids": ["LOG-001"],
        "origenes": [{
            "ip": "203.0.113.10",
            "analisis": "La IP aparece como origen.",
            "evidence_ids": ["LOG-001"],
        }],
        "comprobaciones_recomendadas": [{
            "comprobacion": "Revisar el inicio de sesión.",
            "evidence_ids": ["LOG-999"],
        }],
        "explicacion": "Los datos merecen revisión.",
        "limitacion": "Datos de prueba.",
    }
    monkeypatch.setattr(
        gemini.httpx,
        "post",
        lambda *args, **kwargs: httpx.Response(200, json={"output_text": json.dumps(model_result)}),
    )

    response = client.post("/api/incidents/I-TEST/interpret")

    assert response.status_code == 502
    assert "Log_ID" in response.json()["detail"]


def test_interpret_endpoint_reuses_cached_result_and_invalidates_on_model_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.6-flash")
    monkeypatch.setattr(app.state, "analysis_ready", True)
    monkeypatch.setattr(app.state, "incidents", [_stub_incident()])
    monkeypatch.setattr(app.state, "gemini_interpretations", {})
    model_result = {
        "conclusion": "sospechoso",
        "evidence_ids": ["LOG-001"],
        "origenes": [{
            "ip": "203.0.113.10",
            "analisis": "La IP aparece como origen del evento fallido.",
            "evidence_ids": ["LOG-001"],
        }],
        "comprobaciones_recomendadas": [{
            "comprobacion": "Confirmar con el propietario si el intento era esperado.",
            "evidence_ids": ["LOG-001"],
        }],
        "explicacion": "El intento fallido merece revisión.",
        "limitacion": "Un evento no confirma un ataque.",
    }
    calls: list[str] = []

    def fake_post(*args: object, **kwargs: object) -> httpx.Response:
        calls.append("called")
        return httpx.Response(200, json={"output_text": json.dumps(model_result)})

    monkeypatch.setattr(gemini.httpx, "post", fake_post)

    first = client.post("/api/incidents/I-TEST/interpret")
    second = client.post("/api/incidents/I-TEST/interpret")

    assert first.status_code == 200
    assert first.json()["cache_hit"] is False
    assert second.status_code == 200
    assert second.json()["cache_hit"] is True
    assert len(calls) == 1

    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.8-flash")
    third = client.post("/api/incidents/I-TEST/interpret")

    assert third.status_code == 200
    assert third.json()["model"] == "gemini-3.8-flash"
    assert third.json()["cache_hit"] is False
    assert len(calls) == 2


def _incident_with_finding() -> dict[str, Any]:
    incident = _stub_incident()
    incident["findings"] = [{
        "finding_id": "F-TEST-01",
        "rule_id": "R01",
        "name": "Intentos de autenticación fallidos",
        "explanation": "Varios intentos fallidos desde una IP.",
        "technique_ids": ["T1110"],
        "event_ids": ["LOG-001"],
        "entities": {"source_ips": ["203.0.113.10"]},
    }]
    return incident


def _classification_response(classifications: list[dict[str, object]]) -> dict[str, object]:
    return {
        "conclusion": "sospechoso",
        "evidence_ids": ["LOG-001"],
        "clasificaciones_hallazgos": classifications,
        "origenes": [{
            "ip": "203.0.113.10",
            "analisis": "La IP aparece como origen del evento.",
            "evidence_ids": ["LOG-001"],
        }],
        "comprobaciones_recomendadas": [],
        "explicacion": "Los intentos merecen revisión.",
        "limitacion": "Los registros no confirman por sí solos un ataque.",
    }


def _valid_finding_classification() -> dict[str, object]:
    return {
        "finding_id": "F-TEST-01",
        "riesgo": "Alto",
        "justificacion": "Los intentos repetidos pueden indicar fuerza bruta.",
        "tecnica_mitre": ["T1110"],
        "confianza": 4,
        "evidence_ids": ["LOG-001"],
    }


def test_interpret_endpoint_classifies_every_finding_without_changing_baseline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(app.state, "analysis_ready", True)
    monkeypatch.setattr(app.state, "incidents", [_incident_with_finding()])
    monkeypatch.setattr(app.state, "gemini_interpretations", {})
    model_result = _classification_response([_valid_finding_classification()])
    calls: list[str] = []

    def fake_post(*args: object, **kwargs: object) -> httpx.Response:
        calls.append("called")
        return httpx.Response(200, json={"output_text": json.dumps(model_result)})

    monkeypatch.setattr(gemini.httpx, "post", fake_post)

    response = client.post("/api/incidents/I-TEST/interpret")

    assert response.status_code == 200
    result = response.json()
    assert result["baseline_risk_level"] == "Alto"
    assert result["clasificaciones_hallazgos"] == [{
        **_valid_finding_classification(),
        "baseline_technique_ids": ["T1110"],
    }]
    assert len(calls) == 1


@pytest.mark.parametrize(
    ("classifications", "expected_detail"),
    [
        ([{
            **_valid_finding_classification(),
            "finding_id": "F-FAKE",
        }], "finding_id"),
        ([{
            **_valid_finding_classification(),
            "tecnica_mitre": ["T9999"],
        }], "técnica MITRE"),
        ([{
            **_valid_finding_classification(),
            "evidence_ids": ["LOG-999"],
        }], "evidencia"),
        ([], "no clasificó todos"),
    ],
)
def test_interpret_endpoint_rejects_unverified_finding_classifications(
    monkeypatch: pytest.MonkeyPatch,
    classifications: list[dict[str, object]],
    expected_detail: str,
) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(app.state, "analysis_ready", True)
    monkeypatch.setattr(app.state, "incidents", [_incident_with_finding()])
    monkeypatch.setattr(app.state, "gemini_interpretations", {})
    model_result = _classification_response(classifications)
    monkeypatch.setattr(
        gemini.httpx,
        "post",
        lambda *args, **kwargs: httpx.Response(200, json={"output_text": json.dumps(model_result)}),
    )

    response = client.post("/api/incidents/I-TEST/interpret")

    assert response.status_code == 502
    assert expected_detail in response.json()["detail"]


def _correlation_fixture() -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    findings = [
        {
            "finding_id": "F-01",
            "rule_id": "R01",
            "name": "Fallos de autenticación",
            "explanation": "Varios intentos fallidos.",
            "technique_ids": ["T1110"],
            "event_ids": ["LOG-001"],
            "first_seen": "2026-10-23T10:00:00",
            "last_seen": "2026-10-23T10:02:00",
            "entities": {"source_ips": ["203.0.113.10"]},
        },
        {
            "finding_id": "F-02",
            "rule_id": "R02",
            "name": "Acceso exitoso posterior",
            "explanation": "Acceso tras los fallos.",
            "technique_ids": ["T1078"],
            "event_ids": ["LOG-002"],
            "first_seen": "2026-10-23T10:03:00",
            "last_seen": "2026-10-23T10:03:00",
            "entities": {"source_ips": ["203.0.113.10"]},
        },
        {
            "finding_id": "F-03",
            "rule_id": "R09",
            "name": "Hallazgo informativo",
            "explanation": "No hay evidencia de relación directa.",
            "technique_ids": ["T1560.001"],
            "event_ids": ["LOG-003"],
            "first_seen": "2026-10-23T12:00:00",
            "last_seen": "2026-10-23T12:00:00",
            "entities": {"hosts": ["HOST-02"]},
        },
    ]
    events = [
        {"Log_ID": "LOG-001", "Timestamp": "2026-10-23T10:00:00", "Event_Description": "Fallo."},
        {"Log_ID": "LOG-002", "Timestamp": "2026-10-23T10:03:00", "Event_Description": "Acceso correcto."},
        {"Log_ID": "LOG-003", "Timestamp": "2026-10-23T12:00:00", "Event_Description": "Archivo comprimido."},
    ]
    incidents = [{"incident_id": "I-01", "finding_ids": ["F-01", "F-02"]}]
    return findings, events, incidents


def _valid_correlation_output() -> dict[str, Any]:
    return {
        "groups": [
            {
                "type": "incidente",
                "title": "Intentos y acceso exitoso",
                "finding_ids": ["F-01", "F-02"],
                "justificacion": "El acceso exitoso sigue a los fallos desde la misma IP.",
                "confidence": 4,
                "evidence_ids": ["LOG-001", "LOG-002"],
            },
            {
                "type": "aislado",
                "title": "Hallazgo independiente",
                "finding_ids": ["F-03"],
                "justificacion": "No hay relación sustentada con los otros hallazgos.",
                "confidence": 3,
                "evidence_ids": ["LOG-003"],
            },
        ]
    }


def test_gemini_correlation_endpoint_returns_partition_and_caches_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.6-flash")
    findings, events, incidents = _correlation_fixture()
    monkeypatch.setattr(app.state, "analysis_ready", True)
    monkeypatch.setattr(app.state, "findings", findings)
    monkeypatch.setattr(app.state, "events", events)
    monkeypatch.setattr(app.state, "incidents", incidents)
    monkeypatch.setattr(app.state, "gemini_correlations", {})
    model_result = _valid_correlation_output()
    requests: list[dict[str, Any]] = []

    def fake_post(*args: object, **kwargs: Any) -> httpx.Response:
        requests.append(kwargs["json"])
        return httpx.Response(200, json={"output_text": json.dumps(model_result)})

    monkeypatch.setattr(gemini.httpx, "post", fake_post)

    first = client.post("/api/ai/correlate")
    second = client.post("/api/ai/correlate")

    assert first.status_code == 200
    result = first.json()
    assert result["cache_hit"] is False
    assert result["finding_count"] == 3
    assert result["groups"][0]["group_id"] == "IA-01"
    assert result["groups"][0]["baseline_incident_ids"] == ["I-01"]
    assert result["groups"][1]["baseline_incident_ids"] == []
    assert second.status_code == 200
    assert second.json()["cache_hit"] is True
    assert len(requests) == 1
    assert "F-01" in requests[0]["input"]
    assert "F-03" in requests[0]["input"]

    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.8-flash")
    third = client.post("/api/ai/correlate")

    assert third.status_code == 200
    assert third.json()["cache_hit"] is False
    assert third.json()["model"] == "gemini-3.8-flash"
    assert len(requests) == 2


@pytest.mark.parametrize(
    ("groups", "expected_detail"),
    [
        ([{
            **_valid_correlation_output()["groups"][0],
            "finding_ids": ["F-FAKE", "F-02"],
        }, _valid_correlation_output()["groups"][1]], "finding_id que no existen"),
        ([
            _valid_correlation_output()["groups"][0],
            {
                **_valid_correlation_output()["groups"][1],
                "finding_ids": ["F-02"],
                "type": "aislado",
            },
        ], "más de un grupo"),
        ([_valid_correlation_output()["groups"][0]], "omitió hallazgos"),
        ([
            {
                **_valid_correlation_output()["groups"][0],
                "evidence_ids": ["LOG-003"],
            },
            _valid_correlation_output()["groups"][1],
        ], "evidencia que no pertenece"),
    ],
)
def test_gemini_correlation_rejects_invalid_partition_and_evidence(
    monkeypatch: pytest.MonkeyPatch,
    groups: list[dict[str, Any]],
    expected_detail: str,
) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    findings, events, incidents = _correlation_fixture()
    monkeypatch.setattr(app.state, "analysis_ready", True)
    monkeypatch.setattr(app.state, "findings", findings)
    monkeypatch.setattr(app.state, "events", events)
    monkeypatch.setattr(app.state, "incidents", incidents)
    monkeypatch.setattr(app.state, "gemini_correlations", {})
    model_result = {"groups": groups}
    monkeypatch.setattr(
        gemini.httpx,
        "post",
        lambda *args, **kwargs: httpx.Response(200, json={"output_text": json.dumps(model_result)}),
    )

    response = client.post("/api/ai/correlate")

    assert response.status_code == 502
    assert expected_detail in response.json()["detail"]


def test_gemini_correlation_accepts_all_unique_findings_from_reference_workbook(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    with REAL_WORKBOOK.open("rb") as source:
        upload = client.post(
            "/api/upload",
            files={
                "file": (
                    REAL_WORKBOOK.name,
                    source,
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                )
            },
        )
    assert upload.status_code == 200
    analysis_response = client.post("/api/analyze")
    assert analysis_response.status_code == 200
    findings = app.state.findings
    ids = [finding["finding_id"] for finding in findings]
    assert len(ids) == len(set(ids))

    model_result = {
        "groups": [
            {
                "type": "aislado",
                "title": finding["name"],
                "finding_ids": [finding["finding_id"]],
                "justificacion": "Mock: no se afirma una relación con otros hallazgos.",
                "confidence": 3,
                "evidence_ids": [finding["event_ids"][0]],
            }
            for finding in findings
        ]
    }
    monkeypatch.setattr(
        gemini.httpx,
        "post",
        lambda *args, **kwargs: httpx.Response(200, json={"output_text": json.dumps(model_result)}),
    )

    response = client.post("/api/ai/correlate")

    assert response.status_code == 200
    assert response.json()["finding_count"] == 35
    assert len(response.json()["groups"]) == 35


def test_gemini_correlation_rejects_duplicate_input_ids_before_network_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    findings, events, incidents = _correlation_fixture()
    findings[1]["finding_id"] = findings[0]["finding_id"]
    monkeypatch.setattr(app.state, "analysis_ready", True)
    monkeypatch.setattr(app.state, "findings", findings)
    monkeypatch.setattr(app.state, "events", events)
    monkeypatch.setattr(app.state, "incidents", incidents)
    monkeypatch.setattr(app.state, "gemini_correlations", {})
    calls: list[str] = []

    def fake_post(*args: object, **kwargs: Any) -> httpx.Response:
        calls.append("called")
        return httpx.Response(200, json={"output_text": "{}"})

    monkeypatch.setattr(gemini.httpx, "post", fake_post)

    response = client.post("/api/ai/correlate")

    assert response.status_code == 409
    assert "finding_id duplicados" in response.json()["detail"]
    assert calls == []


def _analysis_report_fixture() -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    findings, events, _ = _correlation_fixture()
    incidents = [{
        "incident_id": "I-01",
        "title": "Intentos y acceso exitoso",
        "finding_ids": ["F-01", "F-02"],
        "technique_ids": ["T1110", "T1078"],
        "rule_ids": ["R01", "R02"],
        "risk": {"level": "Alto", "score": 16},
    }]
    return findings, events, incidents


def _valid_executive_report() -> dict[str, Any]:
    return {
        "summary": "Se observó una secuencia de fallos y acceso posterior.",
        "key_points": [{
            "heading": "Acceso tras fallos",
            "detail": "Los registros muestran fallos y un acceso exitoso posterior.",
            "finding_ids": ["F-01", "F-02"],
            "evidence_ids": ["LOG-001", "LOG-002"],
        }],
        "recommended_actions": [{
            "priority": "Alta",
            "action": "Validar con el propietario de la cuenta si el acceso fue autorizado.",
            "finding_ids": ["F-02"],
            "evidence_ids": ["LOG-002"],
        }],
        "limitations": "Los registros no permiten confirmar la identidad del operador.",
    }


def _valid_technical_report() -> dict[str, Any]:
    return {
        "summary": "El análisis determinista contiene un incidente y un hallazgo informativo.",
        "incident_details": [{
            "incident_id": "I-01",
            "technical_summary": "Los fallos preceden al acceso exitoso.",
            "finding_ids": ["F-01", "F-02"],
            "technique_ids": ["T1110", "T1078"],
            "evidence_ids": ["LOG-001", "LOG-002"],
        }],
        "informational_findings": [{
            "finding_id": "F-03",
            "summary": "Hallazgo informativo independiente.",
            "evidence_ids": ["LOG-003"],
        }],
        "limitations": "No se conoce el contexto operativo del usuario.",
    }


def test_ai_reports_are_on_demand_cached_per_type_and_model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.6-flash")
    findings, events, incidents = _analysis_report_fixture()
    monkeypatch.setattr(app.state, "analysis_ready", True)
    monkeypatch.setattr(app.state, "findings", findings)
    monkeypatch.setattr(app.state, "events", events)
    monkeypatch.setattr(app.state, "incidents", incidents)
    monkeypatch.setattr(app.state, "gemini_reports", {})
    outputs = {"executive": _valid_executive_report(), "technical": _valid_technical_report()}
    requests: list[dict[str, Any]] = []

    def fake_post(*args: object, **kwargs: Any) -> httpx.Response:
        requests.append(kwargs["json"])
        prompt = kwargs["json"]["input"]
        report_type = "technical" if "informe técnico SOC" in prompt else "executive"
        return httpx.Response(200, json={"output_text": json.dumps(outputs[report_type])})

    monkeypatch.setattr(gemini.httpx, "post", fake_post)

    executive = client.post("/api/ai/reports/executive")
    executive_cached = client.post("/api/ai/reports/executive")
    technical = client.post("/api/ai/reports/technical")

    assert executive.status_code == 200
    assert executive.json()["report_type"] == "executive"
    assert executive.json()["baseline"]["incident_count"] == 1
    assert executive.json()["baseline"]["risk_by_incident"] == [{"incident_id": "I-01", "level": "Alto", "score": 16}]
    assert executive_cached.json()["cache_hit"] is True
    assert technical.status_code == 200
    assert technical.json()["informational_findings"][0]["finding_id"] == "F-03"
    assert len(requests) == 2

    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.8-flash")
    changed_model = client.post("/api/ai/reports/executive")
    assert changed_model.status_code == 200
    assert changed_model.json()["model"] == "gemini-3.8-flash"
    assert changed_model.json()["cache_hit"] is False
    assert len(requests) == 3


def test_ai_report_endpoint_rejects_unsupported_report_type(monkeypatch: pytest.MonkeyPatch) -> None:
    findings, events, incidents = _analysis_report_fixture()
    monkeypatch.setattr(app.state, "analysis_ready", True)
    monkeypatch.setattr(app.state, "findings", findings)
    monkeypatch.setattr(app.state, "events", events)
    monkeypatch.setattr(app.state, "incidents", incidents)

    response = client.post("/api/ai/reports/unsupported")

    assert response.status_code == 404
    assert "Tipo de informe" in response.json()["detail"]


def test_ai_report_rejects_unverified_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    findings, events, incidents = _analysis_report_fixture()
    monkeypatch.setattr(app.state, "analysis_ready", True)
    monkeypatch.setattr(app.state, "findings", findings)
    monkeypatch.setattr(app.state, "events", events)
    monkeypatch.setattr(app.state, "incidents", incidents)
    monkeypatch.setattr(app.state, "gemini_reports", {})
    invalid_output = _valid_executive_report()
    invalid_output["key_points"][0]["evidence_ids"] = ["LOG-003"]
    monkeypatch.setattr(
        gemini.httpx,
        "post",
        lambda *args, **kwargs: httpx.Response(200, json={"output_text": json.dumps(invalid_output)}),
    )

    response = client.post("/api/ai/reports/executive")

    assert response.status_code == 502
    assert "evidencia ajena" in response.json()["detail"]


def test_ai_report_rejects_action_citing_another_findings_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    findings, events, incidents = _analysis_report_fixture()
    monkeypatch.setattr(app.state, "analysis_ready", True)
    monkeypatch.setattr(app.state, "findings", findings)
    monkeypatch.setattr(app.state, "events", events)
    monkeypatch.setattr(app.state, "incidents", incidents)
    monkeypatch.setattr(app.state, "gemini_reports", {})
    invalid_output = _valid_executive_report()
    invalid_output["recommended_actions"][0]["action"] = "Revocar credenciales y restablecer sesiones activas."
    invalid_output["recommended_actions"][0]["evidence_ids"] = ["LOG-003"]
    monkeypatch.setattr(
        gemini.httpx,
        "post",
        lambda *args, **kwargs: httpx.Response(200, json={"output_text": json.dumps(invalid_output)}),
    )

    response = client.post("/api/ai/reports/executive")

    assert response.status_code == 502
    assert "evidencia ajena a los hallazgos" in response.json()["detail"]
    assert "Revocar credenciales" in response.json()["detail"]


@pytest.mark.parametrize("techniques", [["T9999"], ["T1110"]])
def test_ai_technical_report_rejects_incomplete_or_unrelated_techniques(
    monkeypatch: pytest.MonkeyPatch,
    techniques: list[str],
) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    findings, events, incidents = _analysis_report_fixture()
    monkeypatch.setattr(app.state, "analysis_ready", True)
    monkeypatch.setattr(app.state, "findings", findings)
    monkeypatch.setattr(app.state, "events", events)
    monkeypatch.setattr(app.state, "incidents", incidents)
    monkeypatch.setattr(app.state, "gemini_reports", {})
    invalid_output = _valid_technical_report()
    invalid_output["incident_details"][0]["technique_ids"] = techniques
    monkeypatch.setattr(
        gemini.httpx,
        "post",
        lambda *args, **kwargs: httpx.Response(200, json={"output_text": json.dumps(invalid_output)}),
    )

    response = client.post("/api/ai/reports/technical")

    assert response.status_code == 502
    assert "técnicas" in response.json()["detail"]


def test_ai_report_rejects_ambiguous_baseline_before_network_call(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    findings, events, incidents = _analysis_report_fixture()
    findings.append(dict(findings[0]))
    monkeypatch.setattr(app.state, "analysis_ready", True)
    monkeypatch.setattr(app.state, "findings", findings)
    monkeypatch.setattr(app.state, "events", events)
    monkeypatch.setattr(app.state, "incidents", incidents)
    monkeypatch.setattr(app.state, "gemini_reports", {})
    calls: list[bool] = []
    monkeypatch.setattr(gemini.httpx, "post", lambda *args, **kwargs: calls.append(True))

    response = client.post("/api/ai/reports/executive")

    assert response.status_code == 409
    assert "finding_id duplicados" in response.json()["detail"]
    assert calls == []


def test_upload_preview_detects_alternate_sheet_and_header_aliases() -> None:
    response = client.post(
        "/api/upload/preview",
        files={"file": ("alternate.xlsx", _alternate_workbook_bytes(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
    )

    assert response.status_code == 200
    preview = response.json()
    assert preview["sheet_name"] == "Windows Events"
    assert preview["header_row"] == 2
    assert preview["suggested_mapping"]["Timestamp"] == "Time Created"
    assert preview["suggested_mapping"]["Source_IP"] == "Client IP"
    assert preview["missing_required_columns"] == []


def test_mapped_upload_normalizes_events_and_generates_missing_log_ids() -> None:
    preview_response = client.post(
        "/api/upload/preview",
        files={"file": ("alternate.xlsx", _alternate_workbook_bytes(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
    )
    assert preview_response.status_code == 200
    preview = preview_response.json()

    response = client.post(
        "/api/upload/mapped",
        data={
            "sheet_name": preview["sheet_name"],
            "header_row": str(preview["header_row"]),
            "column_mapping": json.dumps(preview["suggested_mapping"]),
        },
        files={"file": ("alternate.xlsx", _alternate_workbook_bytes(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
    )

    assert response.status_code == 200
    assert response.json()["event_count"] == 1
    assert app.state.events[0]["Log_ID"] == "ROW-000003"
    assert app.state.events[0]["Event_ID"] == "4624"
    assert app.state.events[0]["result_class"] == "success"


def test_gemini_column_mapping_receives_headers_only_and_validates_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    mapping = {
        "Log_ID": "",
        "Timestamp": "Time Created",
        "Hostname": "Computer Name",
        "Event_ID": "Event Code",
        "User": "Account Name",
        "Source_IP": "Client IP",
        "Destination": "",
        "Log_Source": "",
        "Event_Description": "Message",
        "Process_CommandLine": "Command Line",
        "Result": "Outcome",
        "Severity": "",
    }
    requests: list[dict[str, Any]] = []

    def fake_post(*args: object, **kwargs: Any) -> httpx.Response:
        requests.append(kwargs["json"])
        return httpx.Response(200, json={"output_text": json.dumps({"mapping": mapping})})

    monkeypatch.setattr(gemini.httpx, "post", fake_post)
    response = client.post(
        "/api/ai/map-columns",
        json={"columns": ["Time Created", "Computer Name", "Event Code", "Account Name", "Client IP", "Message", "Command Line", "Outcome"]},
    )

    assert response.status_code == 200
    assert response.json()["mapping"]["Timestamp"] == "Time Created"
    assert "CORP\\alice" not in requests[0]["input"]
    assert "Message" in requests[0]["input"]


def test_flexible_preview_keeps_the_reference_workbook_schema() -> None:
    with REAL_WORKBOOK.open("rb") as source:
        response = client.post(
            "/api/upload/preview",
            files={
                "file": (
                    REAL_WORKBOOK.name,
                    source,
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                )
            },
        )

    assert response.status_code == 200
    preview = response.json()
    assert preview["sheet_name"] == "SIEM Export"
    assert preview["header_row"] == 1
    assert preview["columns"] == list(EXPECTED_COLUMNS)
    assert preview["missing_required_columns"] == []
