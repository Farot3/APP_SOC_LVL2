from io import BytesIO
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from openpyxl import Workbook

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
