from io import BytesIO
from pathlib import Path

from fastapi.testclient import TestClient
from openpyxl import Workbook
import pytest

from app.ingest import EXPECTED_COLUMNS, WorkbookValidationError, read_events
from app.main import app
from app.normalize import normalize_event


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


def test_upload_endpoint_rejects_non_xlsx_file() -> None:
    response = client.post(
        "/api/upload",
        files={"file": ("logs.csv", b"not an xlsx", "text/csv")},
    )

    assert response.status_code == 400
    assert ".xlsx" in response.json()["detail"]
