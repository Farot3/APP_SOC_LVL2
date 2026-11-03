import re
import unicodedata
from collections import Counter
from typing import Any, BinaryIO

from openpyxl import load_workbook

EXPECTED_SHEET = "SIEM Export"
EXPECTED_COLUMNS = (
    "Log_ID",
    "Timestamp",
    "Hostname",
    "Event_ID",
    "User",
    "Source_IP",
    "Destination",
    "Log_Source",
    "Event_Description",
    "Process_CommandLine",
    "Result",
    "Severity",
)
REQUIRED_MAPPING_COLUMNS = (
    "Timestamp",
    "Hostname",
    "Event_ID",
    "User",
    "Source_IP",
    "Event_Description",
    "Result",
)
_COLUMN_ALIASES = {
    "Log_ID": {"log_id", "logid", "record_id", "recordid", "event_record_id", "id_log"},
    "Timestamp": {"timestamp", "time_created", "datetime", "date_time", "fecha_hora", "event_time", "event_created", "event_time_utc", "time_generated", "@timestamp"},
    "Hostname": {"hostname", "host_name", "host", "computer", "computername", "computer_name", "winlog_computer_name", "device_name", "machine", "equipo"},
    "Event_ID": {"event_id", "eventid", "event_code", "event_code_id", "windows_event_id", "winlog_event_id", "id_evento", "codigo_evento", "event_number"},
    "User": {"user", "username", "user_name", "account_name", "account", "usuario", "subject_user_name", "target_user_name"},
    "Source_IP": {"source_ip", "source_ip_address", "src_ip", "sourceip", "client_ip", "client_address", "ip_origen", "source_address", "sourceipaddress"},
    "Destination": {"destination", "destination_ip", "destination_ip_address", "dest_ip", "dst_ip", "target_ip", "destino", "remote_host"},
    "Log_Source": {"log_source", "source", "provider", "provider_name", "channel", "channel_name", "winlog_channel", "logname", "event_source", "source_name"},
    "Event_Description": {"event_description", "description", "message", "message_text", "event_message", "rendered_description", "details", "action", "descripcion"},
    "Process_CommandLine": {"process_commandline", "process_command_line", "command_line", "cmdline", "process_cmd", "commandline", "image_command_line", "process_path"},
    "Result": {"result", "status", "outcome", "event_outcome", "action_result", "event_result", "authentication_result", "resultado"},
    "Severity": {"severity", "level", "level_name", "leveldisplayname", "severity_label", "priority", "risk", "criticality", "severidad"},
}


class WorkbookValidationError(ValueError):
    """Raised when an uploaded workbook does not match the expected schema."""


def read_events(file: BinaryIO) -> list[dict[str, Any]]:
    """Read SIEM events from the expected worksheet without modifying the file."""
    try:
        workbook = load_workbook(file, read_only=True, data_only=True)
    except Exception as exc:
        raise WorkbookValidationError(
            "No se pudo leer el archivo como un libro Excel .xlsx válido."
        ) from exc

    try:
        if EXPECTED_SHEET not in workbook.sheetnames:
            available = ", ".join(workbook.sheetnames) or "ninguna"
            raise WorkbookValidationError(
                f"Falta la hoja '{EXPECTED_SHEET}'. Hojas encontradas: {available}."
            )

        worksheet = workbook[EXPECTED_SHEET]
        rows = worksheet.iter_rows(values_only=True)
        header = next(rows, None)
        if not header:
            raise WorkbookValidationError("La hoja SIEM Export está vacía.")

        names = [str(value).strip() if value is not None else "" for value in header]
        counts = Counter(names)
        duplicates = [name for name in EXPECTED_COLUMNS if counts[name] > 1]
        if duplicates:
            raise WorkbookValidationError(
                "Hay columnas obligatorias duplicadas: " + ", ".join(duplicates)
            )

        missing = [name for name in EXPECTED_COLUMNS if name not in names]
        if missing:
            raise WorkbookValidationError(
                "Faltan columnas obligatorias: " + ", ".join(missing)
            )

        indexes = {name: names.index(name) for name in EXPECTED_COLUMNS}
        events: list[dict[str, Any]] = []
        for row in rows:
            if not row or all(value is None or (isinstance(value, str) and not value.strip()) for value in row):
                continue
            events.append(
                {
                    name: row[index] if index < len(row) else None
                    for name, index in indexes.items()
                }
            )
        return events
    finally:
        workbook.close()


def _normalized_header(value: Any) -> str:
    text = unicodedata.normalize("NFKD", str(value or "").strip().casefold())
    text = "".join(character for character in text if not unicodedata.combining(character))
    return re.sub(r"[^a-z0-9@]+", "_", text).strip("_")


def _suggest_mapping(columns: list[str]) -> dict[str, str | None]:
    aliases = {
        _normalized_header(alias): canonical
        for canonical, names in _COLUMN_ALIASES.items()
        for alias in names | {canonical}
    }
    mapping: dict[str, str | None] = {column: None for column in EXPECTED_COLUMNS}
    used_sources: set[str] = set()
    for column in columns:
        canonical = aliases.get(_normalized_header(column))
        if canonical and mapping[canonical] is None and column not in used_sources:
            mapping[canonical] = column
            used_sources.add(column)
    return mapping


def preview_workbook(
    file: BinaryIO,
    sheet_name: str | None = None,
    header_row: int | None = None,
) -> dict[str, Any]:
    try:
        workbook = load_workbook(file, read_only=True, data_only=True)
    except Exception as exc:
        raise WorkbookValidationError("No se pudo leer el archivo como un libro Excel .xlsx válido.") from exc

    try:
        if sheet_name and sheet_name not in workbook.sheetnames:
            raise WorkbookValidationError(f"No existe la hoja '{sheet_name}' en el libro.")
        sheets = [sheet_name] if sheet_name else workbook.sheetnames
        candidates: list[tuple[int, int, int, list[str]]] = []
        for sheet_index, name in enumerate(sheets):
            worksheet = workbook[name]
            if header_row is not None:
                if header_row < 1:
                    raise WorkbookValidationError("La fila de encabezados debe ser mayor que cero.")
                rows = worksheet.iter_rows(min_row=header_row, max_row=header_row, values_only=True)
                row_start = header_row
            else:
                rows = worksheet.iter_rows(max_row=min(30, worksheet.max_row or 30), values_only=True)
                row_start = 1
            for offset, row in enumerate(rows):
                if not row or all(value is None or not str(value).strip() for value in row):
                    continue
                columns = [str(value).strip() if value is not None else "" for value in row]
                mapping = _suggest_mapping(columns)
                score = sum(value is not None for value in mapping.values())
                if name == EXPECTED_SHEET:
                    score += 2
                candidates.append((score, sheet_index, row_start + offset, columns))
        if not candidates:
            raise WorkbookValidationError("No se encontraron encabezados en las primeras 30 filas del libro.")

        _, _, selected_header_row, columns = max(candidates, key=lambda candidate: candidate[0])
        non_empty_columns = [column for column in columns if column]
        duplicates = sorted({column for column in non_empty_columns if non_empty_columns.count(column) > 1})
        if duplicates:
            raise WorkbookValidationError("Hay encabezados duplicados; renómbralos antes de importar: " + ", ".join(duplicates))
        selected_sheet = sheets[max(candidates, key=lambda candidate: candidate[0])[1]]
        mapping = _suggest_mapping(columns)
        return {
            "sheet_names": workbook.sheetnames,
            "sheet_name": selected_sheet,
            "header_row": selected_header_row,
            "columns": non_empty_columns,
            "suggested_mapping": mapping,
            "required_columns": list(REQUIRED_MAPPING_COLUMNS),
            "missing_required_columns": [
                column for column in REQUIRED_MAPPING_COLUMNS if mapping[column] is None
            ],
        }
    finally:
        workbook.close()


def read_events_mapped(
    file: BinaryIO,
    sheet_name: str,
    header_row: int,
    column_mapping: dict[str, str | None],
) -> list[dict[str, Any]]:
    inspection = preview_workbook(file, sheet_name, header_row)
    columns = inspection["columns"]
    unknown_targets = set(column_mapping) - set(EXPECTED_COLUMNS)
    if unknown_targets:
        raise WorkbookValidationError("El mapeo contiene campos de destino no admitidos.")
    if any(source is not None and not isinstance(source, str) for source in column_mapping.values()):
        raise WorkbookValidationError("Cada campo debe apuntar a un encabezado válido o quedar sin asignar.")
    selected_sources = [source for source in column_mapping.values() if source]
    if any(source not in columns for source in selected_sources):
        raise WorkbookValidationError("El mapeo hace referencia a columnas que no existen en la hoja seleccionada.")
    if len(selected_sources) != len(set(selected_sources)):
        raise WorkbookValidationError("Una columna del Excel no se puede asignar a varios campos.")
    missing = [
        column
        for column in REQUIRED_MAPPING_COLUMNS
        if not column_mapping.get(column)
    ]
    if missing:
        raise WorkbookValidationError("Debes asignar las columnas obligatorias: " + ", ".join(missing))

    try:
        workbook = load_workbook(file, read_only=True, data_only=True)
    except Exception as exc:
        raise WorkbookValidationError("No se pudo leer el archivo Excel.") from exc
    try:
        worksheet = workbook[sheet_name]
        header = next(worksheet.iter_rows(min_row=header_row, max_row=header_row, values_only=True), None)
        if header is None:
            raise WorkbookValidationError("No se encontró la fila de encabezados seleccionada.")
        header_values = [str(value).strip() if value is not None else "" for value in header]
        indexes = {name: index for index, name in enumerate(header_values) if name}
        mapped_indexes = {
            canonical: indexes[source]
            for canonical, source in column_mapping.items()
            if source is not None
        }
        events: list[dict[str, Any]] = []
        for row_number, row in enumerate(
            worksheet.iter_rows(min_row=header_row + 1, values_only=True),
            start=header_row + 1,
        ):
            if not row or all(value is None or (isinstance(value, str) and not value.strip()) for value in row):
                continue
            event = {
                column: row[mapped_indexes[column]] if column in mapped_indexes and mapped_indexes[column] < len(row) else None
                for column in EXPECTED_COLUMNS
            }
            if event["Log_ID"] is None or not str(event["Log_ID"]).strip():
                event["Log_ID"] = f"ROW-{row_number:06d}"
            else:
                event["Log_ID"] = str(event["Log_ID"]).strip()
            events.append(event)
        log_ids = [str(event["Log_ID"]).strip() for event in events]
        if len(log_ids) != len(set(log_ids)):
            raise WorkbookValidationError("La columna Log_ID contiene valores repetidos; corrige la fuente antes de importar.")
        return events
    finally:
        workbook.close()
