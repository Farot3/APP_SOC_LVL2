from collections import Counter
from typing import BinaryIO, Any

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
