import ipaddress
import re
from typing import Any


_HTTP_STATUS = re.compile(r"^\s*(\d{3})\s*$")
_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_BYTES_OUT = re.compile(r"\bbytes_out\s*[:=]\s*([\d,]+)", re.IGNORECASE)
_WINDOWS_PATH = re.compile(r"(?:[A-Za-z]:\\|\\\\)[^\s\"'<>|,;]+")
_TASK_NAME = re.compile(
    r"(?:/tn\s+|task_name\s*[:=]\s*)(?:\"([^\"]+)\"|'([^']+)'|(\S+))",
    re.IGNORECASE,
)
_SERVICE_NAME = re.compile(
    r"(?:sc(?:\.exe)?\s+create\s+|New-Service\s+(?:-Name\s+)?|service_name\s*[:=]\s*)"
    r"(?:\"([^\"]+)\"|'([^']+)'|(\S+))",
    re.IGNORECASE,
)


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value).strip()


def _first_group(match: re.Match[str] | None) -> str | None:
    if match is None:
        return None
    return next((group for group in match.groups() if group is not None), None)


def _http_status(result: Any) -> int | None:
    match = _HTTP_STATUS.fullmatch(_text(result))
    if not match:
        return None
    status = int(match.group(1))
    return status if 100 <= status <= 599 else None


def _result_class(result: Any, status: int | None) -> str:
    value = _text(result).casefold()
    if value == "success":
        return "success"
    if value == "failure":
        return "failure"
    if value == "allowed":
        return "allowed"
    if status is not None:
        if 200 <= status < 400:
            return "success"
        if status >= 400:
            return "failure"
    return "unknown"


def _ip_scope(source_ip: Any) -> str:
    value = _text(source_ip)
    if not value:
        return "unknown"
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return "unknown"
    if address.version == 4 and address in ipaddress.ip_network("10.0.0.0/8"):
        return "internal"
    return "external"


def _command_fields(command_line: Any) -> dict[str, Any]:
    value = _text(command_line)
    if not value:
        return {
            "command": None,
            "uri": None,
            "bytes_out": None,
            "task_name": None,
            "service_name": None,
            "file_path": None,
        }

    quoted_command = re.match(r'^\s*["\']([^"\']+)["\']', value)
    command = quoted_command.group(1) if quoted_command else value.split(maxsplit=1)[0]
    bytes_match = _BYTES_OUT.search(value)
    bytes_out = int(bytes_match.group(1).replace(",", "")) if bytes_match else None
    file_match = _WINDOWS_PATH.search(value)
    uri_match = _URL.search(value)

    return {
        "command": command,
        "uri": uri_match.group(0).rstrip(".,)") if uri_match else None,
        "bytes_out": bytes_out,
        "task_name": _first_group(_TASK_NAME.search(value)),
        "service_name": _first_group(_SERVICE_NAME.search(value)),
        "file_path": file_match.group(0).rstrip(".,)") if file_match else None,
    }


def normalize_event(event: dict[str, Any]) -> dict[str, Any]:
    """Return a normalized copy while retaining source values for auditability."""
    normalized = dict(event)

    raw_hostname = _text(event.get("Hostname"))
    if raw_hostname.casefold().replace("-", "") == "dc01":
        if raw_hostname != "DC-01":
            normalized["Hostname_original"] = event.get("Hostname")
        normalized["Hostname"] = "DC-01"

    normalized["Event_ID"] = _text(event.get("Event_ID"))

    raw_user = _text(event.get("User"))
    if raw_user == "-":
        normalized["User_original"] = event.get("User")
        normalized["User"] = "Anónimo/no autenticado"

    destination = event.get("Destination")
    if destination is None or (isinstance(destination, str) and not destination.strip()):
        normalized["Destination"] = None

    status = _http_status(event.get("Result"))
    normalized["http_status"] = status
    normalized["result_class"] = _result_class(event.get("Result"), status)
    normalized["ip_scope"] = _ip_scope(event.get("Source_IP"))
    normalized.update(_command_fields(event.get("Process_CommandLine")))
    return normalized


def normalize_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [normalize_event(event) for event in events]


def quality_warnings(events: list[dict[str, Any]]) -> list[str]:
    warnings: list[str] = []
    alias_count = sum("Hostname_original" in event for event in events)
    anonymous_count = sum("User_original" in event for event in events)
    empty_destination_count = sum(event.get("Destination") is None for event in events)

    if alias_count:
        warnings.append(f"Se normalizaron {alias_count} nombres de host DC01 a DC-01.")
    if anonymous_count:
        warnings.append(
            f"{anonymous_count} eventos sin usuario autenticado se etiquetaron como anónimos."
        )
    if empty_destination_count:
        warnings.append(
            f"{empty_destination_count} eventos no tienen Destination; se conservaron como nulo."
        )
    return warnings
