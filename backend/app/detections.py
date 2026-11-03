import ipaddress
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from itertools import pairwise
from typing import Any

RULES = {
    "R01": ("Fuerza bruta / password spraying", ["T1110", "T1110.003"]),
    "R02": ("Éxito después de fallos", ["T1078"]),
    "R03": ("Logon exitoso desde IP externa", ["T1133", "T1021.001"]),
    "R04": ("Privilegios tras acceso sospechoso", ["T1078"]),
    "R05": ("PowerShell codificado", ["T1059.001", "T1027"]),
    "R06": ("Reconocimiento", ["T1069.001", "T1135"]),
    "R07": ("Movimiento lateral", ["T1021.002"]),
    "R08": ("Acceso masivo a datos sensibles", ["T1039"]),
    "R09": ("Staging / compresión", ["T1560.001", "T1074.001"]),
    "R10": ("Exfiltración por volumen", ["T1048"]),
    "R11": ("Conexión saliente de proceso sospechoso", ["T1071.001"]),
    "R12": ("Persistencia / beaconing", ["T1053.005", "T1543.003", "T1036.004"]),
    "R13": ("Inhibir recuperación", ["T1490"]),
    "R14": ("Ataque web / ejecución bajo IIS", ["T1190", "T1505.003", "T1059.003"]),
}

_WINDOW_10_MINUTES = timedelta(minutes=10)
_HTTP_SENSITIVE_PATH = re.compile(
    r"^/(?:admin(?:/|$)|login\?user=|[^?]*\.aspx\?cmd=|api/v1/export(?:[/?]|$))",
    re.IGNORECASE,
)
_ENCODED_POWERSHELL = re.compile(r"(?:^|\s)-(?:e|enc|encodedcommand)(?:\s|$)", re.IGNORECASE)
_RECOGNITION = re.compile(
    r"get-localgroupmember|get-smbshare|\bnet(?:\.exe)?\s+view\b", re.IGNORECASE
)
_ARCHIVE = re.compile(r"\b(?:tar|7z|zip)(?:\.exe)?\b", re.IGNORECASE)
_SUSPICIOUS_PATH = re.compile(r"\\(?:ProgramData|Temp|Users)\\", re.IGNORECASE)
_VSS_DELETE = re.compile(r"\bvssadmin(?:\.exe)?\s+delete\s+shadows\b", re.IGNORECASE)
_CMD_PROCESS = re.compile(r"(?:^|[\\/\s])cmd(?:\.exe)?(?:\s|$)", re.IGNORECASE)


def _event_id(event: dict[str, Any]) -> str:
    value = event.get("Event_ID")
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value).strip() if value is not None else ""


def _time(event: dict[str, Any]) -> datetime | None:
    value = event.get("Timestamp")
    if isinstance(value, datetime):
        return value
    if value is None:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def _text(event: dict[str, Any], field: str) -> str:
    value = event.get(field)
    return str(value).strip() if value is not None else ""


def _user(event: dict[str, Any]) -> str:
    return _text(event, "User").casefold()


def _host(event: dict[str, Any]) -> str:
    return _text(event, "Hostname").casefold()


def _source_ip(event: dict[str, Any]) -> str:
    return _text(event, "Source_IP")


def _is_failure(event: dict[str, Any]) -> bool:
    return _event_id(event) == "4625" and _text(event, "result_class") == "failure"


def _is_successful_logon(event: dict[str, Any]) -> bool:
    return _event_id(event) == "4624" and _text(event, "result_class") == "success"


def _is_external_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    # El escenario define 10.0.0.0/8 como interno; el resto de IP válidas es externo.
    return not (address.version == 4 and address in ipaddress.ip_network("10.0.0.0/8"))


def _destination_ip(event: dict[str, Any]) -> str:
    destination = _text(event, "Destination")
    if not destination:
        return ""
    candidate = destination.rsplit(":", 1)[0] if destination.count(":") == 1 else destination
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return ""


def _description(event: dict[str, Any]) -> str:
    return _text(event, "Event_Description")


def _command_line(event: dict[str, Any]) -> str:
    return _text(event, "Process_CommandLine")


def _logon_type(event: dict[str, Any]) -> str | None:
    match = re.search(r"LogonType\s*=\s*(\d+)", _description(event), re.IGNORECASE)
    return match.group(1) if match else None


def _ordered(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(events, key=lambda event: (_time(event) or datetime.min, _text(event, "Log_ID")))


def _finding(
    rule_id: str,
    events: list[dict[str, Any]],
    explanation: str,
) -> dict[str, Any]:
    ordered = _ordered(events)
    name, techniques = RULES[rule_id]
    timestamps = [value for event in ordered if (value := _time(event)) is not None]
    entities = {
        "users": sorted({_text(event, "User") for event in ordered if _text(event, "User")}),
        "source_ips": sorted({_source_ip(event) for event in ordered if _source_ip(event)}),
        "hosts": sorted({_text(event, "Hostname") for event in ordered if _text(event, "Hostname")}),
        "destinations": sorted(
            {_text(event, "Destination") for event in ordered if _text(event, "Destination")}
        ),
    }
    first_log_id = _text(ordered[0], "Log_ID") if ordered else "sin-evidencia"
    return {
        "finding_id": f"{rule_id}-{first_log_id}",
        "rule_id": rule_id,
        "name": name,
        "explanation": explanation,
        "technique_ids": techniques,
        "event_ids": [_text(event, "Log_ID") for event in ordered],
        "first_seen": timestamps[0].isoformat() if timestamps else None,
        "last_seen": timestamps[-1].isoformat() if timestamps else None,
        "entities": entities,
    }


def _windows(
    events: list[dict[str, Any]], duration: timedelta, threshold: int
) -> list[list[dict[str, Any]]]:
    timed_events = []
    for event in events:
        event_time = _time(event)
        if event_time is not None:
            timed_events.append((event_time, event))
    timed_events.sort(key=lambda item: item[0])

    windows: list[list[dict[str, Any]]] = []
    start = 0
    while start < len(timed_events):
        start_time = timed_events[start][0]
        end = start + 1
        while end < len(timed_events) and timed_events[end][0] - start_time <= duration:
            end += 1
        if end - start >= threshold:
            windows.append([event for _, event in timed_events[start:end]])
            start = end
        else:
            start += 1
    return windows


def _r01(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    failures_by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if _is_failure(event) and _source_ip(event):
            failures_by_ip[_source_ip(event)].append(event)

    findings = []
    for source_ip, failures in failures_by_ip.items():
        threshold = 3 if _is_external_ip(source_ip) else 5
        for window in _windows(failures, _WINDOW_10_MINUTES, threshold):
            accounts = {_user(event) for event in window if _user(event)}
            kind = "password spraying" if len(accounts) >= 3 else "fuerza bruta"
            findings.append(
                _finding(
                    "R01",
                    window,
                    f"{len(window)} fallos desde {source_ip} en 10 minutos; "
                    f"{len(accounts)} cuentas distintas ({kind}).",
                )
            )
    return findings


def _r02(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    failures = [event for event in events if _is_failure(event) and _time(event)]
    findings = []
    for success in events:
        success_time = _time(success)
        if not _is_successful_logon(success) or success_time is None:
            continue
        prior = []
        for failure in failures:
            failure_time = _time(failure)
            if (
                _user(failure) == _user(success)
                and _source_ip(failure) == _source_ip(success)
                and failure_time is not None
                and timedelta(0) <= success_time - failure_time <= timedelta(minutes=30)
            ):
                prior.append(failure)
        if prior:
            evidence = prior + [success]
            findings.append(
                _finding(
                    "R02",
                    evidence,
                    f"Logon exitoso de {_text(success, 'User')} después de "
                    f"{len(prior)} fallo(s) desde la misma IP en los 30 minutos previos.",
                )
            )
    return findings


def _r03(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for event in events:
        if (
            _is_successful_logon(event)
            and _text(event, "ip_scope") == "external"
            and _source_ip(event)
        ):
            rdp = _logon_type(event) == "10"
            findings.append(
                _finding(
                    "R03",
                    [event],
                    "Logon exitoso desde IP externa"
                    + (" mediante RDP (LogonType=10)." if rdp else "."),
                )
            )
    return findings


def _suspicious_successes(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    brute_force_log_ids = {
        log_id for finding in _r01(events) for log_id in finding["event_ids"]
    }
    suspicious = []
    for success in events:
        if not _is_successful_logon(success):
            continue
        if _text(success, "ip_scope") == "external":
            suspicious.append(success)
            continue
        success_time = _time(success)
        if success_time is None:
            continue
        matched_brute_force = False
        for failure in events:
            failure_time = _time(failure)
            if (
                _is_failure(failure)
                and _text(failure, "Log_ID") in brute_force_log_ids
                and _user(failure) == _user(success)
                and _source_ip(failure) == _source_ip(success)
                and failure_time is not None
                and timedelta(0) <= success_time - failure_time <= timedelta(minutes=30)
            ):
                matched_brute_force = True
                break
        if matched_brute_force:
            suspicious.append(success)
    return suspicious


def _r04(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    suspicious_logons = _suspicious_successes(events)
    findings = []
    for privilege_event in events:
        privilege_time = _time(privilege_event)
        if _event_id(privilege_event) != "4672" or privilege_time is None:
            continue
        related = []
        for logon in suspicious_logons:
            logon_time = _time(logon)
            if (
                _user(logon) == _user(privilege_event)
                and _source_ip(logon) == _source_ip(privilege_event)
                and logon_time is not None
                and timedelta(0) <= privilege_time - logon_time <= timedelta(minutes=15)
            ):
                related.append(logon)
        if related:
            findings.append(
                _finding(
                    "R04",
                    related[-1:] + [privilege_event],
                    "Se asignaron privilegios especiales después de un logon marcado como sospechoso.",
                )
            )
    return findings


def _r05(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        _finding("R05", [event], "La línea de comandos contiene un parámetro de PowerShell codificado.")
        for event in events
        if _ENCODED_POWERSHELL.search(_command_line(event))
    ]


def _r06(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates = [
        event
        for event in events
        if _RECOGNITION.search(_description(event) + " " + _command_line(event))
    ]
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in candidates:
        grouped[(_user(event), _host(event))].append(event)

    findings = []
    for group in grouped.values():
        for window in _windows(group, timedelta(minutes=30), 1):
            findings.append(
                _finding(
                    "R06",
                    window,
                    "Se observaron comandos de enumeración de grupos, recursos compartidos o equipos de red.",
                )
            )
    return findings


def _r07(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    suspicious_logons = _suspicious_successes(events)
    findings = []
    for lateral in events:
        lateral_time = _time(lateral)
        if (
            not _is_successful_logon(lateral)
            or _logon_type(lateral) != "3"
            or lateral_time is None
        ):
            continue
        related = []
        for logon in suspicious_logons:
            logon_time = _time(logon)
            if (
                _user(logon) == _user(lateral)
                and _host(logon) != _host(lateral)
                and logon_time is not None
                and timedelta(0) <= lateral_time - logon_time <= timedelta(minutes=15)
            ):
                related.append(logon)
        if related:
            findings.append(
                _finding(
                    "R07",
                    related[-1:] + [lateral],
                    f"La cuenta {_text(lateral, 'User')} inició sesión por red en otro host en 15 minutos.",
                )
            )
    return findings


def _sensitive_data_access(event: dict[str, Any]) -> bool:
    if _event_id(event) not in {"4663", "5145"}:
        return False
    value = " ".join(
        (_text(event, "Destination"), _description(event), _command_line(event))
    ).casefold()
    return "finance" in value or "legal" in value


def _r08(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if _sensitive_data_access(event) and _user(event):
            grouped[_user(event)].append(event)

    findings = []
    for group in grouped.values():
        for window in _windows(group, timedelta(minutes=5), 10):
            findings.append(
                _finding(
                    "R08",
                    window,
                    f"{len(window)} accesos a Finance/Legal por la misma cuenta en 5 minutos.",
                )
            )
    return findings


def _r09(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for event in events:
        command = _command_line(event)
        if _ARCHIVE.search(command) and re.search(r"\\(?:Temp|Public)\\", command, re.IGNORECASE):
            findings.append(
                _finding(
                    "R09",
                    [event],
                    "Se creó un archivo comprimido en una ubicación temporal o pública.",
                )
            )
    return findings


def _r10(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        destination_ip = _destination_ip(event)
        if (
            _event_id(event) == "PROXY_ACCESS"
            and "post" in _description(event).casefold()
            and destination_ip
            and _is_external_ip(destination_ip)
            and isinstance(event.get("bytes_out"), (int, float))
        ):
            grouped[(_user(event), destination_ip)].append(event)

    findings = []
    for (user, destination_ip), group in grouped.items():
        for window in _windows(group, timedelta(minutes=10), 1):
            total_bytes = sum(int(event["bytes_out"]) for event in window)
            if total_bytes < 50 * 1024 * 1024:
                continue
            findings.append(
                _finding(
                    "R10",
                    window,
                    f"POST salientes a {destination_ip}: {total_bytes:,} bytes en 10 minutos "
                    f"para la cuenta {_text(window[0], 'User')}.",
                )
            )
    return findings


def _r11(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for event in events:
        process = (_command_line(event) + " " + _description(event)).casefold()
        destination_ip = _destination_ip(event)
        if (
            _event_id(event) == "5156"
            and "powershell.exe" in process
            and destination_ip
            and _is_external_ip(destination_ip)
        ):
            findings.append(
                _finding(
                    "R11",
                    [event],
                    f"Conexión permitida desde PowerShell hacia la IP externa {destination_ip}.",
                )
            )
    return findings


def _r12(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    persistence_by_principal: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if (
            _event_id(event) in {"4698", "7045"}
            and _SUSPICIOUS_PATH.search(_command_line(event))
        ):
            persistence_by_principal[(_host(event), _user(event))].append(event)

    executions: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        path = _text(event, "file_path") or _command_line(event)
        if (
            _event_id(event) == "4688"
            and _SUSPICIOUS_PATH.search(path)
            and _time(event) is not None
        ):
            executions[(_host(event), _user(event), path.casefold())].append(event)

    beacon_by_principal: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for (host, user, _binary), group in executions.items():
        ordered = _ordered(group)
        if len(ordered) < 4:
            continue
        times = [event_time for event in ordered if (event_time := _time(event)) is not None]
        intervals = [(right - left).total_seconds() for left, right in pairwise(times)]
        mean_interval = sum(intervals) / len(intervals)
        if mean_interval and max(abs(interval - mean_interval) for interval in intervals) / mean_interval < 0.10:
            beacon_by_principal[(host, user)].extend(ordered)

    findings = []
    principals = set(persistence_by_principal) | set(beacon_by_principal)
    for principal in principals:
        evidence = persistence_by_principal.get(principal, []) + beacon_by_principal.get(principal, [])
        unique_events = { _text(event, "Log_ID"): event for event in evidence }
        findings.append(
            _finding(
                "R12",
                list(unique_events.values()),
                "Se observó creación de tarea/servicio en una ruta sensible y/o ejecución periódica de un binario.",
            )
        )
    return findings


def _r13(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        _finding("R13", [event], "El comando elimina shadow copies y puede inhibir la recuperación.")
        for event in events
        if _VSS_DELETE.search(_command_line(event))
    ]


def _r14(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    requests_by_source: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if (
            _event_id(event) == "HTTP_ACCESS"
            and _HTTP_SENSITIVE_PATH.search(_command_line(event))
            and _time(event) is not None
        ):
            requests_by_source[(_source_ip(event), _host(event))].append(event)

    processes_by_source: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if (
            _event_id(event) == "4688"
            and _text(event, "User").casefold().startswith("iis apppool\\")
            and _CMD_PROCESS.search(_command_line(event))
        ):
            processes_by_source[(_source_ip(event), _host(event))].append(event)

    findings = []
    source_keys = set(requests_by_source) | set(processes_by_source)
    for source_key in source_keys:
        requests = requests_by_source.get(source_key, [])
        processes = processes_by_source.get(source_key, [])
        failed_requests = [event for event in requests if (event.get("http_status") or 0) >= 400]
        request_windows = _windows(failed_requests, timedelta(minutes=10), 5)
        included_process_ids: set[str] = set()
        for window in request_windows:
            start = _time(window[0])
            if start is None:
                continue
            evidence = []
            for event in requests:
                event_time = _time(event)
                if (
                    event_time is not None
                    and start - timedelta(minutes=10) <= event_time <= start + timedelta(minutes=10)
                ):
                    evidence.append(event)
            related_processes = []
            for process in processes:
                process_time = _time(process)
                if (
                    process_time is not None
                    and start - timedelta(minutes=10) <= process_time <= start + timedelta(minutes=15)
                ):
                    related_processes.append(process)
            included_process_ids.update(_text(process, "Log_ID") for process in related_processes)
            evidence.extend(related_processes)
            findings.append(
                _finding(
                    "R14",
                    evidence,
                    f"{len(window)} solicitudes a rutas sensibles con respuesta 4xx/5xx "
                    "y/o ejecución de cmd.exe bajo la identidad de IIS APPPOOL.",
                )
            )

        for process in processes:
            process_time = _time(process)
            if _text(process, "Log_ID") not in included_process_ids:
                related_requests = []
                for request in requests:
                    request_time = _time(request)
                    if (
                        request_time is not None
                        and process_time is not None
                        and abs((process_time - request_time).total_seconds()) <= 15 * 60
                    ):
                        related_requests.append(request)
                findings.append(
                    _finding(
                        "R14",
                        related_requests + [process],
                        "Se observó cmd.exe ejecutado bajo la identidad de IIS APPPOOL.",
                    )
                )
    return findings


def _disambiguate_finding_ids(findings: list[dict[str, Any]]) -> None:
    """Preserve unique legacy IDs and suffix collisions with the final evidence Log_ID."""
    counts = Counter(finding["finding_id"] for finding in findings)
    reserved_ids = set(counts)
    used_ids = {finding["finding_id"] for finding in findings if counts[finding["finding_id"]] == 1}
    duplicate_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        if counts[finding["finding_id"]] > 1:
            duplicate_groups[finding["finding_id"]].append(finding)

    for base_id, duplicates in duplicate_groups.items():
        ordered_duplicates = sorted(duplicates, key=lambda finding: tuple(finding.get("event_ids", [])))
        for index, finding in enumerate(ordered_duplicates, start=1):
            evidence_ids = finding.get("event_ids", [])
            suffix = evidence_ids[-1] if evidence_ids else f"sin-evidencia-{index:02d}"
            candidate = f"{base_id}-{suffix}"
            if candidate in reserved_ids or candidate in used_ids:
                candidate = f"{candidate}-{index:02d}"
            while candidate in reserved_ids or candidate in used_ids:
                candidate = f"{candidate}-{index:02d}"
            finding["finding_id"] = candidate
            used_ids.add(candidate)


def run_detections(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run deterministic rules R01-R14; every finding includes source Log_ID evidence."""
    rules = (_r01, _r02, _r03, _r04, _r05, _r06, _r07, _r08, _r09, _r10, _r11, _r12, _r13, _r14)
    findings = [finding for rule in rules for finding in rule(events)]
    _disambiguate_finding_ids(findings)
    return sorted(
        findings,
        key=lambda finding: (
            finding["first_seen"] or "",
            finding["rule_id"],
            finding["finding_id"],
            tuple(finding.get("event_ids", [])),
        ),
    )
