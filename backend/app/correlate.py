import ipaddress
import re
from datetime import datetime, timedelta
from typing import Any

_CORRELATION_WINDOW = timedelta(minutes=30)
_ANONYMOUS_USERS = {"", "-", "anónimo/no autenticado", "anonymous", "unknown"}
_ASSET_PATTERNS = re.compile(
    r"DC-?01|APP-SRV01|FS-SRV01|DB-SRV01|WEB-01|WS-\d+", re.IGNORECASE
)


def _time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if value is None:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def _finding_times(finding: dict[str, Any]) -> tuple[datetime, datetime] | None:
    first = _time(finding.get("first_seen"))
    last = _time(finding.get("last_seen"))
    if first is None or last is None:
        return None
    return first, last


def _time_gap(left: dict[str, Any], right: dict[str, Any]) -> timedelta | None:
    left_times = _finding_times(left)
    right_times = _finding_times(right)
    if left_times is None or right_times is None:
        return None
    left_start, left_end = left_times
    right_start, right_end = right_times
    if left_end < right_start:
        return right_start - left_end
    if right_end < left_start:
        return left_start - right_end
    return timedelta(0)


def _strong_entities(finding: dict[str, Any]) -> set[tuple[str, str]]:
    entities = finding.get("entities", {})
    users = {
        value.strip().casefold()
        for value in entities.get("users", [])
        if value.strip().casefold() not in _ANONYMOUS_USERS
    }
    source_ips = {value.strip() for value in entities.get("source_ips", []) if value.strip()}
    return {("user", value) for value in users} | {("source_ip", value) for value in source_ips}


def _is_strong_r02(finding: dict[str, Any], brute_force_ips: set[str]) -> bool:
    source_ips = set(finding.get("entities", {}).get("source_ips", []))
    return bool(source_ips & brute_force_ips)


def _share_direct_entity(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return bool(_strong_entities(left) & _strong_entities(right))


def _connected_components(findings: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    parents = list(range(len(findings)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parents[right_root] = left_root

    for left_index, left in enumerate(findings):
        for right_index in range(left_index + 1, len(findings)):
            right = findings[right_index]
            gap = _time_gap(left, right)
            if (
                gap is not None
                and gap <= _CORRELATION_WINDOW
                and _share_direct_entity(left, right)
            ):
                union(left_index, right_index)

    groups: dict[int, list[dict[str, Any]]] = {}
    for index, finding in enumerate(findings):
        groups.setdefault(find(index), []).append(finding)
    return list(groups.values())


def _incident_title(findings: list[dict[str, Any]]) -> str:
    rules = {finding["rule_id"] for finding in findings}
    if {"R01", "R04"} <= rules and "R05" in rules:
        return "Acceso externo, reconocimiento y movimiento lateral"
    if {"R01", "R04"} <= rules:
        return "Fuerza bruta con logon externo y privilegios"
    if {"R05", "R08", "R13"} <= rules:
        return "Acceso masivo a Finance e inhibición de recuperación"
    if {"R09", "R10"} <= rules:
        return "Compresión y posible exfiltración de datos"
    if "R12" in rules:
        return "Persistencia mediante tarea o servicio"
    if "R14" in rules:
        return "Ataque web y ejecución bajo IIS"
    return ", ".join(sorted({finding["name"] for finding in findings}))


def _incident_entities(findings: list[dict[str, Any]]) -> dict[str, list[str]]:
    fields = ("users", "source_ips", "hosts", "destinations")
    return {
        field: sorted(
            {
                value
                for finding in findings
                for value in finding.get("entities", {}).get(field, [])
                if value
            }
        )
        for field in fields
    }


def _incident_events(
    findings: list[dict[str, Any]], event_by_id: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    log_ids = {log_id for finding in findings for log_id in finding.get("event_ids", [])}
    found_events = [event_by_id[log_id] for log_id in log_ids if log_id in event_by_id]
    return sorted(
        found_events,
        key=lambda event: (_time(event.get("Timestamp")) or datetime.min, str(event.get("Log_ID", ""))),
    )


def _extract_ips(incident_events: list[dict[str, Any]]) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    ips = set()
    for event in incident_events:
        candidates = [event.get("Source_IP"), event.get("Destination")]
        for value in candidates:
            if value is None:
                continue
            text = str(value).strip()
            if text.count(":") == 1:
                text = text.rsplit(":", 1)[0]
            try:
                address = ipaddress.ip_address(text)
            except ValueError:
                continue
            if address.version == 4 and address in ipaddress.ip_network("10.0.0.0/8"):
                continue
            ips.add(address)
    return ips


def _hypotheses(incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hypotheses = []
    for index, left in enumerate(incidents):
        left_ips = _extract_ips(left["events"])
        for right in incidents[index + 1 :]:
            right_ips = _extract_ips(right["events"])
            matching_pairs = []
            for left_ip in left_ips:
                if left_ip.version != 4:
                    continue
                for right_ip in right_ips:
                    if (
                        right_ip.version == 4
                        and left_ip != right_ip
                        and left_ip in ipaddress.ip_network(f"{right_ip}/24", strict=False)
                    ):
                        matching_pairs.append((str(left_ip), str(right_ip)))
            if matching_pairs:
                pairs = sorted(set(matching_pairs))
                hypotheses.append(
                    {
                        "type": "shared_ipv4_24",
                        "incident_ids": [left["incident_id"], right["incident_id"]],
                        "ip_pairs": [list(pair) for pair in pairs],
                        "status": "hypothesis_unconfirmed",
                        "explanation": "Las IP comparten un /24; los registros no demuestran por sí solos que los incidentes estén relacionados.",
                    }
                )
    return hypotheses


def correlate_findings(
    findings: list[dict[str, Any]], events: list[dict[str, Any]]
) -> dict[str, Any]:
    """Group corroborated findings; keep weak R02 matches and /24 links separate."""
    brute_force_ips = {
        source_ip
        for finding in findings
        if finding.get("rule_id") == "R01"
        for source_ip in finding.get("entities", {}).get("source_ips", [])
    }
    incident_findings = []
    informational_findings = []
    for finding in findings:
        if finding.get("rule_id") == "R02" and not _is_strong_r02(finding, brute_force_ips):
            informational_findings.append(finding)
        else:
            incident_findings.append(finding)

    components = _connected_components(incident_findings)
    components.sort(
        key=lambda group: min(
            (_finding_times(finding) or (datetime.max, datetime.max))[0]
            for finding in group
        )
    )
    event_by_id = {str(event.get("Log_ID")): event for event in events}

    incidents = []
    for index, group in enumerate(components, start=1):
        ordered_findings = sorted(
            group,
            key=lambda finding: (finding.get("first_seen") or "", finding.get("rule_id", "")),
        )
        incident_events = _incident_events(ordered_findings, event_by_id)
        incidents.append(
            {
                "incident_id": f"I-{index:02d}",
                "title": _incident_title(ordered_findings),
                "rule_ids": sorted({finding["rule_id"] for finding in ordered_findings}),
                "technique_ids": sorted(
                    {technique for finding in ordered_findings for technique in finding.get("technique_ids", [])}
                ),
                "entities": _incident_entities(ordered_findings),
                "finding_ids": [finding["finding_id"] for finding in ordered_findings],
                "findings": ordered_findings,
                "event_ids": [str(event.get("Log_ID")) for event in incident_events],
                "events": incident_events,
            }
        )

    return {
        "incidents": incidents,
        "informational_findings": informational_findings,
        "hypotheses": _hypotheses(incidents),
    }
