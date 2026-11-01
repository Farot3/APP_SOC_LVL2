from typing import Any

RULE_TACTICS = {
    "R01": {"credential_access"},
    "R02": {"initial_access"},
    "R03": {"initial_access"},
    "R04": {"privilege_escalation"},
    "R05": {"execution", "defense_evasion"},
    "R06": {"discovery"},
    "R07": {"lateral_movement"},
    "R08": {"collection"},
    "R09": {"collection", "data_staging"},
    "R10": {"exfiltration"},
    "R11": {"command_and_control"},
    "R12": {"persistence"},
    "R13": {"impact"},
    "R14": {"initial_access", "execution"},
}

_ASSET_IMPACT = {
    "DC-01": 5,
    "FS-SRV01": 4,
    "APP-SRV01": 4,
    "DB-SRV01": 4,
    "WEB-01": 3,
}
_LEVELS = ((4, "Bajo"), (9, "Medio"), (16, "Alto"), (25, "Crítico"))


def _host_impact(host: str) -> int:
    normalized = host.upper().replace("DC01", "DC-01")
    if normalized in _ASSET_IMPACT:
        return _ASSET_IMPACT[normalized]
    if normalized.startswith("WS-"):
        return 2
    return 1


def _asset_impact(incident: dict[str, Any]) -> tuple[int, str]:
    hosts = incident.get("entities", {}).get("hosts", [])
    if not hosts:
        return 1, "No se identificó un activo más específico en los eventos detectados."
    scored_hosts = sorted(((_host_impact(host), host) for host in hosts), reverse=True)
    impact, host = scored_hosts[0]
    return impact, f"Activo de mayor impacto observado: {host} (nivel {impact})."


def _action_impact(incident: dict[str, Any]) -> tuple[int, str]:
    rules = set(incident.get("rule_ids", []))
    if "R13" in rules:
        return 5, "La eliminación de shadow copies puede inhibir la recuperación."
    if "R12" in rules:
        return 5, "Se observó persistencia mediante tarea/servicio y ejecución periódica."
    if {"R09", "R10"} <= rules:
        return 5, "Compresión de archivos de Legal seguida de transferencia externa de alto volumen."
    if {"R07", "R08"} <= rules or "R07" in rules:
        return 4, "Se observó movimiento lateral o acceso a datos sensibles."
    if "R08" in rules:
        return 4, "Se observó acceso masivo a datos sensibles."
    if "R14" in rules:
        return 3, "Se observaron solicitudes web sospechosas y ejecución de comandos bajo IIS."
    if "R06" in rules:
        return 2, "Se observó reconocimiento sin otra acción de impacto superior."
    return 1, "La evidencia corresponde a una actividad aislada o de impacto no confirmado."


def _confidence(incident: dict[str, Any]) -> tuple[int, str]:
    rules = set(incident.get("rule_ids", []))
    tactics = {tactic for rule in rules for tactic in RULE_TACTICS.get(rule, set())}
    events = incident.get("events", [])
    sources = {str(event.get("Log_Source")) for event in events if event.get("Log_Source")}
    has_success = any(
        event.get("result_class") == "success"
        or str(event.get("Result", "")).casefold() == "success"
        for event in events
    )
    has_command = any(
        str(event.get("Event_ID")) in {"4688", "4104"}
        or "cmd.exe" in str(event.get("Process_CommandLine", "")).casefold()
        for event in events
    )
    event_count = len({str(event.get("Log_ID")) for event in events})

    if len(tactics) >= 3 and len(sources) >= 3:
        return 5, f"Cadena con {len(tactics)} tácticas y evidencia de {len(sources)} fuentes de log."
    if len(tactics) >= 3:
        return 4, f"Cadena que cubre {len(tactics)} tácticas ATT&CK distintas."
    if len(tactics) >= 2 and (has_success or has_command):
        return 4, f"Varias tácticas respaldadas por éxito o ejecución observada; {len(sources)} fuentes de log."
    if has_success or has_command:
        return 3, "Patrón con indicador de éxito o comando ejecutado."
    if event_count >= 3:
        return 2, f"Patrón respaldado por {event_count} eventos."
    return 1, "Evidencia aislada, sin indicador de éxito confirmado."


def _risk_level(score: int) -> str:
    for upper_bound, level in _LEVELS:
        if score <= upper_bound:
            return level
    return "Crítico"


def score_incident(incident: dict[str, Any]) -> dict[str, Any]:
    """Calculate impact, confidence, score, and rationale from structured evidence."""
    asset_score, asset_reason = _asset_impact(incident)
    action_score, action_reason = _action_impact(incident)
    impact = max(asset_score, action_score)
    confidence, confidence_reason = _confidence(incident)
    score = impact * confidence
    return {
        "impact": impact,
        "confidence": confidence,
        "score": score,
        "level": _risk_level(score),
        "impact_rationale": asset_reason if asset_score >= action_score else action_reason,
        "confidence_rationale": confidence_reason,
    }


def score_incidents(incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for incident in incidents:
        incident["risk"] = score_incident(incident)
    return incidents
