import json
import os
from typing import Any

import httpx

_INTERACTIONS_URL = "https://generativelanguage.googleapis.com/v1beta/interactions"


class GeminiConfigurationError(Exception):
    pass


class GeminiAPIError(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def gemini_status() -> dict[str, Any]:
    return {
        "enabled": bool(os.getenv("GEMINI_API_KEY", "").strip()),
        "model": os.getenv("GEMINI_MODEL", "gemini-3.6-flash").strip() or "gemini-3.6-flash",
    }


def _schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "conclusion": {"type": "string", "enum": ["sospechoso", "no_suficiente"]},
            "evidence_ids": {"type": "array", "items": {"type": "string"}},
            "origenes": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "ip": {"type": "string"},
                        "analisis": {"type": "string"},
                        "evidence_ids": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["ip", "analisis", "evidence_ids"],
                },
            },
            "comprobaciones_recomendadas": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "comprobacion": {"type": "string"},
                        "evidence_ids": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["comprobacion", "evidence_ids"],
                },
            },
            "explicacion": {"type": "string"},
            "limitacion": {"type": "string"},
        },
        "required": [
            "conclusion",
            "evidence_ids",
            "origenes",
            "comprobaciones_recomendadas",
            "explicacion",
            "limitacion",
        ],
    }


def _package_incident(incident: dict[str, Any]) -> dict[str, Any]:
    finding_fields = (
        "finding_id",
        "rule_id",
        "name",
        "explanation",
        "technique_ids",
        "event_ids",
        "first_seen",
        "last_seen",
        "entities",
    )
    event_fields = (
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
    return {
        "incident_id": incident.get("incident_id"),
        "title": incident.get("title"),
        "rule_ids": incident.get("rule_ids", []),
        "baseline_risk": incident.get("risk", {}),
        "findings": [
            {field: finding.get(field) for field in finding_fields if field in finding}
            for finding in incident.get("findings", [])
        ],
        "events": [
            {field: event.get(field) for field in event_fields if field in event}
            for event in incident.get("events", [])
        ],
    }


def validate_model_output(
    output_text: str,
    incident: dict[str, Any],
    model: str,
) -> dict[str, Any]:
    try:
        result = json.loads(output_text)
    except json.JSONDecodeError as exc:
        raise GeminiAPIError(502, "Gemini devolvió una respuesta que no es JSON válido.") from exc

    if not isinstance(result, dict):
        raise GeminiAPIError(502, "Gemini devolvió una respuesta JSON con formato inesperado.")

    conclusion = result.get("conclusion")
    evidence_ids = result.get("evidence_ids")
    origins = result.get("origenes")
    recommended_checks = result.get("comprobaciones_recomendadas")
    explanation = result.get("explicacion")
    limitation = result.get("limitacion")
    if not isinstance(conclusion, str) or conclusion not in {"sospechoso", "no_suficiente"}:
        raise GeminiAPIError(502, "Gemini devolvió una conclusión no permitida.")
    if not isinstance(evidence_ids, list) or not all(isinstance(value, str) for value in evidence_ids):
        raise GeminiAPIError(502, "Gemini devolvió una lista de evidence_ids inválida.")
    if not isinstance(origins, list):
        raise GeminiAPIError(502, "Gemini devolvió un análisis de orígenes inválido.")
    if not isinstance(recommended_checks, list):
        raise GeminiAPIError(502, "Gemini devolvió una lista de comprobaciones inválida.")
    if not isinstance(explanation, str) or not explanation.strip():
        raise GeminiAPIError(502, "Gemini omitió la explicación del análisis.")
    if not isinstance(limitation, str) or not limitation.strip():
        raise GeminiAPIError(502, "Gemini omitió la limitación del análisis.")

    events = incident.get("events", [])
    events_by_id = {str(event.get("Log_ID")): event for event in events}
    valid_ids = set(events_by_id)
    invalid_ids = sorted(set(evidence_ids) - valid_ids)
    if invalid_ids:
        raise GeminiAPIError(502, "Gemini citó Log_ID que no pertenecen a este incidente.")

    valid_source_ips = {
        str(event.get("Source_IP")).strip()
        for event in events
        if event.get("Source_IP") is not None and str(event.get("Source_IP")).strip()
    }
    validated_origins = []
    seen_origin_ips = set()
    for origin in origins:
        if not isinstance(origin, dict):
            raise GeminiAPIError(502, "Gemini devolvió una entrada de origen inválida.")
        source_ip = origin.get("ip")
        analysis = origin.get("analisis")
        origin_evidence = origin.get("evidence_ids")
        if not isinstance(source_ip, str) or source_ip not in valid_source_ips:
            raise GeminiAPIError(502, "Gemini citó una IP de origen que no aparece en este incidente.")
        if not isinstance(analysis, str) or not analysis.strip():
            raise GeminiAPIError(502, "Gemini omitió el análisis de una IP de origen.")
        if (
            not isinstance(origin_evidence, list)
            or not origin_evidence
            or not all(isinstance(value, str) for value in origin_evidence)
        ):
            raise GeminiAPIError(502, "Gemini devolvió evidencia inválida para una IP de origen.")
        if not set(origin_evidence) <= set(evidence_ids):
            raise GeminiAPIError(502, "Las citas del análisis de origen deben aparecer en evidence_ids.")
        if any(
            evidence_id not in events_by_id
            or str(events_by_id[evidence_id].get("Source_IP") or "").strip() != source_ip
            for evidence_id in origin_evidence
        ):
            raise GeminiAPIError(502, "La evidencia citada no respalda la IP de origen indicada.")
        if source_ip not in seen_origin_ips:
            validated_origins.append(
                {
                    "ip": source_ip,
                    "analisis": analysis,
                    "evidence_ids": list(dict.fromkeys(origin_evidence)),
                }
            )
            seen_origin_ips.add(source_ip)

    if len(recommended_checks) > 5:
        raise GeminiAPIError(502, "Gemini devolvió demasiadas comprobaciones recomendadas.")
    validated_checks = []
    for item in recommended_checks:
        if not isinstance(item, dict):
            raise GeminiAPIError(502, "Gemini devolvió una comprobación inválida.")
        check = item.get("comprobacion")
        check_evidence = item.get("evidence_ids")
        if not isinstance(check, str) or not check.strip():
            raise GeminiAPIError(502, "Gemini omitió una comprobación recomendada.")
        if (
            not isinstance(check_evidence, list)
            or not check_evidence
            or not all(isinstance(value, str) for value in check_evidence)
        ):
            raise GeminiAPIError(502, "Gemini devolvió citas inválidas para una comprobación.")
        if not set(check_evidence) <= valid_ids:
            raise GeminiAPIError(502, "Una comprobación cita Log_ID que no pertenecen a este incidente.")
        if not set(check_evidence) <= set(evidence_ids):
            raise GeminiAPIError(502, "Las citas de comprobación deben aparecer en evidence_ids.")
        validated_checks.append(
            {
                "comprobacion": check,
                "evidence_ids": list(dict.fromkeys(check_evidence)),
            }
        )

    return {
        "incident_id": incident.get("incident_id"),
        "model": model,
        "conclusion": conclusion,
        "evidence_ids": list(dict.fromkeys(evidence_ids)),
        "origenes": validated_origins,
        "comprobaciones_recomendadas": validated_checks,
        "explicacion": explanation,
        "limitacion": limitation,
        "baseline_risk_level": incident.get("risk", {}).get("level"),
    }


def _output_text(response_payload: dict[str, Any]) -> str:
    direct_text = response_payload.get("output_text")
    if isinstance(direct_text, str) and direct_text:
        return direct_text

    steps = response_payload.get("steps", [])
    if not isinstance(steps, list):
        return ""
    text_parts = [
        part["text"]
        for step in steps
        if isinstance(step, dict) and step.get("type") == "model_output"
        and isinstance(step.get("content"), list)
        for part in step["content"]
        if isinstance(part, dict) and part.get("type") == "text"
        and isinstance(part.get("text"), str)
    ]
    return "\n".join(part for part in text_parts if part)


def interpret_incident(incident: dict[str, Any]) -> dict[str, Any]:
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise GeminiConfigurationError("Gemini no está configurado. Define GEMINI_API_KEY en el entorno del backend.")

    model = os.getenv("GEMINI_MODEL", "gemini-3.6-flash").strip() or "gemini-3.6-flash"
    try:
        configured_timeout = float(os.getenv("GEMINI_TIMEOUT_SECONDS", "60"))
    except ValueError as exc:
        raise GeminiConfigurationError("GEMINI_TIMEOUT_SECONDS debe ser un número.") from exc
    timeout_seconds = max(5.0, min(configured_timeout, 300.0))
    package_json = json.dumps(_package_incident(incident), ensure_ascii=False, separators=(",", ":"))
    prompt = f"""Analiza este único incidente SOC usando solo los datos del paquete.
La conclusión indica si merece revisión humana:
- sospechoso: merece revisión; no significa que el ataque esté confirmado.
- no_suficiente: no hay base suficiente ni siquiera para recomendar revisión.
Devuelve evidencia concisa: solo los Log_ID pertinentes, exactos y en orden cronológico; no repitas todos los eventos por defecto.
En origenes, analiza cada IP Source_IP relevante usando solo datos del paquete. Escribe la IP exactamente como aparece y cita eventos con esa misma Source_IP. Distingue observaciones de inferencias; no afirmes reputación, geolocalización, propietario ni malicia sin datos que lo respalden. No clasifiques una IP como maliciosa solo por ser externa.
En comprobaciones_recomendadas, propone como máximo cinco pasos de investigación para un analista humano, sin ejecutar acciones ni afirmar que ya se realizaron. Incluye solo pasos útiles y cita los Log_ID que los motivan; si no hay pasos útiles, devuelve una lista vacía.
No afirmes que una hipótesis está confirmada. Distingue los indicios de lo que no se puede determinar.
Usa exclusivamente Log_ID presentes en events. No inventes IP, técnicas ni hechos. Las citas de origen y de comprobaciones también deben estar incluidas en evidence_ids.

Paquete del incidente:
{package_json}"""
    request_payload = {
        "model": model,
        "input": prompt,
        "response_format": {
            "type": "text",
            "mime_type": "application/json",
            "schema": _schema(),
        },
    }

    try:
        response = httpx.post(
            _INTERACTIONS_URL,
            headers={"x-goog-api-key": api_key},
            json=request_payload,
            timeout=timeout_seconds,
        )
    except httpx.TimeoutException as exc:
        raise GeminiAPIError(504, "Gemini tardó demasiado en responder. Intenta nuevamente.") from exc
    except httpx.RequestError as exc:
        raise GeminiAPIError(502, "No se pudo conectar con Gemini.") from exc

    if response.is_error:
        if response.status_code == 429:
            raise GeminiAPIError(429, "Gemini alcanzó el límite de solicitudes. Intenta más tarde.")
        if response.status_code == 503:
            raise GeminiAPIError(503, "Gemini está temporalmente ocupado. Intenta nuevamente más tarde.")
        raise GeminiAPIError(502, f"Gemini rechazó la solicitud (HTTP {response.status_code}).")

    try:
        response_payload = response.json()
    except ValueError as exc:
        raise GeminiAPIError(502, "Gemini devolvió una respuesta de API inválida.") from exc
    if not isinstance(response_payload, dict):
        raise GeminiAPIError(502, "Gemini devolvió una respuesta de API con formato inesperado.")

    output_text = _output_text(response_payload)
    if not output_text:
        raise GeminiAPIError(502, "Gemini no devolvió texto para este incidente.")
    return validate_model_output(output_text, incident, model)
