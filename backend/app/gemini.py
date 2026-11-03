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
            "clasificaciones_hallazgos": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "finding_id": {"type": "string"},
                        "riesgo": {"type": "string", "enum": ["Crítico", "Alto", "Medio", "Bajo"]},
                        "justificacion": {"type": "string"},
                        "tecnica_mitre": {"type": "array", "items": {"type": "string"}},
                        "confianza": {"type": "integer"},
                        "evidence_ids": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": [
                        "finding_id",
                        "riesgo",
                        "justificacion",
                        "tecnica_mitre",
                        "confianza",
                        "evidence_ids",
                    ],
                },
            },
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
            "clasificaciones_hallazgos",
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
    finding_classifications = result.get("clasificaciones_hallazgos", [])
    origins = result.get("origenes")
    recommended_checks = result.get("comprobaciones_recomendadas")
    explanation = result.get("explicacion")
    limitation = result.get("limitacion")
    if not isinstance(conclusion, str) or conclusion not in {"sospechoso", "no_suficiente"}:
        raise GeminiAPIError(502, "Gemini devolvió una conclusión no permitida.")
    if not isinstance(evidence_ids, list) or not all(isinstance(value, str) for value in evidence_ids):
        raise GeminiAPIError(502, "Gemini devolvió una lista de evidence_ids inválida.")
    if not isinstance(finding_classifications, list):
        raise GeminiAPIError(502, "Gemini devolvió una lista de clasificaciones de hallazgos inválida.")
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

    findings_by_id = {
        str(finding.get("finding_id")): finding
        for finding in incident.get("findings", [])
        if finding.get("finding_id") is not None
    }
    classifications_by_id: dict[str, dict[str, Any]] = {}
    for classification in finding_classifications:
        if not isinstance(classification, dict):
            raise GeminiAPIError(502, "Gemini devolvió una clasificación de hallazgo inválida.")
        finding_id = classification.get("finding_id")
        if not isinstance(finding_id, str) or finding_id not in findings_by_id:
            raise GeminiAPIError(502, "Gemini citó un finding_id que no pertenece a este incidente.")
        if finding_id in classifications_by_id:
            raise GeminiAPIError(502, "Gemini devolvió más de una clasificación para el mismo hallazgo.")

        risk = classification.get("riesgo")
        justification = classification.get("justificacion")
        techniques = classification.get("tecnica_mitre")
        confidence = classification.get("confianza")
        finding_evidence = classification.get("evidence_ids")
        if not isinstance(risk, str) or risk not in {"Crítico", "Alto", "Medio", "Bajo"}:
            raise GeminiAPIError(502, "Gemini devolvió un nivel de riesgo no permitido para un hallazgo.")
        if not isinstance(justification, str) or not justification.strip():
            raise GeminiAPIError(502, "Gemini omitió la justificación de un hallazgo.")
        if not isinstance(techniques, list) or not all(isinstance(value, str) for value in techniques):
            raise GeminiAPIError(502, "Gemini devolvió técnicas MITRE inválidas para un hallazgo.")
        if type(confidence) is not int or not 1 <= confidence <= 5:
            raise GeminiAPIError(502, "La confianza de cada hallazgo debe ser un entero entre 1 y 5.")
        if (
            not isinstance(finding_evidence, list)
            or not finding_evidence
            or not all(isinstance(value, str) for value in finding_evidence)
        ):
            raise GeminiAPIError(502, "Gemini devolvió evidencia inválida para un hallazgo.")

        finding = findings_by_id[finding_id]
        allowed_techniques = set(finding.get("technique_ids", []))
        if not set(techniques) <= allowed_techniques:
            raise GeminiAPIError(502, "Gemini asignó una técnica MITRE que no está asociada al hallazgo.")
        allowed_evidence = set(finding.get("event_ids", [])) & valid_ids
        if not set(finding_evidence) <= allowed_evidence:
            raise GeminiAPIError(502, "Gemini citó evidencia que no pertenece al hallazgo.")
        if not set(finding_evidence) <= set(evidence_ids):
            raise GeminiAPIError(502, "Las citas de cada hallazgo también deben aparecer en evidence_ids.")
        classifications_by_id[finding_id] = {
            "finding_id": finding_id,
            "riesgo": risk,
            "justificacion": justification,
            "tecnica_mitre": list(dict.fromkeys(techniques)),
            "confianza": confidence,
            "evidence_ids": list(dict.fromkeys(finding_evidence)),
            "baseline_technique_ids": list(finding.get("technique_ids", [])),
        }

    missing_findings = set(findings_by_id) - set(classifications_by_id)
    if missing_findings:
        raise GeminiAPIError(502, "Gemini no clasificó todos los hallazgos del incidente.")

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
        "clasificaciones_hallazgos": [
            classifications_by_id[finding_id]
            for finding_id in findings_by_id
        ],
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
Devuelve exactamente una entrada en clasificaciones_hallazgos por cada finding_id del paquete, sin omitir ni duplicar ninguno. Para cada una estima riesgo (Crítico, Alto, Medio o Bajo), justificación breve, confianza entera de 1 a 5, tecnica_mitre usando solo las técnicas ya asociadas al hallazgo y evidence_ids tomados de los event_ids de ese hallazgo. Incluye esas citas en el evidence_ids general. Esta evaluación es asesoramiento IA y no modifica la línea base determinista.
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


def _correlation_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "groups": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "type": {"type": "string", "enum": ["incidente", "aislado"]},
                        "title": {"type": "string"},
                        "finding_ids": {"type": "array", "items": {"type": "string"}},
                        "justificacion": {"type": "string"},
                        "confidence": {"type": "integer"},
                        "evidence_ids": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": [
                        "type",
                        "title",
                        "finding_ids",
                        "justificacion",
                        "confidence",
                        "evidence_ids",
                    ],
                },
            }
        },
        "required": ["groups"],
    }


def _package_correlation(
    findings: list[dict[str, Any]], events: list[dict[str, Any]]
) -> dict[str, Any]:
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
    event_ids = {str(log_id) for finding in findings for log_id in finding.get("event_ids", [])}
    event_fields = (
        "Log_ID",
        "Timestamp",
        "Hostname",
        "Event_ID",
        "User",
        "Source_IP",
        "Destination",
        "Event_Description",
        "Process_CommandLine",
    )
    return {
        "findings": [
            {field: finding.get(field) for field in finding_fields if field in finding}
            for finding in findings
        ],
        "events": [
            {field: event.get(field) for field in event_fields if field in event}
            for event in events
            if str(event.get("Log_ID")) in event_ids
        ],
    }


def validate_correlation_output(
    output_text: str,
    findings: list[dict[str, Any]],
    events: list[dict[str, Any]],
    incidents: list[dict[str, Any]],
    model: str,
) -> dict[str, Any]:
    try:
        result = json.loads(output_text)
    except json.JSONDecodeError as exc:
        raise GeminiAPIError(502, "Gemini devolvió una correlación que no es JSON válido.") from exc
    if not isinstance(result, dict) or not isinstance(result.get("groups"), list):
        raise GeminiAPIError(502, "Gemini devolvió una correlación con formato inesperado.")

    findings_by_id = {str(finding.get("finding_id")): finding for finding in findings}
    if len(findings_by_id) != len(findings):
        raise GeminiAPIError(500, "El análisis contiene finding_id duplicados; no se puede correlacionar.")
    expected_ids = set(findings_by_id)
    events_by_id = {str(event.get("Log_ID")): event for event in events}
    seen_ids: set[str] = set()
    validated_groups = []

    for group in result["groups"]:
        if not isinstance(group, dict):
            raise GeminiAPIError(502, "Gemini devolvió un grupo de hallazgos inválido.")
        group_type = group.get("type")
        title = group.get("title")
        finding_ids = group.get("finding_ids")
        justification = group.get("justificacion")
        confidence = group.get("confidence")
        evidence_ids = group.get("evidence_ids")

        if not isinstance(group_type, str) or group_type not in {"incidente", "aislado"}:
            raise GeminiAPIError(502, "Gemini devolvió un tipo de grupo no permitido.")
        if not isinstance(title, str) or not title.strip():
            raise GeminiAPIError(502, "Gemini omitió el título de un grupo.")
        if not isinstance(finding_ids, list) or not finding_ids or not all(
            isinstance(value, str) for value in finding_ids
        ):
            raise GeminiAPIError(502, "Gemini devolvió finding_ids inválidos para un grupo.")
        if len(set(finding_ids)) != len(finding_ids):
            raise GeminiAPIError(502, "Gemini repitió un hallazgo dentro del mismo grupo.")
        if group_type == "aislado" and len(finding_ids) != 1:
            raise GeminiAPIError(502, "Un grupo aislado debe contener exactamente un hallazgo.")
        if group_type == "incidente" and len(finding_ids) < 2:
            raise GeminiAPIError(502, "Un incidente sugerido debe agrupar al menos dos hallazgos.")
        if not isinstance(justification, str) or not justification.strip():
            raise GeminiAPIError(502, "Gemini omitió la justificación de un grupo.")
        if type(confidence) is not int or not 1 <= confidence <= 5:
            raise GeminiAPIError(502, "La confianza de correlación debe ser un entero entre 1 y 5.")
        if not isinstance(evidence_ids, list) or not evidence_ids or not all(
            isinstance(value, str) for value in evidence_ids
        ):
            raise GeminiAPIError(502, "Gemini devolvió evidencia inválida para un grupo.")

        unknown_ids = set(finding_ids) - expected_ids
        if unknown_ids:
            raise GeminiAPIError(502, "Gemini citó finding_id que no existen en este análisis.")
        duplicate_ids = set(finding_ids) & seen_ids
        if duplicate_ids:
            raise GeminiAPIError(502, "Gemini asignó un hallazgo a más de un grupo.")
        allowed_evidence = {
            str(log_id)
            for finding_id in finding_ids
            for log_id in findings_by_id[finding_id].get("event_ids", [])
        } & set(events_by_id)
        cited_evidence = set(evidence_ids)
        if not cited_evidence <= allowed_evidence:
            raise GeminiAPIError(502, "Gemini citó evidencia que no pertenece a los hallazgos del grupo.")
        if any(
            not cited_evidence & set(findings_by_id[finding_id].get("event_ids", []))
            for finding_id in finding_ids
        ):
            raise GeminiAPIError(502, "La evidencia del grupo debe respaldar cada hallazgo incluido.")

        baseline_ids = [
            incident["incident_id"]
            for incident in incidents
            if set(finding_ids) & set(incident.get("finding_ids", []))
        ]
        group_index = len(validated_groups) + 1
        validated_groups.append(
            {
                "group_id": f"IA-{group_index:02d}",
                "type": group_type,
                "title": title.strip(),
                "finding_ids": list(finding_ids),
                "justificacion": justification.strip(),
                "confidence": confidence,
                "evidence_ids": list(dict.fromkeys(evidence_ids)),
                "baseline_incident_ids": baseline_ids,
            }
        )
        seen_ids.update(finding_ids)

    missing_ids = expected_ids - seen_ids
    if missing_ids:
        raise GeminiAPIError(502, "Gemini omitió hallazgos; la correlación debe cubrirlos todos.")

    return {
        "model": model,
        "groups": validated_groups,
        "finding_count": len(findings_by_id),
        "baseline_incident_count": len(incidents),
    }


def suggest_finding_correlation(
    findings: list[dict[str, Any]],
    events: list[dict[str, Any]],
    incidents: list[dict[str, Any]],
) -> dict[str, Any]:
    finding_ids = [str(finding.get("finding_id")) for finding in findings]
    if len(finding_ids) != len(set(finding_ids)):
        raise GeminiAPIError(
            409,
            "El análisis contiene finding_id duplicados; vuelve a analizar antes de correlacionar.",
        )

    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise GeminiConfigurationError("Gemini no está configurado. Define GEMINI_API_KEY en el entorno del backend.")

    model = os.getenv("GEMINI_MODEL", "gemini-3.6-flash").strip() or "gemini-3.6-flash"
    try:
        configured_timeout = float(os.getenv("GEMINI_TIMEOUT_SECONDS", "60"))
    except ValueError as exc:
        raise GeminiConfigurationError("GEMINI_TIMEOUT_SECONDS debe ser un número.") from exc
    timeout_seconds = max(5.0, min(configured_timeout, 300.0))
    package_json = json.dumps(
        _package_correlation(findings, events), ensure_ascii=False, separators=(",", ":"), default=str
    )
    prompt = f"""Propón una correlación SOC alternativa para los hallazgos del paquete, usando solo sus datos.
Devuelve una partición completa: cada finding_id debe aparecer exactamente una vez en todos los grupos.
Usa type=incidente solo cuando haya evidencia suficiente de una misma actividad o cadena causal; cada incidente sugerido debe agrupar al menos dos hallazgos. Usa type=aislado para cada hallazgo que no puedas relacionar; no lo presentes como incidente.
No unas hallazgos solo por compartir una IP, host o usuario. Considera la secuencia temporal, la relación entre reglas y evidencia concreta. No inventes vínculos, hechos ni IDs.
Cada grupo debe tener título, justificación breve, confianza entera de 1 a 5 y Log_ID pertinentes que pertenezcan a los event_ids de sus hallazgos. La salida es una sugerencia: no confirma actividad maliciosa ni modifica la correlación determinista.

Paquete del análisis:
{package_json}"""
    request_payload = {
        "model": model,
        "input": prompt,
        "response_format": {
            "type": "text",
            "mime_type": "application/json",
            "schema": _correlation_schema(),
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
        raise GeminiAPIError(502, "Gemini no devolvió texto para la correlación.")
    return validate_correlation_output(output_text, findings, events, incidents, model)
