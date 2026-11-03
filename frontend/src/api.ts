export interface GeminiStatus {
  enabled: boolean;
  model: string;
}

export interface GeminiOriginAnalysis {
  ip: string;
  analisis: string;
  evidence_ids: string[];
}

export interface GeminiRecommendedCheck {
  comprobacion: string;
  evidence_ids: string[];
}

export interface GeminiFindingClassification {
  finding_id: string;
  riesgo: "Crítico" | "Alto" | "Medio" | "Bajo";
  justificacion: string;
  tecnica_mitre: string[];
  confianza: number;
  evidence_ids: string[];
  baseline_technique_ids: string[];
}

export interface GeminiInterpretation {
  incident_id: string;
  model: string;
  conclusion: "sospechoso" | "no_suficiente";
  evidence_ids: string[];
  clasificaciones_hallazgos: GeminiFindingClassification[];
  origenes: GeminiOriginAnalysis[];
  comprobaciones_recomendadas: GeminiRecommendedCheck[];
  explicacion: string;
  limitacion: string;
  baseline_risk_level: string | null;
  cache_hit: boolean;
}

export interface GeminiCorrelationGroup {
  group_id: string;
  type: "incidente" | "aislado";
  title: string;
  finding_ids: string[];
  justificacion: string;
  confidence: number;
  evidence_ids: string[];
  baseline_incident_ids: string[];
}

export interface GeminiCorrelation {
  model: string;
  groups: GeminiCorrelationGroup[];
  finding_count: number;
  baseline_incident_count: number;
  cache_hit: boolean;
}

export interface GeminiReportBaseline {
  event_count: number;
  finding_count: number;
  incident_count: number;
  risk_by_incident: { incident_id: string; level: string | null; score: number | null }[];
}

export interface GeminiExecutiveReport {
  report_type: "executive";
  model: string;
  summary: string;
  key_points: {
    heading: string;
    detail: string;
    finding_ids: string[];
    evidence_ids: string[];
  }[];
  recommended_actions: {
    priority: "Alta" | "Media" | "Baja";
    action: string;
    finding_ids: string[];
    evidence_ids: string[];
  }[];
  limitations: string;
  baseline: GeminiReportBaseline;
  cache_hit: boolean;
}

export interface GeminiTechnicalReport {
  report_type: "technical";
  model: string;
  summary: string;
  incident_details: {
    incident_id: string;
    technical_summary: string;
    finding_ids: string[];
    technique_ids: string[];
    evidence_ids: string[];
  }[];
  informational_findings: {
    finding_id: string;
    summary: string;
    evidence_ids: string[];
  }[];
  limitations: string;
  baseline: GeminiReportBaseline;
  cache_hit: boolean;
}

export type GeminiAnalysisReport = GeminiExecutiveReport | GeminiTechnicalReport;

export type CanonicalEventField =
  | "Log_ID"
  | "Timestamp"
  | "Hostname"
  | "Event_ID"
  | "User"
  | "Source_IP"
  | "Destination"
  | "Log_Source"
  | "Event_Description"
  | "Process_CommandLine"
  | "Result"
  | "Severity";

export interface WorkbookPreview {
  sheet_names: string[];
  sheet_name: string;
  header_row: number;
  columns: string[];
  suggested_mapping: Record<CanonicalEventField, string | null>;
  required_columns: CanonicalEventField[];
  missing_required_columns: CanonicalEventField[];
}

export interface ColumnMappingSuggestion {
  model: string;
  mapping: Record<CanonicalEventField, string | null>;
  required_columns: CanonicalEventField[];
}

export interface UploadResult {
  filename: string;
  event_count: number;
  columns: string[];
  warnings: string[];
  source_sheet?: string;
  header_row?: number;
}

export interface EventRecord {
  Log_ID: string;
  Timestamp: string;
  Hostname: string;
  Event_ID: string | number;
  User: string;
  Source_IP: string;
  Destination: string | null;
  Log_Source: string;
  Event_Description: string;
  Process_CommandLine: string | null;
  Result: string | number;
  Severity: string;
  result_class?: string;
  http_status?: number | null;
  ip_scope?: string;
}

export interface RiskScore {
  impact: number;
  confidence: number;
  score: number;
  level: "Crítico" | "Alto" | "Medio" | "Bajo" | string;
  impact_rationale: string;
  confidence_rationale: string;
}

export interface Finding {
  finding_id: string;
  rule_id: string;
  name: string;
  explanation: string;
  technique_ids: string[];
  event_ids: string[];
  first_seen: string | null;
  last_seen: string | null;
  entities: Record<string, string[]>;
}

export interface Incident {
  incident_id: string;
  title: string;
  rule_ids: string[];
  technique_ids: string[];
  entities: {
    users: string[];
    source_ips: string[];
    hosts: string[];
    destinations: string[];
  };
  finding_ids: string[];
  findings: Finding[];
  event_ids: string[];
  events: EventRecord[];
  risk: RiskScore;
}

export interface EventPage {
  total: number;
  page: number;
  page_size: number;
  items: EventRecord[];
}

export interface IncidentList {
  total: number;
  items: Incident[];
}

export interface Dashboard {
  loaded: boolean;
  analysis_ready: boolean;
  event_count: number;
  finding_count: number;
  incident_count: number;
  events_by_log_source: CounterItem[];
  events_by_siem_severity: CounterItem[];
  top_hosts: CounterItem[];
  top_users: CounterItem[];
  top_source_ips: CounterItem[];
  findings_by_rule: CounterItem[];
  incidents_by_risk: { level: string; count: number }[];
  attack_tactics: { id: string; name: string; count: number }[];
  attack_techniques: CounterItem[];
  risk_matrix: {
    incident_id: string;
    impact: number;
    confidence: number;
    score: number;
    level: string;
  }[];
  events_by_hour: { hour: string; count: number }[];
}

export interface CounterItem {
  name: string;
  count: number;
}

export interface AnalysisResult {
  event_count: number;
  finding_count: number;
  findings_by_rule: Record<string, number>;
  incident_count: number;
  incidents: Incident[];
  informational_finding_count: number;
  findings: Finding[];
  hypotheses: {
    type: string;
    incident_ids: string[];
    ip_pairs: string[][];
    status: string;
    explanation: string;
  }[];
}

export async function apiRequest<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, init);
  } catch {
    throw new Error("No se pudo conectar con la API. Comprueba que FastAPI esté ejecutándose en el puerto 8000.");
  }

  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    const detail = payload?.detail;
    const message = Array.isArray(detail)
      ? detail.map((item: { msg?: string }) => item.msg ?? "Error de validación").join("; ")
      : typeof detail === "string"
        ? detail
        : `La API respondió con el estado ${response.status}.`;
    throw new Error(message);
  }
  return payload as T;
}
