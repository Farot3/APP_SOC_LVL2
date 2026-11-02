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

export interface GeminiInterpretation {
  incident_id: string;
  model: string;
  conclusion: "sospechoso" | "no_suficiente";
  evidence_ids: string[];
  origenes: GeminiOriginAnalysis[];
  comprobaciones_recomendadas: GeminiRecommendedCheck[];
  explicacion: string;
  limitacion: string;
  baseline_risk_level: string | null;
  cache_hit: boolean;
}

export interface UploadResult {
  filename: string;
  event_count: number;
  columns: string[];
  warnings: string[];
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
