import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import {
  apiRequest,
  type AnalysisResult,
  type Dashboard,
  type EventPage,
  type EventRecord,
  type GeminiInterpretation,
  type GeminiStatus,
  type Incident,
  type IncidentList,
  type UploadResult,
} from "./api";

type Section = "dashboard" | "incidents" | "events";
type EventFilters = {
  host: string;
  user: string;
  source_ip: string;
  event_id: string;
  start_time: string;
  end_time: string;
};

const PAGE_SIZE = 25;
const EMPTY_FILTERS: EventFilters = {
  host: "",
  user: "",
  source_ip: "",
  event_id: "",
  start_time: "",
  end_time: "",
};

function displayTime(value: string | null | undefined): string {
  return value ? value.replace("T", " ") : "—";
}

function RiskBadge({ level }: { level: string }) {
  const className = level.toLocaleLowerCase("es").replaceAll("í", "i").replaceAll("ó", "o");
  return <span className={`risk-badge risk-${className}`}>{level}</span>;
}

function MetricCard({ label, value, hint }: { label: string; value: string | number; hint?: string }) {
  return (
    <article className="metric-card">
      <span className="metric-label">{label}</span>
      <strong>{value}</strong>
      {hint && <span className="metric-hint">{hint}</span>}
    </article>
  );
}

function BarList({ items, empty = "Sin datos" }: { items: { name: string; count: number }[]; empty?: string }) {
  const max = Math.max(1, ...items.map((item) => item.count));
  if (!items.length) return <p className="empty-copy">{empty}</p>;
  return (
    <div className="bar-list">
      {items.map((item) => (
        <div className="bar-row" key={item.name}>
          <div className="bar-label-line">
            <span title={item.name}>{item.name}</span>
            <strong>{item.count}</strong>
          </div>
          <div className="bar-track">
            <span style={{ width: `${Math.max(3, (item.count / max) * 100)}%` }} />
          </div>
        </div>
      ))}
    </div>
  );
}

function Panel({ title, action, children }: { title: string; action?: ReactNode; children: ReactNode }) {
  return (
    <section className="panel">
      <div className="panel-heading">
        <h2>{title}</h2>
        {action}
      </div>
      {children}
    </section>
  );
}

function App() {

  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [upload, setUpload] = useState<UploadResult | null>(null);
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [incidentList, setIncidentList] = useState<Incident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [section, setSection] = useState<Section>("dashboard");
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState<"upload" | "analysis" | "incident" | null>(null);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [eventPage, setEventPage] = useState<EventPage | null>(null);
  const [page, setPage] = useState(1);
  const [filterDraft, setFilterDraft] = useState<EventFilters>(EMPTY_FILTERS);
  const [activeFilters, setActiveFilters] = useState<EventFilters>(EMPTY_FILTERS);
  const [riskFilter, setRiskFilter] = useState("");
  const [geminiStatus, setGeminiStatus] = useState<GeminiStatus | null>(null);
  const [geminiLoading, setGeminiLoading] = useState(true);
  const [geminiBusy, setGeminiBusy] = useState(false);
  const [geminiResult, setGeminiResult] = useState<GeminiInterpretation | null>(null);
  const [geminiError, setGeminiError] = useState("");

  useEffect(() => {
    apiRequest<GeminiStatus>("/api/ai/status")
      .then(setGeminiStatus)
      .catch(() => setGeminiStatus(null))
      .finally(() => setGeminiLoading(false));
  }, []);

  async function loadEvents(nextPage: number, filters: EventFilters = activeFilters) {
    setEventsLoading(true);
    setError("");
    try {
      const params = new URLSearchParams({ page: String(nextPage), page_size: String(PAGE_SIZE) });
      Object.entries(filters).forEach(([key, value]) => {
        if (value.trim()) params.set(key, value.trim());
      });
      const response = await apiRequest<EventPage>(`/api/events?${params.toString()}`);
      setEventPage(response);
      setPage(nextPage);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "No se pudieron cargar los eventos.");
    } finally {
      setEventsLoading(false);
    }
  }

  async function uploadWorkbook(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedFile) {
      setError("Selecciona un archivo .xlsx antes de continuar.");
      return;
    }

    setBusy("upload");
    setError("");
    setNotice("");
    try {
      const form = new FormData();
      form.append("file", selectedFile);
      const result = await apiRequest<UploadResult>("/api/upload", { method: "POST", body: form });
      setUpload(result);
      setAnalysis(null);
      setDashboard(null);
      setIncidentList([]);
      setSelectedIncident(null);
      setGeminiResult(null);
      setGeminiError("");
      setRiskFilter("");
      setActiveFilters(EMPTY_FILTERS);
      setFilterDraft(EMPTY_FILTERS);
      setNotice(`Se cargaron ${result.event_count} eventos. Ya puedes ejecutar el análisis.`);
      await loadEvents(1, EMPTY_FILTERS);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "No se pudo cargar el Excel.");
    } finally {
      setBusy(null);
    }
  }

  async function analyzeWorkbook() {
    setBusy("analysis");
    setError("");
    setNotice("");
    try {
      const result = await apiRequest<AnalysisResult>("/api/analyze", { method: "POST" });
      const [dashboardResult, incidentsResult] = await Promise.all([
        apiRequest<Dashboard>("/api/dashboard"),
        apiRequest<IncidentList>("/api/incidents"),
      ]);
      setAnalysis(result);
      setDashboard(dashboardResult);
      setIncidentList(incidentsResult.items);
      setSelectedIncident(null);
      setGeminiResult(null);
      setGeminiError("");
      setSection("dashboard");
      setNotice(`Análisis terminado: ${result.incident_count} incidentes y ${result.finding_count} hallazgos de reglas.`);
      await loadEvents(1, activeFilters);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "No se pudo completar el análisis.");
    } finally {
      setBusy(null);
    }
  }

  async function applyEventFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setActiveFilters(filterDraft);
    await loadEvents(1, filterDraft);
  }

  async function clearEventFilters() {
    setFilterDraft(EMPTY_FILTERS);
    setActiveFilters(EMPTY_FILTERS);
    await loadEvents(1, EMPTY_FILTERS);
  }

  async function loadIncidentsByRisk(level: string) {
    setRiskFilter(level);
    setError("");
    try {
      const params = new URLSearchParams();
      if (level) params.set("risk_level", level);
      const suffix = params.size ? `?${params.toString()}` : "";
      const result = await apiRequest<IncidentList>(`/api/incidents${suffix}`);
      setIncidentList(result.items);
      setSelectedIncident(null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "No se pudieron filtrar los incidentes.");
    }
  }

  async function openIncident(incidentId: string) {
    setBusy("incident");
    setError("");
    try {
      const result = await apiRequest<Incident>(`/api/incidents/${encodeURIComponent(incidentId)}`);
      setSelectedIncident(result);
      setGeminiResult(null);
      setGeminiError("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "No se pudo cargar el incidente.");
    } finally {
      setBusy(null);
    }
  }

  async function interpretSelectedIncident() {
    if (!selectedIncident || !geminiStatus?.enabled) return;
    setGeminiBusy(true);
    setGeminiError("");
    setGeminiResult(null);
    try {
      const result = await apiRequest<GeminiInterpretation>(
        `/api/incidents/${encodeURIComponent(selectedIncident.incident_id)}/interpret`,
        { method: "POST" },
      );
      setGeminiResult(result);
    } catch (caught) {
      setGeminiError(caught instanceof Error ? caught.message : "No se pudo interpretar el incidente con Gemini.");
    } finally {
      setGeminiBusy(false);
    }
  }

  function setFilter<K extends keyof EventFilters>(key: K, value: EventFilters[K]) {
    setFilterDraft((current) => ({ ...current, [key]: value }));
  }

  return (
    <div className="app-shell">
      <header className="topbar" style={{ textAlign: "center" }}>
        <div className="brand-lockup">
          <div>
            <p className="eyebrow" style={{ textAlign: "center" }}>ANÁLISIS DE SEGURIDAD</p>
            <h1>SOC L2 Incident Analyzer</h1>
          </div>
        </div>
      </header>

      <main className="main-content">
        <section className="upload-panel">
          <div className="upload-copy">
            <span className="section-kicker">FLUJO DE ANÁLISIS</span>
            <h2>{upload ? "Archivo listo para analizar" : "Carga los registros del SIEM"}</h2>
            <p>Los hallazgos se basan en los eventos del Excel.</p>
          </div>
          <form className="upload-form" onSubmit={uploadWorkbook}>
            <label className="file-picker">
              <span className="file-picker-icon" aria-hidden="true">＋</span>
              <span>{selectedFile?.name ?? upload?.filename ?? "Seleccionar archivo .xlsx"}</span>
              <input
                type="file"
                accept=".xlsx,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                onChange={(event) => setSelectedFile(event.target.files?.[0] ?? null)}
              />
            </label>
            <button className="button button-secondary" type="submit" disabled={!selectedFile || busy !== null || geminiBusy}>
              {busy === "upload" ? "Cargando…" : "Cargar Excel"}
            </button>
            <button className="button button-primary" type="button" onClick={analyzeWorkbook} disabled={!upload || busy !== null || geminiBusy}>
              {busy === "analysis" ? "Analizando…" : analysis ? "Volver a analizar" : "Analizar archivo"}
            </button>
          </form>
        </section>

        {upload && (
          <aside className="quality-panel" aria-labelledby="quality-title">
            <div className="quality-heading">
              <h2 id="quality-title">Resumen de carga</h2>
            </div>
            <div className="quality-metrics">
              <div className="quality-metric">
                <strong>{upload.event_count.toLocaleString("es-ES")}</strong>
                <span>Eventos cargados</span>
              </div>
              <div className="quality-metric">
                <strong>{upload.columns.length}</strong>
                <span>Columnas detectadas</span>
              </div>
              <div className="quality-metric">
                <strong>{upload.warnings.length}</strong>
                <span>Observaciones de calidad</span>
              </div>
            </div>
          </aside>
        )}

        {error && <div className="alert alert-error" role="alert">{error}</div>}
        {notice && !error && <div className="alert alert-success" role="status">{notice}</div>}

        {!upload && (
          <section className="empty-state welcome-state">
            <div className="empty-icon" aria-hidden="true">↥</div>
            <h2>Empieza con un archivo SIEM</h2>
            <p>Selecciona el Excel del reto. Después podrás revisar las métricas, los incidentes y los eventos que sustentan cada hallazgo.</p>
          </section>
        )}

        {upload && (
          <section className="analysis-workspace" aria-label="Secciones de análisis">
            <nav className="section-nav">
              {([
                ["dashboard", "Resumen"],
                ["incidents", "Incidentes", analysis?.incident_count],
                ["events", "Eventos", upload.event_count],
              ] as [Section, string, number?][]).map(([key, label, count]) => (
                <button
                  className={`nav-tab ${section === key ? "active" : ""}`}
                  key={key}
                  onClick={() => setSection(key)}
                  type="button"
                >
                  {label}{count !== undefined && <span className="tab-count">{count}</span>}
                </button>
              ))}
            </nav>

            <div className="tab-content">
              {section === "dashboard" && (
                <DashboardView dashboard={dashboard} analysis={analysis} onOpenIncidents={() => setSection("incidents")} />
              )}

              {section === "incidents" && (
                <section className="content-grid incident-layout">
                  <Panel
                    title="Incidentes detectados"
                    action={
                      <select aria-label="Filtrar incidentes por criticidad" value={riskFilter} disabled={!analysis || geminiBusy} onChange={(event) => void loadIncidentsByRisk(event.target.value)}>
                        <option value="">Todas las criticidades</option>
                        <option value="Crítico">Crítico</option>
                        <option value="Alto">Alto</option>
                        <option value="Medio">Medio</option>
                        <option value="Bajo">Bajo</option>
                      </select>
                    }
                  >
                    {!analysis ? (
                      <p className="empty-copy">Carga el archivo y ejecuta el análisis para ver incidentes.</p>
                    ) : incidentList.length ? (
                      <div className="incident-list">
                        {incidentList.map((incident) => (
                          <button
                            className={`incident-row ${selectedIncident?.incident_id === incident.incident_id ? "selected" : ""}`}
                            disabled={geminiBusy}
                            key={incident.incident_id}
                            onClick={() => void openIncident(incident.incident_id)}
                            type="button"
                          >
                            <div className="incident-row-top">
                              <span className="incident-id">{incident.incident_id}</span>
                              <RiskBadge level={incident.risk.level} />
                            </div>
                            <strong>{incident.title}</strong>
                            <span className="incident-row-meta">{incident.entities.hosts.join(" · ") || "Host no especificado"}</span>
                            <span className="incident-row-meta">Puntaje {incident.risk.score} · {incident.rule_ids.join(", ")}</span>
                          </button>
                        ))}
                      </div>
                    ) : (
                      <p className="empty-copy">No hay incidentes para este filtro.</p>
                    )}
                  </Panel>

                  <Panel title={selectedIncident ? `${selectedIncident.incident_id} · Detalle` : "Detalle del incidente"}>
                    {busy === "incident" && <p className="empty-copy">Cargando evidencia…</p>}
                    {!selectedIncident && busy !== "incident" && <p className="empty-copy">Selecciona un incidente para revisar su evidencia y cronología.</p>}
                    {selectedIncident && (
                      <IncidentDetail
                        incident={selectedIncident}
                        geminiStatus={geminiStatus}
                        geminiLoading={geminiLoading}
                        geminiBusy={geminiBusy}
                        geminiResult={geminiResult}
                        geminiError={geminiError}
                        onInterpret={() => void interpretSelectedIncident()}
                        onPrintReport={() => window.print()}
                      />
                    )}
                  </Panel>
                </section>
              )}

              {section === "events" && (
                <EventsView
                  eventPage={eventPage}
                  page={page}
                  loading={eventsLoading}
                  filterDraft={filterDraft}
                  setFilter={setFilter}
                  onSubmit={applyEventFilters}
                  onClear={clearEventFilters}
                  onPage={(nextPage) => void loadEvents(nextPage)}
                />
              )}
            </div>
          </section>
        )}

        <footer className="page-footer">
          <span>Reglas y riesgo locales · Gemini opcional bajo demanda</span>
          <span>{upload?.filename ?? "Sin archivo cargado"}</span>
        </footer>
      </main>
      {selectedIncident && (
        <PrintableIncidentReport
          incident={selectedIncident}
          sourceFilename={upload?.filename ?? "Archivo no disponible"}
          geminiResult={geminiResult?.incident_id === selectedIncident.incident_id ? geminiResult : null}
        />
      )}
    </div>
  );
}

function DashboardView({
  dashboard,
  analysis,
  onOpenIncidents,
}: {
  dashboard: Dashboard | null;
  analysis: AnalysisResult | null;
  onOpenIncidents: () => void;
}) {
  if (!dashboard?.analysis_ready || !analysis) {
    return (
      <section className="empty-state">
        <div className="empty-icon" aria-hidden="true">▦</div>
        <h2>El resumen aparecerá después del análisis</h2>
        <p>La carga está lista. Ejecuta el análisis para calcular las reglas, correlacionar los incidentes y construir el dashboard.</p>
      </section>
    );
  }

  const maxHour = Math.max(1, ...dashboard.events_by_hour.map((item) => item.count));
  return (
    <div className="dashboard-stack">
      <div className="section-title-row">
        <div>
          <span className="section-kicker">VISTA GENERAL</span>
          <h2>Resumen del análisis</h2>
        </div>
        <button className="button button-secondary" onClick={onOpenIncidents} type="button">Ver incidentes →</button>
      </div>

      <div className="metrics-grid">
        <MetricCard label="Eventos procesados" value={dashboard.event_count.toLocaleString("es-ES")} hint="Registros del Excel" />
        <MetricCard label="Hallazgos de reglas" value={dashboard.finding_count} hint="Incluye coincidencias informativas" />
        <MetricCard label="Incidentes" value={dashboard.incident_count} hint="Correlacionados con evidencia" />
        <MetricCard label="Hipótesis" value={analysis.hypotheses.length} hint="Vínculos no confirmados" />
      </div>

      <div className="content-grid dashboard-grid">
        <Panel title="Incidentes por criticidad">
          <div className="risk-summary-list">
            {dashboard.incidents_by_risk.map((item) => (
              <div className="risk-summary-row" key={item.level}>
                <RiskBadge level={item.level} />
                <div className="risk-summary-track"><span className={`risk-fill risk-fill-${item.level.toLocaleLowerCase("es").replaceAll("í", "i").replaceAll("ó", "o")}`} style={{ width: `${Math.max(0, (item.count / Math.max(1, dashboard.incident_count)) * 100)}%` }} /></div>
                <strong>{item.count}</strong>
              </div>
            ))}
          </div>
          <button className="text-button" onClick={onOpenIncidents} type="button">Abrir lista de incidentes →</button>
        </Panel>
        <Panel title="Eventos por hora">
          <div className="hourly-chart">
            {dashboard.events_by_hour.map((item) => (
              <div className="hour-column" key={item.hour} title={`${displayTime(item.hour)} · ${item.count} eventos`}>
                <span className="hour-value">{item.count}</span>
                <div className="hour-bar-track"><span style={{ height: `${Math.max(5, (item.count / maxHour) * 100)}%` }} /></div>
                <span className="hour-label">{item.hour.slice(11, 13)}h</span>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      <div className="content-grid dashboard-grid">
        <Panel title="Tácticas ATT&CK">
          <div className="tag-cloud">
            {dashboard.attack_tactics.map((tactic) => (
              <span className="tactic-tag" key={tactic.id}>{tactic.name}<strong>{tactic.count}</strong></span>
            ))}
          </div>
        </Panel>
        <Panel title="Fuentes de registro">
          <BarList items={dashboard.events_by_log_source} />
        </Panel>
      </div>

      <Panel title="Matriz de riesgo · impacto × confianza">
        <div className="risk-matrix-list">
          {dashboard.risk_matrix.map((item) => (
            <button className="risk-matrix-row" key={item.incident_id} onClick={onOpenIncidents} type="button">
              <span className="incident-id">{item.incident_id}</span>
              <span className="matrix-axis">Impacto <strong>{item.impact}</strong></span>
              <span className="matrix-axis">Confianza <strong>{item.confidence}</strong></span>
              <span className="matrix-score">{item.score}</span>
              <RiskBadge level={item.level} />
            </button>
          ))}
        </div>
      </Panel>

      {analysis.hypotheses.length > 0 && (
        <Panel title="Hipótesis por validar">
          <div className="hypothesis-list">
            {analysis.hypotheses.map((hypothesis) => (
              <article className="hypothesis-row" key={`${hypothesis.incident_ids.join("-")}-${hypothesis.ip_pairs.flat().join("-")}`}>
                <div><strong>{hypothesis.incident_ids.join(" ↔ ")}</strong><span>{hypothesis.ip_pairs.map((pair) => pair.join(" ↔ ")).join(" · ")}</span></div>
                <p>{hypothesis.explanation}</p>
              </article>
            ))}
          </div>
        </Panel>
      )}
    </div>
  );
}

function EventsView({
  eventPage,
  page,
  loading,
  filterDraft,
  setFilter,
  onSubmit,
  onClear,
  onPage,
}: {
  eventPage: EventPage | null;
  page: number;
  loading: boolean;
  filterDraft: EventFilters;
  setFilter: <K extends keyof EventFilters>(key: K, value: EventFilters[K]) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  onClear: () => void;
  onPage: (page: number) => void;
}) {
  return (
    <div className="dashboard-stack">
      <div className="section-title-row">
        <div><span className="section-kicker">EVIDENCIA ORIGINAL</span><h2>Eventos del SIEM</h2></div>
        <span className="result-count">{eventPage?.total.toLocaleString("es-ES") ?? 0} eventos</span>
      </div>
      <Panel title="Filtros">
        <form className="filter-form" onSubmit={onSubmit}>
          <label>Host<input value={filterDraft.host} onChange={(event) => setFilter("host", event.target.value)} placeholder="WEB-01" /></label>
          <label>Usuario<input value={filterDraft.user} onChange={(event) => setFilter("user", event.target.value)} placeholder="CORP\\admin" /></label>
          <label>IP origen<input value={filterDraft.source_ip} onChange={(event) => setFilter("source_ip", event.target.value)} placeholder="192.0.2.91" /></label>
          <label>Event_ID<input value={filterDraft.event_id} onChange={(event) => setFilter("event_id", event.target.value)} placeholder="4625" /></label>
          <label>Desde<input type="datetime-local" value={filterDraft.start_time} onChange={(event) => setFilter("start_time", event.target.value)} /></label>
          <label>Hasta<input type="datetime-local" value={filterDraft.end_time} onChange={(event) => setFilter("end_time", event.target.value)} /></label>
          <div className="filter-actions">
            <button className="button button-primary" type="submit">Aplicar filtros</button>
            <button className="button button-quiet" type="button" onClick={onClear}>Limpiar</button>
          </div>
        </form>
      </Panel>
      <Panel title="Registros" action={<span className="muted-copy">Página {page} · {PAGE_SIZE} por página</span>}>
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr><th>Log_ID</th><th>Timestamp</th><th>Host</th><th>Event_ID</th><th>Usuario</th><th>IP origen</th><th>Descripción</th><th>Severidad SIEM</th></tr>
            </thead>
            <tbody>
              {eventPage?.items.map((event) => <EventRow event={event} key={event.Log_ID} />)}
            </tbody>
          </table>
          {loading && <div className="table-overlay">Cargando eventos…</div>}
          {!loading && !eventPage?.items.length && <p className="empty-copy table-empty">No hay eventos que coincidan con los filtros.</p>}
        </div>
        <div className="pagination-row">
          <span className="muted-copy">{eventPage?.total ?? 0} resultados</span>
          <div>
            <button className="button button-quiet" disabled={page <= 1 || loading} onClick={() => onPage(page - 1)} type="button">← Anterior</button>
            <button className="button button-quiet" disabled={!eventPage || page * PAGE_SIZE >= eventPage.total || loading} onClick={() => onPage(page + 1)} type="button">Siguiente →</button>
          </div>
        </div>
      </Panel>
    </div>
  );
}

function EventRow({ event }: { event: EventRecord }) {
  return (
    <tr>
      <td className="log-id">{event.Log_ID}</td>
      <td className="timestamp-cell">{displayTime(event.Timestamp)}</td>
      <td>{event.Hostname}</td>
      <td><code>{event.Event_ID}</code></td>
      <td>{event.User}</td>
      <td><code>{event.Source_IP}</code></td>
      <td className="description-cell" title={event.Event_Description}>{event.Event_Description}</td>
      <td><span className="severity-label">{event.Severity}</span></td>
    </tr>
  );
}

function IncidentDetail({
  incident,
  geminiStatus,
  geminiLoading,
  geminiBusy,
  geminiResult,
  geminiError,
  onInterpret,
  onPrintReport,
}: {
  incident: Incident;
  geminiStatus: GeminiStatus | null;
  geminiLoading: boolean;
  geminiBusy: boolean;
  geminiResult: GeminiInterpretation | null;
  geminiError: string;
  onInterpret: () => void;
  onPrintReport: () => void;
}) {
  const citedEvents = new Map(incident.events.map((event) => [event.Log_ID, event]));
  const citedLogIds = new Set(
    geminiResult?.incident_id === incident.incident_id ? geminiResult.evidence_ids : [],
  );
  return (
    <div className="incident-detail">
      <div className="detail-title-row"><h3>{incident.title}</h3><RiskBadge level={incident.risk.level} /></div>
      <div className="report-actions">
        <button className="button button-secondary" onClick={onPrintReport} type="button">Imprimir / Guardar informe PDF</button>
      </div>
      <div className="detail-score-grid">
        <span>Puntaje<strong>{incident.risk.score}</strong></span>
        <span>Impacto<strong>{incident.risk.impact}/5</strong></span>
        <span>Confianza<strong>{incident.risk.confidence}/5</strong></span>
      </div>
      <p className="rationale"><strong>Impacto:</strong> {incident.risk.impact_rationale}</p>
      <p className="rationale"><strong>Confianza:</strong> {incident.risk.confidence_rationale}</p>
      <div className="detail-block"><span className="detail-label">Reglas</span><div className="tag-cloud">{incident.rule_ids.map((rule) => <span className="rule-tag" key={rule}>{rule}</span>)}</div></div>
      <div className="detail-block"><span className="detail-label">Técnicas ATT&CK</span><div className="tag-cloud">{incident.technique_ids.map((technique) => <span className="technique-tag" key={technique}>{technique}</span>)}</div></div>
      <div className="detail-block"><span className="detail-label">Entidades</span><div className="entity-list">
        {incident.entities.users.map((value) => <span key={`user-${value}`}>Usuario · {value}</span>)}
        {incident.entities.hosts.map((value) => <span key={`host-${value}`}>Host · {value}</span>)}
        {incident.entities.source_ips.map((value) => <span key={`ip-${value}`}>IP · {value}</span>)}
      </div></div>
      <section className="gemini-panel" aria-labelledby="gemini-title">
        <div className="gemini-heading">
          <div>
            <span className="detail-label">Interpretación opcional</span>
            <h4 id="gemini-title">{geminiStatus?.model ?? "Gemini"}</h4>
          </div>
          <span className={`gemini-status ${geminiStatus?.enabled ? "is-enabled" : ""}`}>
            {geminiLoading ? "Comprobando…" : geminiStatus?.enabled ? "Disponible" : "No configurado"}
          </span>
        </div>
        <p className="gemini-privacy">
          La primera interpretación envía a Google los hallazgos y eventos de este incidente. Si ya está guardada,
          consultarla de nuevo no genera otra llamada. La clave permanece en el backend; las reglas y el riesgo deterministas no cambian.
        </p>
        <button
          className="button button-primary"
          type="button"
          onClick={onInterpret}
          disabled={!geminiStatus?.enabled || geminiLoading || geminiBusy}
        >
          {geminiBusy ? "Interpretando con Gemini…" : geminiResult ? "Consultar interpretación guardada" : "Interpretar con Gemini"}
        </button>
        {!geminiLoading && !geminiStatus?.enabled && (
          <p className="muted-copy">Configura GEMINI_API_KEY en el entorno donde se inicia FastAPI para habilitar esta función.</p>
        )}
        {geminiError && <p className="gemini-error" role="alert">{geminiError}</p>}
        {geminiResult && (
          <div className="gemini-result" aria-live="polite">
            <p className="gemini-cache-note">
              {geminiResult.cache_hit
                ? "Se recuperó la interpretación guardada; no se hizo otra llamada a Gemini."
                : "Interpretación guardada en memoria; volver a consultarla no hará otra llamada a Gemini."}
            </p>
            <div className="gemini-result-heading">
              <strong>Conclusión: {geminiResult.conclusion.replace("_", " ")}</strong>
              <span>{geminiResult.model}</span>
            </div>
            <div className="gemini-finding-classifications">
              <span className="detail-label">Clasificación IA por hallazgo</span>
              <p className="muted-copy">Evaluación asistida por IA; no reemplaza el riesgo determinista del incidente ({incident.risk.level}, puntaje {incident.risk.score}).</p>
              {geminiResult.clasificaciones_hallazgos.length ? (
                <div className="gemini-finding-list">
                  {geminiResult.clasificaciones_hallazgos.map((classification) => {
                    const finding = incident.findings.find((item) => item.finding_id === classification.finding_id);
                    return (
                      <article className="gemini-finding-item" key={classification.finding_id}>
                        <div className="gemini-finding-heading">
                          <strong>{classification.finding_id}{finding ? ` · ${finding.name}` : ""}</strong>
                          <RiskBadge level={classification.riesgo} />
                        </div>
                        <p>{classification.justificacion}</p>
                        <span className="muted-copy">Confianza IA: {classification.confianza}/5 · Técnicas MITRE sugeridas: {classification.tecnica_mitre.join(", ") || "ninguna"}</span>
                        <span className="muted-copy">Evidencia: {classification.evidence_ids.map((id) => `${id}${citedEvents.get(id) ? ` · ${citedEvents.get(id)?.Event_Description}` : ""}`).join("; ")}</span>
                      </article>
                    );
                  })}
                </div>
              ) : <p className="muted-copy">Este incidente no contiene hallazgos para clasificar.</p>}
            </div>
            <p><strong>Explicación:</strong> {geminiResult.explicacion}</p>
            <p><strong>Limitación:</strong> {geminiResult.limitacion}</p>
            <div>
              <span className="detail-label">Evidencia citada</span>
              {geminiResult.evidence_ids.length ? (
                <ul className="gemini-evidence-list">
                  {geminiResult.evidence_ids.map((id) => (
                    <li key={id}>
                      <code>{id}</code>
                      <span>{citedEvents.get(id)?.Event_Description ?? "ID validado para este incidente"}</span>
                    </li>
                  ))}
                </ul>
              ) : <p className="muted-copy">Gemini no citó Log_ID para esta conclusión.</p>}
            </div>
            <div className="gemini-origin-analysis">
              <span className="detail-label">Análisis de IP de origen</span>
              {geminiResult.origenes.length ? (
                <ul className="gemini-origin-list">
                  {geminiResult.origenes.map((origin) => (
                    <li key={origin.ip}>
                      <code>{origin.ip}</code>
                      <p>{origin.analisis}</p>
                      <span className="muted-copy">
                        Evidencia: {origin.evidence_ids.map((id) => `${id}${citedEvents.get(id) ? ` · ${citedEvents.get(id)?.Event_Description}` : ""}`).join("; ")}
                      </span>
                    </li>
                  ))}
                </ul>
              ) : <p className="muted-copy">No se identificaron IP de origen pertinentes en estos eventos.</p>}
              <p className="gemini-origin-caveat">Basado solo en los registros del incidente; no consulta reputación, geolocalización ni titularidad de las IP.</p>
            </div>
            <div className="gemini-recommendations">
              <span className="detail-label">Comprobaciones sugeridas para el analista</span>
              {geminiResult.comprobaciones_recomendadas.length ? (
                <ol>
                  {geminiResult.comprobaciones_recomendadas.map((item, index) => (
                    <li key={`${index}-${item.comprobacion}`}>
                      <p>{item.comprobacion}</p>
                      <span className="muted-copy">
                        Evidencia: {item.evidence_ids.map((id) => `${id}${citedEvents.get(id) ? ` · ${citedEvents.get(id)?.Event_Description}` : ""}`).join("; ")}
                      </span>
                    </li>
                  ))}
                </ol>
              ) : <p className="muted-copy">No se sugirieron comprobaciones adicionales.</p>}
              <p className="gemini-origin-caveat">Son pasos de investigación para una persona; no se ejecutan automáticamente.</p>
            </div>
          </div>
        )}
      </section>
      <div className="detail-block">
        <span className="detail-label">Cronología y evidencia · {incident.events.length} eventos</span>
        <div className="timeline-list">
          {incident.events.map((event) => {
            const isAiCited = citedLogIds.has(event.Log_ID);
            return (
              <article className={`timeline-item ${isAiCited ? "timeline-item-ai-cited" : ""}`} key={event.Log_ID}>
                <span className="timeline-dot" />
                <div className="timeline-content">
                  <div className="timeline-meta">
                    <time>{displayTime(event.Timestamp)}</time>
                    <code>{event.Log_ID}</code>
                    {isAiCited && <span className="ai-evidence-badge">Citada por Gemini</span>}
                    <span>{event.Hostname}</span>
                  </div>
                  <strong>{event.Event_Description}</strong>
                  {event.Process_CommandLine && <code className="command-line">{event.Process_CommandLine}</code>}
                </div>
              </article>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function PrintableIncidentReport({
  incident,
  sourceFilename,
  geminiResult,
}: {
  incident: Incident;
  sourceFilename: string;
  geminiResult: GeminiInterpretation | null;
}) {
  const generatedAt = new Date().toLocaleString("es-ES");
  const citedEvents = new Map(incident.events.map((event) => [event.Log_ID, event]));

  return (
    <article className="print-report">
      <header className="print-report-header">
        <p className="print-eyebrow">SOC L2 · INFORME DE INCIDENTE</p>
        <h1>{incident.title}</h1>
        <div className="print-report-meta">
          <span><strong>Incidente:</strong> {incident.incident_id}</span>
          <span><strong>Generado:</strong> {generatedAt}</span>
          <span><strong>Fuente:</strong> {sourceFilename}</span>
        </div>
      </header>

      <section className="print-report-section">
        <h2>Resumen y riesgo determinista</h2>
        <div className="print-risk-grid">
          <div><span>Criticidad</span><strong>{incident.risk.level}</strong></div>
          <div><span>Puntaje</span><strong>{incident.risk.score}</strong></div>
          <div><span>Impacto</span><strong>{incident.risk.impact}/5</strong></div>
          <div><span>Confianza</span><strong>{incident.risk.confidence}/5</strong></div>
        </div>
        <p><strong>Impacto:</strong> {incident.risk.impact_rationale}</p>
        <p><strong>Confianza:</strong> {incident.risk.confidence_rationale}</p>
        <p><strong>Reglas:</strong> {incident.rule_ids.join(", ") || "Sin reglas asociadas"}</p>
        <p><strong>Técnicas ATT&CK:</strong> {incident.technique_ids.join(", ") || "Sin técnicas asociadas"}</p>
      </section>

      <section className="print-report-section">
        <h2>Hallazgos</h2>
        {incident.findings.length ? incident.findings.map((finding) => (
          <article className="print-finding" key={finding.finding_id}>
            <h3>{finding.rule_id} · {finding.name}</h3>
            <p>{finding.explanation}</p>
            <p className="print-muted">
              Periodo: {displayTime(finding.first_seen)} – {displayTime(finding.last_seen)}
              {finding.event_ids.length ? ` · ${finding.event_ids.length} registros vinculados` : ""}
            </p>
          </article>
        )) : <p>No hay hallazgos asociados a este incidente.</p>}
      </section>

      <section className="print-report-section">
        <h2>Entidades relacionadas</h2>
        <p><strong>Usuarios:</strong> {incident.entities.users.join(", ") || "—"}</p>
        <p><strong>Hosts:</strong> {incident.entities.hosts.join(", ") || "—"}</p>
        <p><strong>IP de origen:</strong> {incident.entities.source_ips.join(", ") || "—"}</p>
        <p><strong>Destinos:</strong> {incident.entities.destinations.join(", ") || "—"}</p>
      </section>

      <section className="print-report-section">
        <h2>Interpretación asistida por IA</h2>
        {geminiResult ? (
          <>
            <p><strong>Modelo:</strong> {geminiResult.model}</p>
            <p><strong>Conclusión:</strong> {geminiResult.conclusion.replace("_", " ")}</p>
            <p><strong>Línea base determinista:</strong> riesgo {incident.risk.level}, puntaje {incident.risk.score}. La clasificación IA siguiente es complementaria y no la modifica.</p>
            <h3>Clasificación IA por hallazgo</h3>
            {geminiResult.clasificaciones_hallazgos.length ? geminiResult.clasificaciones_hallazgos.map((classification) => {
              const finding = incident.findings.find((item) => item.finding_id === classification.finding_id);
              return (
                <article className="print-finding" key={classification.finding_id}>
                  <h3>{classification.finding_id}{finding ? ` · ${finding.name}` : ""} · Riesgo IA: {classification.riesgo}</h3>
                  <p>{classification.justificacion}</p>
                  <p><strong>Confianza IA:</strong> {classification.confianza}/5 · <strong>Técnicas MITRE:</strong> {classification.tecnica_mitre.join(", ") || "ninguna"}</p>
                  <p className="print-muted">Evidencia: {classification.evidence_ids.map((id) => `${id}${citedEvents.get(id) ? ` · ${citedEvents.get(id)?.Event_Description}` : ""}`).join("; ")}</p>
                </article>
              );
            }) : <p>Este incidente no contiene hallazgos para clasificar.</p>}
            <h3>Análisis de IP de origen</h3>
            {geminiResult.origenes.length ? geminiResult.origenes.map((origin) => (
              <article className="print-origin" key={origin.ip}>
                <p><strong>{origin.ip}</strong> — {origin.analisis}</p>
                <p className="print-muted">Evidencia: {origin.evidence_ids.map((id) => `${id}${citedEvents.get(id) ? ` · ${citedEvents.get(id)?.Event_Description}` : ""}`).join("; ")}</p>
              </article>
            )) : <p>No se identificaron IP de origen pertinentes en los eventos.</p>}
            <p className="print-muted">El análisis usa solo los registros del incidente; no consulta reputación, geolocalización ni titularidad de las IP.</p>
            <h3>Comprobaciones sugeridas para el analista</h3>
            {geminiResult.comprobaciones_recomendadas.length ? geminiResult.comprobaciones_recomendadas.map((item, index) => (
              <article className="print-origin" key={`${index}-${item.comprobacion}`}>
                <p>{item.comprobacion}</p>
                <p className="print-muted">Evidencia: {item.evidence_ids.map((id) => `${id}${citedEvents.get(id) ? ` · ${citedEvents.get(id)?.Event_Description}` : ""}`).join("; ")}</p>
              </article>
            )) : <p>No se sugirieron comprobaciones adicionales.</p>}
            <p className="print-muted">Son pasos de investigación para una persona; no se ejecutan automáticamente.</p>
            <p><strong>Explicación:</strong> {geminiResult.explicacion}</p>
            <p><strong>Limitación:</strong> {geminiResult.limitacion}</p>
            <p><strong>Log_ID citados:</strong> {geminiResult.evidence_ids.length
              ? geminiResult.evidence_ids.map((id) => `${id} — ${citedEvents.get(id)?.Event_Description ?? ""}`).join("; ")
              : "No se citaron registros específicos."}</p>
          </>
        ) : (
          <p>No se ejecutó Gemini para este incidente. El análisis determinista y su riesgo siguen disponibles.</p>
        )}
        <p className="print-disclaimer">
          La conclusión de IA es una ayuda para priorizar la revisión y no confirma por sí sola actividad maliciosa.
        </p>
      </section>

      <section className="print-report-section print-timeline">
        <h2>Cronología completa · {incident.events.length} eventos</h2>
        {incident.events.map((event) => {
          const isAiCited = geminiResult?.evidence_ids.includes(event.Log_ID) ?? false;
          return (
            <article className={`print-event ${isAiCited ? "print-event-ai-cited" : ""}`} key={event.Log_ID}>
              <div className="print-event-meta">
                <time>{displayTime(event.Timestamp)}</time>
                <code>{event.Log_ID}</code>
                {isAiCited && <strong className="print-cited-marker">Citado por Gemini</strong>}
                <span>{event.Hostname || "Host no indicado"}</span>
                <span>Event_ID {event.Event_ID}</span>
              </div>
              <p><strong>{event.Event_Description}</strong></p>
              <p className="print-muted">
                Usuario: {event.User || "—"} · Origen: {event.Source_IP || "—"} · Destino: {event.Destination || "—"} · Resultado: {event.Result}
              </p>
              {event.Process_CommandLine && <code className="print-command">{event.Process_CommandLine}</code>}
            </article>
          );
        })}
      </section>

      <footer className="print-report-footer">
        Informe generado localmente a partir de los datos cargados. Verifica las conclusiones y la evidencia antes de tomar medidas.
      </footer>
    </article>
  );
}

export default App;
