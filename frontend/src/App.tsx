import { useState, type FormEvent, type ReactNode } from "react";
import {
  apiRequest,
  type AnalysisResult,
  type Dashboard,
  type EventPage,
  type EventRecord,
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
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "No se pudo cargar el incidente.");
    } finally {
      setBusy(null);
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
            <button className="button button-secondary" type="submit" disabled={!selectedFile || busy !== null}>
              {busy === "upload" ? "Cargando…" : "Cargar Excel"}
            </button>
            <button className="button button-primary" type="button" onClick={analyzeWorkbook} disabled={!upload || busy !== null}>
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
                      <select aria-label="Filtrar incidentes por criticidad" value={riskFilter} disabled={!analysis} onChange={(event) => void loadIncidentsByRisk(event.target.value)}>
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
                    {selectedIncident && <IncidentDetail incident={selectedIncident} />}
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
          <span>Procesamiento local · Hallazgos respaldados por evidencia</span>
          <span>{upload?.filename ?? "Sin archivo cargado"}</span>
        </footer>
      </main>
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

function IncidentDetail({ incident }: { incident: Incident }) {
  return (
    <div className="incident-detail">
      <div className="detail-title-row"><h3>{incident.title}</h3><RiskBadge level={incident.risk.level} /></div>
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
      <div className="detail-block">
        <span className="detail-label">Cronología y evidencia · {incident.events.length} eventos</span>
        <div className="timeline-list">
          {incident.events.map((event) => (
            <article className="timeline-item" key={event.Log_ID}>
              <span className="timeline-dot" />
              <div className="timeline-content">
                <div className="timeline-meta"><time>{displayTime(event.Timestamp)}</time><code>{event.Log_ID}</code><span>{event.Hostname}</span></div>
                <strong>{event.Event_Description}</strong>
                {event.Process_CommandLine && <code className="command-line">{event.Process_CommandLine}</code>}
              </div>
            </article>
          ))}
        </div>
      </div>
    </div>
  );
}

export default App;
