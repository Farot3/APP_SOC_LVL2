import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import {
  apiRequest,
  type AnalysisResult,
  type CanonicalEventField,
  type ColumnMappingSuggestion,
  type Dashboard,
  type EventPage,
  type EventRecord,
  type GeminiCorrelation,
  type GeminiExecutiveReport,
  type GeminiInterpretation,
  type GeminiTechnicalReport,
  type GeminiStatus,
  type Incident,
  type IncidentList,
  type UploadResult,
  type WorkbookPreview,
} from "./api";

type Section = "dashboard" | "reports" | "incidents" | "events";
type EventFilters = {
  host: string;
  user: string;
  source_ip: string;
  event_id: string;
  start_time: string;
  end_time: string;
};

const PAGE_SIZE = 25;
const CANONICAL_FIELDS: CanonicalEventField[] = [
  "Log_ID", "Timestamp", "Hostname", "Event_ID", "User", "Source_IP", "Destination",
  "Log_Source", "Event_Description", "Process_CommandLine", "Result", "Severity",
];
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
  const [workbookPreview, setWorkbookPreview] = useState<WorkbookPreview | null>(null);
  const [mappingDraft, setMappingDraft] = useState<Partial<Record<CanonicalEventField, string | null>>>({});
  const [sheetDraft, setSheetDraft] = useState("");
  const [headerRowDraft, setHeaderRowDraft] = useState("1");
  const [previewStale, setPreviewStale] = useState(false);
  const [mappingBusy, setMappingBusy] = useState(false);
  const [mappingError, setMappingError] = useState("");
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
  const [geminiResultsByIncident, setGeminiResultsByIncident] = useState<Record<string, GeminiInterpretation>>({});
  const [geminiError, setGeminiError] = useState("");
  const [geminiCorrelation, setGeminiCorrelation] = useState<GeminiCorrelation | null>(null);
  const [geminiCorrelationBusy, setGeminiCorrelationBusy] = useState(false);
  const [geminiCorrelationError, setGeminiCorrelationError] = useState("");
  const [executiveReport, setExecutiveReport] = useState<GeminiExecutiveReport | null>(null);
  const [technicalReport, setTechnicalReport] = useState<GeminiTechnicalReport | null>(null);
  const [geminiReportBusy, setGeminiReportBusy] = useState(false);
  const [geminiReportError, setGeminiReportError] = useState("");
  const [reportAuthorName, setReportAuthorName] = useState("");
  const [includeTimelineInReport, setIncludeTimelineInReport] = useState(false);
  const [printTarget, setPrintTarget] = useState<"final" | null>(null);

  useEffect(() => {
    const handleAfterPrint = () => setPrintTarget(null);
    window.addEventListener("afterprint", handleAfterPrint);
    return () => window.removeEventListener("afterprint", handleAfterPrint);
  }, []);

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

  async function previewWorkbook(sheetName?: string, headerRow?: number) {
    if (headerRow !== undefined && (!Number.isInteger(headerRow) || headerRow < 1)) {
      setError("La fila de encabezados debe ser un entero mayor que cero.");
      return;
    }
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
      if (sheetName) form.append("sheet_name", sheetName);
      if (headerRow) form.append("header_row", String(headerRow));
      const preview = await apiRequest<WorkbookPreview>("/api/upload/preview", { method: "POST", body: form });
      setWorkbookPreview(preview);
      setMappingDraft(preview.suggested_mapping);
      setSheetDraft(preview.sheet_name);
      setHeaderRowDraft(String(preview.header_row));
      setPreviewStale(false);
      setMappingError("");
      setUpload(null);
      setAnalysis(null);
      setDashboard(null);
      setIncidentList([]);
      setSelectedIncident(null);
      setGeminiResultsByIncident({});
      setGeminiError("");
      setGeminiCorrelation(null);
      setGeminiCorrelationError("");
      setExecutiveReport(null);
      setTechnicalReport(null);
      setGeminiReportError("");
      setNotice(`Se detectó la hoja “${preview.sheet_name}”, fila de encabezados ${preview.header_row}. Revisa el mapeo antes de importar.`);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "No se pudo leer la estructura del Excel.");
    } finally {
      setBusy(null);
    }
  }

  async function uploadWorkbook(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    await previewWorkbook();
  }

  async function suggestColumnMapping() {
    if (!workbookPreview || previewStale || !geminiStatus?.enabled || mappingBusy) return;
    setMappingBusy(true);
    setMappingError("");
    try {
      const suggestion = await apiRequest<ColumnMappingSuggestion>("/api/ai/map-columns", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ columns: workbookPreview.columns }),
      });
      setMappingDraft(suggestion.mapping);
      setNotice(`Gemini sugirió un mapeo con ${suggestion.model}; revísalo y confirma antes de importar.`);
    } catch (caught) {
      setMappingError(caught instanceof Error ? caught.message : "Gemini no pudo sugerir el mapeo.");
    } finally {
      setMappingBusy(false);
    }
  }

  async function importMappedWorkbook() {
    if (!selectedFile || !workbookPreview) return;
    const missing = workbookPreview.required_columns.filter((field) => !mappingDraft[field]);
    if (missing.length) {
      setMappingError(`Asigna los campos obligatorios: ${missing.join(", ")}.`);
      return;
    }
    setBusy("upload");
    setError("");
    setMappingError("");
    try {
      const form = new FormData();
      form.append("file", selectedFile);
      form.append("sheet_name", workbookPreview.sheet_name);
      form.append("header_row", String(workbookPreview.header_row));
      form.append("column_mapping", JSON.stringify(mappingDraft));
      const result = await apiRequest<UploadResult>("/api/upload/mapped", { method: "POST", body: form });
      setUpload(result);
      setWorkbookPreview(null);
      setAnalysis(null);
      setDashboard(null);
      setIncidentList([]);
      setSelectedIncident(null);
      setGeminiResultsByIncident({});
      setGeminiError("");
      setGeminiCorrelation(null);
      setGeminiCorrelationError("");
      setExecutiveReport(null);
      setTechnicalReport(null);
      setGeminiReportError("");
      setRiskFilter("");
      setActiveFilters(EMPTY_FILTERS);
      setFilterDraft(EMPTY_FILTERS);
      setNotice(`Se importaron ${result.event_count} eventos desde “${result.source_sheet}”. Ya puedes ejecutar el análisis.`);
      await loadEvents(1, EMPTY_FILTERS);
    } catch (caught) {
      setMappingError(caught instanceof Error ? caught.message : "No se pudo importar el Excel con este mapeo.");
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
      setGeminiResultsByIncident({});
      setGeminiError("");
      setGeminiCorrelation(null);
      setGeminiCorrelationError("");
      setExecutiveReport(null);
      setTechnicalReport(null);
      setGeminiReportError("");
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
      setGeminiError("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "No se pudo cargar el incidente.");
    } finally {
      setBusy(null);
    }
  }

  async function interpretSelectedIncident() {
    if (!selectedIncident || !geminiStatus?.enabled || geminiBusy || geminiCorrelationBusy || geminiReportBusy) return;
    const incidentId = selectedIncident.incident_id;
    if (geminiResultsByIncident[incidentId]) return;
    setGeminiBusy(true);
    setGeminiError("");
    try {
      const result = await apiRequest<GeminiInterpretation>(
        `/api/incidents/${encodeURIComponent(incidentId)}/interpret`,
        { method: "POST" },
      );
      setGeminiResultsByIncident((current) => ({ ...current, [incidentId]: result }));
    } catch (caught) {
      setGeminiError(caught instanceof Error ? caught.message : "No se pudo interpretar el incidente con Gemini.");
    } finally {
      setGeminiBusy(false);
    }
  }

  async function suggestCorrelationWithGemini() {
    if (!analysis || !geminiStatus?.enabled || geminiBusy || geminiCorrelationBusy || geminiReportBusy) return;
    setGeminiCorrelationBusy(true);
    setGeminiCorrelationError("");
    try {
      const result = await apiRequest<GeminiCorrelation>("/api/ai/correlate", { method: "POST" });
      setGeminiCorrelation(result);
    } catch (caught) {
      setGeminiCorrelationError(
        caught instanceof Error ? caught.message : "No se pudo proponer la correlación con Gemini.",
      );
    } finally {
      setGeminiCorrelationBusy(false);
    }
  }

  async function generateFinalReport() {
    if (!analysis || !geminiStatus?.enabled || geminiBusy || geminiCorrelationBusy || geminiReportBusy) return;
    setGeminiReportBusy(true);
    setGeminiReportError("");
    try {
      const executive = await apiRequest<GeminiExecutiveReport>("/api/ai/reports/executive", { method: "POST" });
      const technical = await apiRequest<GeminiTechnicalReport>("/api/ai/reports/technical", { method: "POST" });
      setExecutiveReport(executive);
      setTechnicalReport(technical);
    } catch (caught) {
      setGeminiReportError(caught instanceof Error ? caught.message : "No se pudo generar el informe completo con Gemini.");
    } finally {
      setGeminiReportBusy(false);
    }
  }

  function printFinalReport() {
    setPrintTarget("final");
    window.setTimeout(() => window.print(), 0);
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
                disabled={busy !== null || mappingBusy}
                onChange={(event) => {
                  setSelectedFile(event.target.files?.[0] ?? null);
                  setWorkbookPreview(null);
                  setMappingError("");
                }}
              />
            </label>
            <button className="button button-secondary" type="submit" disabled={!selectedFile || busy !== null || mappingBusy || geminiBusy || geminiCorrelationBusy || geminiReportBusy}>
              {busy === "upload" ? "Leyendo…" : "Revisar formato"}
            </button>
            <button className="button button-primary" type="button" onClick={analyzeWorkbook} disabled={!upload || busy !== null || geminiBusy || geminiCorrelationBusy || geminiReportBusy}>
              {busy === "analysis" ? "Analizando…" : analysis ? "Volver a analizar" : "Analizar archivo"}
            </button>
          </form>
        </section>

        {workbookPreview && (
          <section className="mapping-panel" aria-labelledby="mapping-title">
            <div className="mapping-panel-heading">
              <div><span className="section-kicker">IMPORTACIÓN FLEXIBLE</span><h2 id="mapping-title">Revisa cómo se interpretarán las columnas</h2></div>
              <button className="button button-quiet" disabled={busy !== null || mappingBusy} onClick={() => void previewWorkbook(sheetDraft, Number(headerRowDraft))} type="button">Actualizar vista previa</button>
            </div>
            <p>La detección automática busca encabezados equivalentes. Confirma hoja, fila y correspondencias antes de importar; el análisis usará estas columnas normalizadas.</p>
            <div className="mapping-source-controls">
              <label>Hoja del Excel<select disabled={mappingBusy || busy !== null} value={sheetDraft} onChange={(event) => { setSheetDraft(event.target.value); setPreviewStale(true); }}>{workbookPreview.sheet_names.map((name) => <option key={name} value={name}>{name}</option>)}</select></label>
              <label>Fila de encabezados<input disabled={mappingBusy || busy !== null} min="1" type="number" value={headerRowDraft} onChange={(event) => { setHeaderRowDraft(event.target.value); setPreviewStale(true); }} /></label>
            </div>
            {previewStale && <p className="mapping-warning">Cambiaste la hoja o fila. Actualiza la vista previa antes de sugerir o confirmar el mapeo.</p>}
            <div className="mapping-grid">
              {CANONICAL_FIELDS.map((field) => {
                const required = workbookPreview.required_columns.includes(field);
                return (
                  <label className="mapping-field" key={field}>
                    <span>{field}{required && <strong>Obligatoria</strong>}</span>
                    <select disabled={mappingBusy || busy !== null} value={mappingDraft[field] ?? ""} onChange={(event) => setMappingDraft((current) => ({ ...current, [field]: event.target.value || null }))}>
                      <option value="">— Sin asignar —</option>
                      {workbookPreview.columns.map((column) => <option key={`${field}-${column}`} value={column}>{column}</option>)}
                    </select>
                  </label>
                );
              })}
            </div>
            {workbookPreview.missing_required_columns.length > 0 && <p className="mapping-warning">No se detectaron automáticamente: {workbookPreview.missing_required_columns.join(", ")}. Asígnalos manualmente o prueba la sugerencia de Gemini.</p>}
            {mappingError && <p className="gemini-error" role="alert">{mappingError}</p>}
            <div className="mapping-actions">
              <div>
                <button className="button button-quiet" disabled={!geminiStatus?.enabled || geminiLoading || mappingBusy || busy !== null || previewStale} onClick={() => void suggestColumnMapping()} type="button">
                  {mappingBusy ? "Consultando Gemini…" : "Sugerir mapeo con Gemini"}
                </button>
                <span className="mapping-privacy">Solo se envían los nombres de las columnas, nunca filas ni valores de eventos. Revisa la propuesta antes de importar.</span>
              </div>
              <button className="button button-primary" disabled={busy !== null || mappingBusy || previewStale || workbookPreview.required_columns.some((field) => !mappingDraft[field])} onClick={() => void importMappedWorkbook()} type="button">
                {busy === "upload" ? "Importando…" : "Confirmar mapeo e importar"}
              </button>
            </div>
          </section>
        )}

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

        {!upload && !workbookPreview && (
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
                ["reports", "Informes"],
                ["incidents", "Incidentes", analysis?.incident_count],
                ["events", "Eventos", upload.event_count],
              ] as [Section, string, number?][]).map(([key, label, count]) => (
                <button
                  className={`nav-tab ${section === key ? "active" : ""}`}
                  key={key}
                  disabled={(key === "reports" && !analysis) || geminiBusy || geminiCorrelationBusy || geminiReportBusy}
                  onClick={() => setSection(key)}
                  type="button"
                >
                  {label}{count !== undefined && <span className="tab-count">{count}</span>}
                </button>
              ))}
            </nav>

            <div className="tab-content">
              {section === "dashboard" && (
                <DashboardView
                  dashboard={dashboard}
                  analysis={analysis}
                  geminiStatus={geminiStatus}
                  geminiLoading={geminiLoading}
                  geminiCorrelation={geminiCorrelation}
                  geminiCorrelationBusy={geminiCorrelationBusy}
                  geminiCorrelationError={geminiCorrelationError}
                  geminiRequestBusy={geminiBusy || geminiCorrelationBusy || geminiReportBusy}
                  onSuggestCorrelation={() => void suggestCorrelationWithGemini()}
                  onOpenIncidents={() => setSection("incidents")}
                />
              )}

              {section === "reports" && (
                <ReportsView
                  analysis={analysis}
                  executiveReport={executiveReport}
                  technicalReport={technicalReport}
                  geminiEnabled={Boolean(geminiStatus?.enabled && !geminiLoading)}
                  geminiRequestBusy={geminiBusy || geminiCorrelationBusy || geminiReportBusy}
                  geminiReportBusy={geminiReportBusy}
                  geminiReportError={geminiReportError}
                  reportAuthorName={reportAuthorName}
                  includeTimelineInReport={includeTimelineInReport}
                  onAuthorNameChange={setReportAuthorName}
                  onTimelineOptionChange={setIncludeTimelineInReport}
                  onGenerateFinalReport={() => void generateFinalReport()}
                  onPrintFinalReport={printFinalReport}
                />
              )}

              {section === "incidents" && (
                <section className="content-grid incident-layout">
                  <Panel
                    title="Incidentes detectados"
                    action={
                      <select aria-label="Filtrar incidentes por criticidad" value={riskFilter} disabled={!analysis || geminiBusy || geminiCorrelationBusy || geminiReportBusy} onChange={(event) => void loadIncidentsByRisk(event.target.value)}>
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
                            disabled={geminiBusy || geminiCorrelationBusy || geminiReportBusy}
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
                        geminiBusy={geminiBusy || geminiCorrelationBusy || geminiReportBusy}
                        geminiResult={geminiResultsByIncident[selectedIncident.incident_id] ?? null}
                        geminiError={geminiError}
                        onInterpret={() => void interpretSelectedIncident()}
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

      {analysis && executiveReport && technicalReport && (
        <PrintableFinalReport
          analysis={analysis}
          executiveReport={executiveReport}
          technicalReport={technicalReport}
          authorName={reportAuthorName.trim()}
          includeTimeline={includeTimelineInReport}
          sourceFilename={upload?.filename ?? "Archivo no disponible"}
          className={printTarget === "final" ? "is-print-target" : ""}
        />
      )}
    </div>
  );
}

function DashboardView({
  dashboard,
  analysis,
  geminiStatus,
  geminiLoading,
  geminiCorrelation,
  geminiCorrelationBusy,
  geminiCorrelationError,
  geminiRequestBusy,
  onSuggestCorrelation,
  onOpenIncidents,
}: {
  dashboard: Dashboard | null;
  analysis: AnalysisResult | null;
  geminiStatus: GeminiStatus | null;
  geminiLoading: boolean;
  geminiCorrelation: GeminiCorrelation | null;
  geminiCorrelationBusy: boolean;
  geminiCorrelationError: string;
  geminiRequestBusy: boolean;
  onSuggestCorrelation: () => void;
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

      <Panel
        title="Correlación IA de hallazgos"
        action={(
          <button
            className="button button-primary"
            disabled={!geminiStatus?.enabled || geminiLoading || geminiRequestBusy}
            onClick={onSuggestCorrelation}
            type="button"
          >
            {geminiCorrelationBusy
              ? "Correlacionando…"
              : geminiCorrelation
                ? "Consultar propuesta guardada"
                : "Proponer correlación con Gemini"}
          </button>
        )}
      >
        <p className="correlation-intro">
          Una llamada analiza los {analysis.findings.length} hallazgos y los eventos vinculados a su evidencia. Esos datos se envían a Google; Gemini propone grupos, pero no modifica la correlación ni el riesgo deterministas. La respuesta se guarda en memoria para evitar llamadas repetidas.
        </p>
        {!geminiLoading && !geminiStatus?.enabled && (
          <p className="muted-copy">Configura GEMINI_API_KEY en el backend para habilitar esta propuesta.</p>
        )}
        {geminiCorrelationError && <p className="gemini-error" role="alert">{geminiCorrelationError}</p>}
        {geminiCorrelation && (
          <div className="correlation-result" aria-live="polite">
            <p className="gemini-cache-note">
              {geminiCorrelation.cache_hit
                ? "Propuesta recuperada de la caché; no se hizo otra llamada a Gemini."
                : "Propuesta guardada en memoria para este análisis y modelo."}
              {` Línea base: ${geminiCorrelation.baseline_incident_count} incidentes · Modelo ${geminiCorrelation.model} · ${geminiCorrelation.groups.filter((group) => group.type === "incidente").length} incidentes sugeridos · ${geminiCorrelation.groups.filter((group) => group.type === "aislado").length} hallazgos aislados.`}
            </p>
            <div className="correlation-groups">
              {geminiCorrelation.groups.map((group) => (
                <article className="correlation-group" key={group.group_id}>
                  <div className="correlation-group-heading">
                    <div>
                      <span className={`correlation-kind ${group.type === "incidente" ? "is-incident" : "is-isolated"}`}>
                        {group.type === "incidente" ? "Incidente sugerido" : "Hallazgo aislado"}
                      </span>
                      <h3>{group.group_id} · {group.title}</h3>
                    </div>
                    <span className="correlation-confidence">Confianza IA {group.confidence}/5</span>
                  </div>
                  <p>{group.justificacion}</p>
                  <p className="correlation-baseline">
                    <strong>Línea base:</strong> {group.baseline_incident_ids.length
                      ? group.baseline_incident_ids.join(", ")
                      : "Sin incidente determinista (hallazgo informativo)"}
                  </p>
                  <div className="correlation-finding-list">
                    {group.finding_ids.map((findingId) => {
                      const finding = analysis.findings.find((item) => item.finding_id === findingId);
                      return (
                        <span className="correlation-finding-tag" key={findingId}>
                          <code>{findingId}</code>{finding ? ` · ${finding.rule_id} ${finding.name}` : ""}
                        </span>
                      );
                    })}
                  </div>
                  <p className="correlation-evidence"><strong>Evidencia:</strong> {group.evidence_ids.map((id) => <code key={id}>{id}</code>)}</p>
                </article>
              ))}
            </div>
            <p className="correlation-disclaimer">
              Propuesta asesorativa, no confirmación de un incidente. Los hallazgos aislados no se consideran incidentes nuevos.
            </p>
          </div>
        )}
      </Panel>
    </div>
  );
}

function ReportsView({
  analysis,
  executiveReport,
  technicalReport,
  geminiEnabled,
  geminiRequestBusy,
  geminiReportBusy,
  geminiReportError,
  reportAuthorName,
  includeTimelineInReport,
  onAuthorNameChange,
  onTimelineOptionChange,
  onGenerateFinalReport,
  onPrintFinalReport,
}: {
  analysis: AnalysisResult | null;
  executiveReport: GeminiExecutiveReport | null;
  technicalReport: GeminiTechnicalReport | null;
  geminiEnabled: boolean;
  geminiRequestBusy: boolean;
  geminiReportBusy: boolean;
  geminiReportError: string;
  reportAuthorName: string;
  includeTimelineInReport: boolean;
  onAuthorNameChange: (value: string) => void;
  onTimelineOptionChange: (value: boolean) => void;
  onGenerateFinalReport: () => void;
  onPrintFinalReport: () => void;
}) {
  if (!analysis) {
    return (
      <section className="empty-state">
        <div className="empty-icon" aria-hidden="true">▤</div>
        <h2>El informe estará disponible después del análisis</h2>
        <p>Primero ejecuta el análisis determinista para preparar el informe completo.</p>
      </section>
    );
  }

  const reportReady = Boolean(executiveReport && technicalReport);

  return (
    <div className="dashboard-stack">
      <div className="section-title-row">
        <div><span className="section-kicker">ANÁLISIS ASISTIDO</span><h2>Informe</h2></div>
      </div>
      <p className="report-intro">La aplicación prepara un único informe con resumen ejecutivo, análisis técnico, hallazgos y evidencias. No se ofrecen informes ejecutivos, técnicos ni por incidente como archivos separados.</p>
      {!geminiEnabled && <p className="muted-copy">Configura GEMINI_API_KEY en el backend para habilitar la generación asistida.</p>}
      {geminiReportError && <p className="gemini-error" role="alert">{geminiReportError}</p>}
      <Panel
        title="Informe completo (PDF)"
        action={(
          <button className="button button-primary" disabled={!geminiEnabled || geminiRequestBusy} onClick={onGenerateFinalReport} type="button">
            {geminiReportBusy ? "Generando informe completo…" : reportReady ? "Actualizar informe completo" : "Generar informe completo"}
          </button>
        )}
      >
        <p>{reportReady ? "El contenido del informe está preparado para imprimir." : "Genera el contenido asistido para habilitar el informe PDF."} Las solicitudes a Gemini solo se realizan al pulsar el botón y las propuestas no modifican el análisis determinista.</p>
        <div className="report-cover-fields">
          <label className="mapping-field">
            Nombre de quien presenta
            <input autoComplete="name" onChange={(event) => onAuthorNameChange(event.target.value)} placeholder="Nombre y apellidos" value={reportAuthorName} />
          </label>
        </div>
        <label className="report-option">
          <input
            checked={includeTimelineInReport}
            onChange={(event) => onTimelineOptionChange(event.target.checked)}
            type="checkbox"
          />
          Incluir línea de tiempo de eventos correlacionados (opcional)
        </label>
        <p className="muted-copy">La fecha se añade al imprimir. La línea de tiempo está desactivada por defecto.</p>
        <button
          className="button button-secondary"
          disabled={!reportReady || !reportAuthorName.trim()}
          onClick={onPrintFinalReport}
          type="button"
        >
          Imprimir / Guardar como PDF
        </button>
      </Panel>
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
          <label>Usuario<input value={filterDraft.user} onChange={(event) => setFilter("user", event.target.value)} placeholder="CORP\admin" /></label>
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
}: {
  incident: Incident;
  geminiStatus: GeminiStatus | null;
  geminiLoading: boolean;
  geminiBusy: boolean;
  geminiResult: GeminiInterpretation | null;
  geminiError: string;
  onInterpret: () => void;
}) {
  const citedEvents = new Map(incident.events.map((event) => [event.Log_ID, event]));
  const citedLogIds = new Set(
    geminiResult?.incident_id === incident.incident_id ? geminiResult.evidence_ids : [],
  );
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
          La interpretación se guarda para este incidente durante el análisis. Cambiar de incidente y volver conserva la respuesta sin otra petición a Gemini. La primera solicitud envía a Google los hallazgos y eventos de este incidente; las reglas y el riesgo deterministas no cambian.
        </p>
        <button
          className="button button-primary"
          type="button"
          onClick={onInterpret}
          disabled={!geminiStatus?.enabled || geminiLoading || geminiBusy || Boolean(geminiResult)}
        >
          {geminiBusy ? "Interpretando con Gemini…" : geminiResult ? "Interpretación guardada" : "Interpretar con Gemini"}
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

function PrintableFinalReport({
  analysis,
  executiveReport,
  technicalReport,
  authorName,
  includeTimeline,
  sourceFilename,
  className,
}: {
  analysis: AnalysisResult;
  executiveReport: GeminiExecutiveReport;
  technicalReport: GeminiTechnicalReport;
  authorName: string;
  includeTimeline: boolean;
  sourceFilename: string;
  className: string;
}) {
  const generatedAt = new Date().toLocaleDateString("es-ES");
  const riskLevels = ["Crítico", "Alto", "Medio", "Bajo"];
  const riskCounts = Object.fromEntries(riskLevels.map((level) => [
    level,
    analysis.incidents.filter((incident) => incident.risk.level === level).length,
  ]));
  const incidentFindingCount = new Set(analysis.incidents.flatMap((incident) => incident.finding_ids)).size;
  const incidentFindings = analysis.findings.filter((finding) =>
    analysis.incidents.some((incident) => incident.finding_ids.includes(finding.finding_id)),
  );
  const timelineById = new Map<string, { event: EventRecord; incidentIds: Set<string> }>();
  analysis.incidents.forEach((incident) => incident.events.forEach((event) => {
    const existing = timelineById.get(event.Log_ID);
    if (existing) existing.incidentIds.add(incident.incident_id);
    else timelineById.set(event.Log_ID, { event, incidentIds: new Set([incident.incident_id]) });
  }));
  const timeline = [...timelineById.values()].sort((left, right) => {
    const leftTime = Date.parse(left.event.Timestamp);
    const rightTime = Date.parse(right.event.Timestamp);
    if (!Number.isFinite(leftTime)) return Number.isFinite(rightTime) ? 1 : 0;
    if (!Number.isFinite(rightTime)) return -1;
    return leftTime - rightTime;
  });
  const eventById = new Map(timeline.map(({ event }) => [event.Log_ID, event]));
  const incidentDetailById = new Map(technicalReport.incident_details.map((detail) => [detail.incident_id, detail]));

  return (
    <article className={`print-report print-final-report ${className}`}>
      <header className="print-cover">
        <p className="print-eyebrow">SOC L2 · INFORME TÉCNICO DE SEGURIDAD</p>
        <h1>Informe de análisis de eventos e incidentes</h1>
        <p><strong>Presentado por:</strong> {authorName}</p>
        <p><strong>Fecha:</strong> {generatedAt}</p>
        <p><strong>Archivo analizado:</strong> {sourceFilename}</p>

      </header>

      <section className="print-report-section">
        <h2>1. Resumen ejecutivo</h2>
        <p>{executiveReport.summary}</p>
        <p>El análisis local identificó {analysis.incident_count} {analysis.incident_count === 1 ? "incidente" : "incidentes"} y {analysis.finding_count} hallazgos en total: {incidentFindingCount} vinculados a incidentes y {analysis.informational_finding_count} informativos. Los informativos están incluidos en el total, no se suman aparte. La clasificación de riesgo es determinista; las interpretaciones y recomendaciones de Gemini son asesorativas.</p>
      </section>

      <section className="print-report-section">
        <h2>2. Matriz de riesgo y resumen de hallazgos</h2>
        <div className="print-risk-grid">
          {riskLevels.map((level) => <div key={level}><span>{level}</span><strong>{riskCounts[level] ?? 0} incidentes</strong></div>)}
        </div>
        <p><strong>Incidentes identificados:</strong> {analysis.incident_count} ({analysis.incident_count ? "uno o varios incidentes" : "ningún incidente"}).</p>
        <p><strong>Eventos analizados:</strong> {analysis.event_count} · <strong>Hallazgos totales:</strong> {analysis.finding_count} ({incidentFindingCount} vinculados a incidentes, {analysis.informational_finding_count} informativos).</p>
        {analysis.incidents.map((incident) => (
          <p key={incident.incident_id}><strong>{incident.incident_id} · {incident.title}:</strong> riesgo {incident.risk.level}, puntaje {incident.risk.score}/25. {incident.risk.impact_rationale} {incident.risk.confidence_rationale}</p>
        ))}
        <p className="print-disclaimer">Los niveles y puntajes se asignan al incidente mediante reglas locales. No representan una calificación de severidad individual de cada hallazgo.</p>
      </section>

      <section className="print-report-section">
        <h2>3. Hallazgos identificados</h2>
        {incidentFindings.length ? incidentFindings.map((finding) => {
          const incident = analysis.incidents.find((item) => item.finding_ids.includes(finding.finding_id));
          const reportDetail = incident ? incidentDetailById.get(incident.incident_id) : undefined;
          const evidenceEvents = finding.event_ids.map((id) => eventById.get(id)).filter((event): event is EventRecord => Boolean(event));
          return (
            <article className="print-finding" key={finding.finding_id}>
              <h3>{finding.finding_id} · {finding.name} ({finding.rule_id})</h3>
              <p><strong>Explicación técnica:</strong> {finding.explanation}</p>
              {reportDetail && <p><strong>Contexto técnico del incidente:</strong> {reportDetail.technical_summary}</p>}
              <p><strong>Evidencias:</strong> {finding.event_ids.length ? finding.event_ids.join(", ") : "No hay Log_ID asociados"}</p>
              {evidenceEvents.map((event) => (
                <p className="print-evidence-row" key={event.Log_ID}><strong>{event.Log_ID}</strong> · {displayTime(event.Timestamp)} · {event.Hostname} · {event.Event_Description}{event.Process_CommandLine ? ` · Proceso: ${event.Process_CommandLine}` : ""}</p>
              ))}
              <p><strong>Criticidad:</strong> {incident ? `${incident.risk.level} (incidente ${incident.incident_id}; puntaje ${incident.risk.score})` : "Informativo; sin criticidad de incidente determinista"}</p>
              {incident && <p><strong>Justificación del riesgo del incidente:</strong> {incident.risk.impact_rationale} {incident.risk.confidence_rationale}</p>}
              <p><strong>Posible impacto organizacional (no confirmado):</strong> Si la actividad se valida, podría afectar la confidencialidad, integridad o disponibilidad de los sistemas o datos relacionados. Investigar el alcance antes de afirmar un impacto real.</p>
              <p><strong>MITRE ATT&amp;CK:</strong> {finding.technique_ids.length ? finding.technique_ids.join(", ") : incident?.technique_ids.join(", ") || "No asociada por la línea base"}</p>
            </article>
          );
        }) : <p>No se identificaron hallazgos asociados a reglas.</p>}

        <h3>Hallazgos informativos</h3>
        {technicalReport.informational_findings.length ? technicalReport.informational_findings.map((item) => {
          const finding = analysis.findings.find((entry) => entry.finding_id === item.finding_id);
          return (
            <article className="print-finding" key={item.finding_id}>
              <h3>{item.finding_id}{finding ? ` · ${finding.name}` : ""} · Informativo</h3>
              <p>{item.summary}</p>
              {finding && <p><strong>Explicación técnica:</strong> {finding.explanation}</p>}
              <p><strong>Criticidad:</strong> Informativo; no constituye un incidente de riesgo determinista.</p>
              <p><strong>Evidencias Log_ID:</strong> {item.evidence_ids.join(", ") || finding?.event_ids.join(", ") || "No especificadas"}</p>
              <p><strong>MITRE ATT&amp;CK:</strong> {finding?.technique_ids.join(", ") || "No asociada"}</p>
            </article>
          );
        }) : <p>No hay hallazgos informativos adicionales descritos en el informe técnico.</p>}
      </section>

      {includeTimeline && <section className="print-report-section">
        <h2>4. Línea de tiempo de eventos correlacionados</h2>
        <p>Se muestran eventos únicos vinculados a los incidentes, en orden cronológico. Total en análisis: {analysis.event_count}; eventos de incidente incluidos en esta cronología: {timeline.length}.</p>
        {timeline.length ? timeline.map(({ event, incidentIds }) => (
          <article className="print-event" key={event.Log_ID}>
            <div className="print-event-meta"><time>{displayTime(event.Timestamp)}</time><strong>{event.Log_ID}</strong><span>{event.Hostname}</span><span>{[...incidentIds].join(", ")}</span></div>
            <p>{event.Event_Description}</p>
            {event.Process_CommandLine && <code className="print-command">{event.Process_CommandLine}</code>}
          </article>
        )) : <p>No hay eventos de incidente disponibles para la cronología.</p>}
      </section>}

      <section className="print-report-section">
        <h2>{includeTimeline ? "5" : "4"}. Plan de acción</h2>
        <h3>1. Investigar</h3>
        <p>Validar los Log_ID y la secuencia temporal con las fuentes originales; confirmar usuario, host, proceso, resultado y contexto de negocio. Ampliar la búsqueda alrededor de los eventos relacionados y documentar los hallazgos sin asumir compromiso.</p>
        <h3>2. Contener</h3>
        <p>Si la investigación confirma actividad maliciosa y conforme al procedimiento autorizado de la organización, aplicar medidas proporcionales para limitar el alcance. Registrar aprobaciones, responsables, hora y efecto; evitar acciones disruptivas sin validación.</p>
        <h3>3. Remediar</h3>
        <p>Tras confirmar causa y alcance, eliminar persistencia o corregir la configuración afectada, rotar credenciales cuando corresponda, aplicar parches y verificar la recuperación y el monitoreo posterior.</p>
        <p className="print-disclaimer">Este plan es una guía para revisión humana. No se ejecutó ninguna acción de investigación, contención o remediación.</p>
      </section>

      <section className="print-report-section">
        <h2>{includeTimeline ? "6" : "5"}. Recomendaciones generales de seguridad</h2>
        <ul>
          <li>Mantener inventario de activos y fuentes de registro con sincronización horaria fiable y retención adecuada.</li>
          <li>Revisar periódicamente reglas de detección, falsos positivos y cobertura de MITRE ATT&amp;CK según el entorno.</li>
          <li>Aplicar mínimo privilegio, autenticación multifactor y gestión segura de credenciales.</li>
          <li>Definir procedimientos de respuesta, responsables y vías de escalamiento, y probarlos regularmente.</li>
          <li>Preservar evidencias y registrar toda decisión y acción de respuesta.</li>
        </ul>
        {executiveReport.recommended_actions.length > 0 && <>
          <h3>Propuestas adicionales de Gemini (requieren validación)</h3>
          {executiveReport.recommended_actions.map((item, index) => <p key={`${index}-${item.action}`}><strong>{item.priority}:</strong> {item.action} · Hallazgos: {item.finding_ids.join(", ") || "—"} · Log_ID: {item.evidence_ids.join(", ") || "—"}</p>)}
        </>}
      </section>

      <section className="print-report-section">
        <h2>Limitaciones</h2>
        <p><strong>Informe ejecutivo:</strong> {executiveReport.limitations}</p>
        <p><strong>Informe técnico:</strong> {technicalReport.limitations}</p>
        <p>El contenido generado con Gemini es asesorativo y puede contener errores. Comprueba las conclusiones y las citas frente a los registros originales. El análisis no confirma por sí solo actividad maliciosa ni impacto organizacional.</p>
      </section>
      <footer className="print-report-footer">Fuente: {sourceFilename}. Riesgos e incidentes provienen de la línea base local y no son modificados por Gemini.</footer>
    </article>
  );
}

export default App;
