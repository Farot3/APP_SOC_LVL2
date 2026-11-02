# SOC L2 Incident Analyzer

Aplicación local para cargar un Excel exportado por el SIEM, detectar patrones con reglas deterministas, agrupar incidentes y revisar la evidencia asociada. La interfaz está en español y consulta una API local; esta versión no utiliza IA.

## Requisitos

- Python 3.11 o compatible con las dependencias del backend.
- Node.js y npm.
- El archivo de prueba `SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx`.

## Iniciar la aplicación en Windows

Abre dos terminales de PowerShell desde la carpeta del proyecto.

**Terminal 1 — API**, desde `backend/`:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

**Terminal 2 — interfaz**, desde `frontend/`:

```powershell
npm install
npm run dev
```

Abre la dirección que muestre Vite (por defecto `http://127.0.0.1:5173`). La interfaz reenvía las peticiones `/api` a FastAPI en `http://127.0.0.1:8000`. Si la API se inicia después de abrir la página, recárgala para actualizar el indicador de conexión.

## Recorrido de prueba

1. Selecciona `SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx` y pulsa **Cargar Excel**. La respuesta esperada es de 715 eventos.
2. Pulsa **Analizar archivo**. Para el libro de referencia se esperan 35 hallazgos de reglas y seis incidentes; los hallazgos no equivalen a incidentes.
3. Revisa el resumen, las hipótesis marcadas como no confirmadas y la matriz de riesgo.
4. Abre **Incidentes**, selecciona un incidente y comprueba su puntuación, reglas, entidades, cronología y `Log_ID` de evidencia.
5. Abre **Eventos**, filtra por host/usuario/IP/Event_ID o rango de tiempo y navega entre páginas.

La carga y los resultados del backend se mantienen en memoria: al reiniciar la API se debe volver a cargar y analizar el Excel. La carpeta `definicion/` contiene el plan de trabajo por fases y está excluida por el `.gitignore` actual.

## Validación

Backend, desde `backend/`:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check app tests
```

Frontend, desde `frontend/`:

```powershell
npm run build
```

Consulta `backend/README.md` para los detalles de la API y la preparación del entorno Python.
