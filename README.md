# SOC L2 Incident Analyzer

Aplicación local para revisar eventos exportados desde un SIEM, identificar incidentes y consultar la evidencia asociada. La interfaz está en español.

## Estado actual

La aplicación carga el Excel, normaliza los eventos y analiza patrones mediante reglas deterministas R01–R14. El dashboard y el riesgo siguen basándose en esos resultados; Gemini es optativo y, bajo demanda, clasifica los hallazgos de un incidente en una llamada, además de aportar su interpretación. Desde el detalle puedes imprimir o guardar en PDF un informe individual con los hallazgos, el análisis IA disponible y toda la cronología.

Con el libro de referencia `SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx` (715 eventos, 12 columnas), el análisis actual produce 35 hallazgos de reglas y seis incidentes. Hallazgos e incidentes son conceptos distintos. Las coincidencias débiles entre subredes se presentan como hipótesis, no como relaciones confirmadas.

La carga y el análisis permanecen en memoria; al reiniciar la API, hay que volver a cargar y analizar el archivo. La interpretación de Gemini no altera las reglas ni el puntaje de riesgo determinista.

## Requisitos actuales

- Python compatible con las dependencias de `backend/requirements.txt`.
- Node.js y npm.
- El archivo de referencia incluido en la raíz del proyecto.

Gemini es opcional. Sin `GEMINI_API_KEY`, la aplicación conserva todas sus funciones deterministas y la interpretación con IA queda deshabilitada.

## Iniciar la aplicación en Windows

Abre dos terminales de PowerShell.

**Terminal 1 — API**, desde `backend/`:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

**Terminal 2 — interfaz**, desde `frontend/`:

```powershell
npm install
npm run dev
```

Abre la dirección que muestre Vite (por defecto `http://127.0.0.1:5173`). Vite reenvía las peticiones `/api` a FastAPI en `http://127.0.0.1:8000`.

## Recorrido de prueba actual

1. Selecciona el Excel de referencia y pulsa **Cargar Excel**. Debe indicar 715 eventos y 12 columnas; las observaciones de calidad aparecen resumidas por cantidad.
2. Pulsa **Analizar archivo**. La línea base determinista muestra 35 hallazgos y seis incidentes.
3. Revisa el dashboard y las hipótesis no confirmadas.
4. Abre **Incidentes** y revisa riesgo, reglas, entidades, cronología y `Log_ID`.
5. Desde el detalle, pulsa **Imprimir / Guardar informe PDF** para generar el informe individual desde el diálogo del navegador. Si Gemini ya se ejecutó, el informe incorpora también la clasificación de hallazgos, el análisis de IP de origen y las comprobaciones recomendadas.
6. Abre **Eventos**, prueba los filtros y la paginación.

## Interpretación opcional con Gemini

En PowerShell, define la clave en la misma terminal donde iniciarás FastAPI. Se solicita como texto seguro y la variable solo estará disponible para esa sesión:

```powershell
$secureKey = Read-Host "API key de Gemini" -AsSecureString
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
try {
  $env:GEMINI_API_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
}
finally {
  [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
}
$secureKey.Dispose()
$env:GEMINI_MODEL = "gemini-3.8-flash"
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Si FastAPI ya estaba ejecutándose, deténlo con `Ctrl+C` y vuelve a iniciarlo desde esa terminal después de establecer las variables. En la interfaz abre **Incidentes**, selecciona uno y pulsa **Interpretar con Gemini**. Una solicitud nueva envía a Google únicamente los hallazgos y eventos de ese incidente y clasifica todos los hallazgos en esa misma llamada; no se llama a Gemini durante **Analizar archivo**. Las interpretaciones se guardan en memoria por incidente y modelo para evitar llamadas repetidas; se borran al cargar otro Excel, volver a analizar o reiniciar el backend. La API valida que cada `evidence_id` exista entre los `Log_ID` del incidente, que las IP analizadas aparezcan como `Source_IP` en los eventos citados y que las comprobaciones sugeridas tengan evidencia asociada. El análisis de IP se limita a esos registros; no consulta reputación ni geolocalización.

La clave permanece en el backend y no se guarda en el repositorio. Aun así, los datos del incidente seleccionado salen de tu equipo y se envían a Google. No uses datos sensibles sin autorización y revisa las condiciones de privacidad y tratamiento de datos de tu plan Gemini. Errores `503` pueden indicar disponibilidad temporal o límites del proveedor; puedes reintentar más tarde.

Consulta `backend/README.md` para preparar y validar la API. La hoja de ruta visible, el estado actual y los siguientes pasos están en [`docs/ROADMAP.md`](docs/ROADMAP.md).

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
