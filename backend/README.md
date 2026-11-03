# Backend — SOC L2 Incident Analyzer

Ingesta, detección determinista, correlación, puntuación de riesgo y API; la interfaz está en `../frontend/`. `/api/analyze` mantiene el análisis determinista y Gemini es optativo. La interfaz permite imprimir o guardar en PDF un informe individual por incidente.

## Preparar entorno

Desde esta carpeta, crear un entorno virtual e instalar dependencias:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Ejecutar pruebas

Desde `backend/`:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Las pruebas de integración usan `../SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx`.

Para revisar también el estilo del backend:

```powershell
.\.venv\Scripts\python.exe -m ruff check app tests
```

## Iniciar API local

Desde `backend/`:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

La configuración opcional de Gemini se explica en la sección **Interpretación optativa con Gemini**.

Rutas disponibles en esta fase:

- `GET /api/health`
- `POST /api/upload` — formulario multipart, campo `file`, archivo `.xlsx`
- `GET /api/events?page=1&page_size=50` — admite filtros `host`, `user`, `source_ip`, `event_id`, `start_time` y `end_time`
- `POST /api/analyze` — ejecuta reglas R01–R14, correlaciona y calcula riesgo
- `GET /api/incidents` — lista filtrable por `risk_level`, `rule_id`, `user` y `host`
- `GET /api/incidents/{incident_id}` — detalle, cronología y evidencia
- `GET /api/ai/status` — indica si la interpretación optativa con Gemini está configurada
- `POST /api/incidents/{incident_id}/interpret` — interpreta solo ese incidente con Gemini, clasifica todos sus hallazgos en la misma llamada y valida hallazgos, técnicas y `Log_ID`
- `POST /api/ai/correlate` — propone grupos alternativos para todos los hallazgos, valida una partición exacta y cachea el resultado por análisis/modelo
- `GET /api/dashboard` — métricas de eventos, reglas, incidentes, tácticas y matriz de riesgo

La carga, los hallazgos y los incidentes quedan en memoria. Los vínculos débiles se devuelven como hipótesis y no se usan para unir incidentes. Las rutas dependientes del análisis responden `409` si todavía no se ha cargado o analizado el Excel.

## Ejecutar la interfaz

Con la API iniciada en el puerto 8000, abre otra terminal en `frontend/`:

```powershell
npm install
npm run dev
```

Abre `http://127.0.0.1:5173`. Vite reenvía `/api` a la API local. También puedes compilar la interfaz con `npm run build`.

## Interpretación y correlación optativas con Gemini

`POST /api/analyze` sigue ejecutando R01–R14, correlacionando hallazgos y calculando el riesgo de forma determinista. Gemini solo se invoca cuando el usuario solicita interpretar un incidente o proponer una correlación alternativa; ninguna de esas acciones cambia las reglas ni el puntaje de riesgo.

En PowerShell, define la clave en la misma terminal donde inicias Uvicorn:

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
$env:GEMINI_MODEL = "gemini-3.6-flash"
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Si ya estaba ejecutándose, detén Uvicorn con `Ctrl+C` y reinícialo después de configurar las variables. La clave no debe guardarse en el frontend ni en Git. Sin ella, `/api/ai/status` informa que Gemini está deshabilitado.

La interpretación individual envía solo los hallazgos y eventos del incidente seleccionado, no el libro completo. Las interpretaciones exitosas se guardan en memoria por incidente y modelo; volver a consultar el resultado no consume otra llamada. La correlación envía todos los hallazgos y únicamente los eventos citados por ellos, en una llamada por análisis. La salida debe asignar cada `finding_id` exactamente una vez a un incidente sugerido o a un grupo aislado; se rechazan IDs duplicados/inventados y evidencia ajena al grupo. Ambas cachés se borran al cargar otro Excel, volver a analizar o reiniciar el backend. Gemini devuelve JSON estructurado con clasificación por hallazgo, explicación, análisis de IP de origen y comprobaciones sugeridas para un analista humano. El backend valida que la respuesta cubra exactamente los hallazgos del incidente, que las técnicas y citas pertenezcan a cada hallazgo, que cada IP exista en `Source_IP` de los eventos y que las recomendaciones citen `Log_ID` del incidente. Las clasificaciones IA no sustituyen el riesgo determinista. No consulta reputación ni geolocalización y no ejecuta acciones sugeridas.

La clasificación de hallazgos se incluye en la misma llamada por incidente para limitar el consumo de cuota. La correlación global añade una llamada opcional por análisis. Las pruebas automatizadas usan mocks y no hacen llamadas a Google. El estado de fases y próximos pasos está en `../docs/ROADMAP.md`. Al activar estas funciones, los datos asociados a la solicitud salen a Google; no remitas información sensible sin autorización y consulta las condiciones de privacidad y tratamiento de datos aplicables a tu plan.
