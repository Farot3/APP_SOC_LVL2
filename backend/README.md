# Backend — SOC L2 Incident Analyzer

API FastAPI para importar y normalizar eventos, ejecutar detecciones R01–R14, correlacionar hallazgos y calcular riesgo determinista. Gemini se conecta desde el backend y sus resultados no modifican la línea base.

La interfaz se documenta por separado en [`../frontend/README.md`](../frontend/README.md). Para iniciar ambos componentes juntos, consulta el [manual de ejecución](../docs/MANUAL_USUARIO.md).

## Preparación

Desde `backend/`, crea el entorno e instala las dependencias:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Iniciar la API

Desde `backend/`, si deseas usar Gemini, define la clave en la misma terminal donde iniciarás Uvicorn:

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

Las variables pertenecen a esa sesión de PowerShell; vuelve a introducirlas al iniciar el backend en una sesión nueva. Si no defines `GEMINI_API_KEY`, la API inicia normalmente y conserva el análisis determinista, pero las funciones de IA quedan deshabilitadas. No guardes la clave en Git ni en el frontend.

## Rutas principales

- `GET /api/health` — estado de la API.
- `POST /api/upload/preview` — detecta hoja, fila de encabezados y mapeo sugerido del Excel.
- `POST /api/upload/mapped` — importa el Excel con el mapeo confirmado.
- `POST /api/upload` — ruta compatible con el esquema canónico anterior.
- `POST /api/ai/map-columns` — sugiere un mapeo con Gemini usando solo encabezados.
- `POST /api/analyze` — ejecuta reglas, correlación determinista y riesgo.
- `GET /api/dashboard` — métricas para el dashboard.
- `GET /api/events` — eventos paginados y filtrables.
- `GET /api/incidents` y `GET /api/incidents/{incident_id}` — incidentes y detalle.
- `GET /api/ai/status` — estado y modelo configurado.
- `POST /api/incidents/{incident_id}/interpret` — interpretación asistida de un incidente.
- `POST /api/ai/correlate` — propuesta global de correlación.
- `POST /api/ai/reports/executive` y `POST /api/ai/reports/technical` — informes bajo demanda.

El importador mapea los encabezados al esquema canónico y requiere temporalidad, host, ID de evento, usuario, IP de origen, descripción y resultado. Los campos auxiliares ausentes quedan vacíos; si no hay `Log_ID`, se genera uno localmente. Gemini no se llama durante la carga ni durante el análisis. Al usar las funciones de IA, los datos relevantes se envían a Google; no envíes información sensible sin autorización.

## Pruebas y estilo

Desde `backend/`:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check app tests
```

Las pruebas usan respuestas simuladas para Gemini y no realizan llamadas externas.
