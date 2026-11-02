# Backend — SOC L2 Incident Analyzer

Fases 1–4: ingesta, detección, correlación, puntuación de riesgo y API para la aplicación. La interfaz de la Fase 5 está en `../frontend/`.

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

Rutas disponibles en esta fase:

- `GET /api/health`
- `POST /api/upload` — formulario multipart, campo `file`, archivo `.xlsx`
- `GET /api/events?page=1&page_size=50` — admite filtros `host`, `user`, `source_ip`, `event_id`, `start_time` y `end_time`
- `POST /api/analyze` — ejecuta reglas R01–R14, correlaciona y calcula riesgo
- `GET /api/incidents` — lista filtrable por `risk_level`, `rule_id`, `user` y `host`
- `GET /api/incidents/{incident_id}` — detalle, cronología y evidencia
- `GET /api/dashboard` — métricas de eventos, reglas, incidentes, tácticas y matriz de riesgo

La carga, los hallazgos y los incidentes quedan en memoria. Los vínculos débiles se devuelven como hipótesis y no se usan para unir incidentes. Las rutas dependientes del análisis responden `409` si todavía no se ha cargado o analizado el Excel.

## Ejecutar la interfaz (Fase 5)

Con la API iniciada en el puerto 8000, abre otra terminal en `frontend/`:

```powershell
npm install
npm run dev
```

Abre `http://127.0.0.1:5173`. Vite reenvía `/api` a la API local. También puedes compilar la interfaz con `npm run build`.
