# Backend — SOC L2 Incident Analyzer

Fases 1–3: ingesta, detección determinista, correlación y puntuación de riesgo sobre el Excel SIEM.

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

## Iniciar API local

Desde `backend/`:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Rutas disponibles en esta fase:

- `GET /api/health`
- `POST /api/upload` — formulario multipart, campo `file`, archivo `.xlsx`
- `GET /api/events?page=1&page_size=50`
- `POST /api/analyze` — ejecuta reglas R01–R14, correlaciona y calcula riesgo
- `GET /api/incidents` — lista los incidentes del último análisis

La carga, los hallazgos y los incidentes quedan en memoria. Los vínculos débiles se devuelven como hipótesis y no se usan para unir incidentes.
