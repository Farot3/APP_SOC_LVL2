# Backend — SOC L2 Incident Analyzer

Primera fase: ingesta, validación y normalización del Excel SIEM.

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

La carga queda en memoria y se reemplaza al subir otro archivo. Todavía no se implementaron reglas de detección ni correlación.
