# Frontend — SOC L2 Incident Analyzer

Interfaz web en React, TypeScript y Vite. Consume la API local del backend; no se conecta directamente con Gemini ni almacena claves de proveedor.

## Requisitos

- Node.js y npm.
- Backend ejecutándose en `http://127.0.0.1:8000` para usar datos y análisis.

## Instalar y ejecutar

Desde `frontend/`, instala las dependencias una vez:

```powershell
npm install
```

Inicia el servidor de desarrollo:

```powershell
npm run dev
```

Abre la dirección indicada por Vite, normalmente `http://127.0.0.1:5173`. Vite reenvía las rutas `/api` al backend en `http://127.0.0.1:8000`.

## Compilar

```powershell
npm run build
```

Para servir localmente la compilación:

```powershell
npm run preview
```

## Secciones de la aplicación

- **Resumen:** métricas deterministas y propuesta opcional de correlación IA.
- **Informes:** generación independiente de informes ejecutivo y técnico, con opción de imprimir o guardar como PDF.
- **Incidentes:** riesgo, hallazgos, eventos y evidencia.
- **Eventos:** registros normalizados con filtros y paginación.

La importación permite revisar y confirmar el mapeo de columnas antes de analizar. Si Gemini está configurado en el backend, se puede solicitar una sugerencia de mapeo basada solo en los encabezados. Para el arranque completo del proyecto, consulta el [manual de ejecución](../docs/MANUAL_USUARIO.md).
