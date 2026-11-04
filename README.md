# SOC L2 Incident Analyzer

Aplicación local para cargar exportaciones SIEM en Excel, analizar eventos y consultar evidencia de incidentes. La interfaz está en español.

## Componentes

- [`backend/README.md`](backend/README.md): instalación, configuración de Gemini, API y pruebas del backend.
- [`frontend/README.md`](frontend/README.md): instalación, ejecución y compilación de la interfaz.
- [`docs/MANUAL_USUARIO.md`](docs/MANUAL_USUARIO.md): pasos breves para iniciar la aplicación completa.
- [`docs/ROADMAP.md`](docs/ROADMAP.md): estado de las fases del proyecto.

## Cómo funciona

El backend normaliza los eventos y ejecuta las reglas R01–R14, la correlación base y la puntuación de riesgo de forma determinista. Gemini es opcional y, cuando se solicita, puede interpretar incidentes, proponer correlaciones o generar informes. Sus propuestas no reemplazan ni modifican la línea base. Las claves de proveedor se configuran solo en el backend.

El importador permite revisar y mapear encabezados de Excel antes de cargar los eventos. La sugerencia de mapeo con Gemini envía solo los nombres de columnas y requiere confirmación del usuario.

Con el libro de referencia se esperan 715 eventos, 35 hallazgos y seis incidentes. La carga y los resultados se mantienen en memoria; al reiniciar el backend hay que volver a cargar y analizar el archivo.
