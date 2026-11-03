# Hoja de ruta por fases — SOC L2

Este documento es la referencia del estado del proyecto y de los próximos pasos. La
línea base de detección y riesgo sigue siendo determinista; Gemini es opcional,
explícito y asesor. No se debe presentar una salida de IA como hecho confirmado ni
permitir que reemplace silenciosamente el resultado del código.

## Estado resumido

- **Fases 1–3: completadas.** Carga/normalización, reglas R01–R14, hallazgos con
evidencia, correlación determinista, riesgo base y API.
- **Fase 4: implementada y validada en vivo en un caso.** Gemini 3.6 Flash
clasificó los nueve hallazgos de I-02 en una llamada; el backend aceptó la respuesta
tras validar IDs, evidencia y técnicas. La caché funciona en memoria. Las pruebas
automatizadas siguen usando respuestas simuladas; falta comprobar más incidentes
para aumentar la cobertura real.
- **Fase 5: implementada y validada en vivo inicialmente.** Con Gemini 3.6 Flash,
  una llamada cubrió los 35 hallazgos en 20 grupos; la salida pasó la validación y
  no cambió la línea base determinista. La caché devolvió el resultado al consultar
  de nuevo, sin una llamada adicional.
- **Fase 6: pendiente.** Informes IA ejecutivo y técnico.
- **Fase 7: parcial/completada para la base actual.** Dashboard y detalle de
incidentes están disponibles; el informe individual se imprime/guarda como PDF
desde el navegador. Falta integrar los informes IA de la fase 6 cuando existan.

## Fases

### 1. Carga y normalización — completada

Leer el libro Excel esperado, validar columnas, normalizar campos y exponer
observaciones de calidad sin descartar los valores originales relevantes.

### 2. Detección por reglas — completada

Ejecutar R01–R14 de forma determinista sobre los eventos normalizados. Las reglas
no dependen de Gemini.

### 3. Agrupación en hallazgos e incidentes base — completada

Agrupar eventos como hallazgos con `finding_id` y `event_ids`; correlacionarlos con
criterios deterministas y calcular el riesgo base. Los vínculos débiles se mantienen
como hipótesis no confirmadas.

### 4. Clasificación y justificación con Gemini — implementada; prueba real inicial aprobada

- Una llamada optativa por incidente clasifica todos los hallazgos de ese incidente
  (no una llamada por hallazgo), para limitar consumo de cuota.
- Cada clasificación propone riesgo, justificación, técnicas MITRE, confianza y
  `Log_ID` de evidencia.
- La API exige cobertura exacta de los hallazgos y verifica que hallazgo, técnica y
  evidencia existan y estén relacionados en la línea base.
- Las propuestas de Gemini se muestran separadas; no alteran reglas, hallazgos ni
  riesgo determinista.
- La caché es por incidente/modelo y vive en memoria. Se invalida al cargar otro
  Excel, volver a analizar o reiniciar el backend.
- **Validación real:** el usuario probó I-02 con `gemini-3.6-flash`; se recibieron
  las nueve clasificaciones y la respuesta pasó la validación del backend. Esto
  verifica un caso, no todas las combinaciones de respuesta. No hacer reintentos
  automáticos ante `503` o timeout; verificar cuota y disponibilidad antes de reintentar.

### 5. Correlación IA e incidentes — implementada; validación real inicial aprobada

En **Resumen**, el usuario puede solicitar una propuesta global. Una llamada analiza
los hallazgos y sus eventos de evidencia, y devuelve incidentes sugeridos o hallazgos
aislados. El backend exige que todos los `finding_id` aparezcan exactamente una vez,
que los grupos tengan forma válida y que los `Log_ID` citados pertenezcan a cada
hallazgo del grupo. Añade al resultado los IDs de incidentes deterministas para
comparar propuestas. La línea base no se modifica y la propuesta queda cacheada por
análisis/modelo en memoria. **Prueba en vivo:** con `gemini-3.6-flash`, los 35
hallazgos se repartieron en cuatro grupos de incidente y 16 hallazgos aislados; la
respuesta pasó la validación. El resultado se recuperó luego de caché, sin otra
llamada a Google. Las pruebas automatizadas usan mocks.

### 6. Informes ejecutivo y técnico — pendiente

Generar dos salidas separadas y bajo demanda: un resumen ejecutivo y un informe
técnico. Incluir citas verificables, limitaciones y separación clara entre hechos
deterministas e interpretación IA. Mantener ambas salidas cacheadas por análisis y
modelo. No generarlas automáticamente durante la carga o el análisis.

### 7. Dashboard y PDF — base implementada, integración pendiente

El dashboard determinista, el detalle de incidentes y la impresión/guardado de un
informe individual desde el navegador ya existen. Cuando se complete la fase 6,
integrar los informes ejecutivo y técnico en las vistas y en una salida imprimible;
verificar que los PDF mantengan evidencia, procedencia y advertencias de IA.

## Presupuesto de llamadas y validación

Con el libro de referencia (35 hallazgos, 6 incidentes), clasificar por hallazgo
individualmente excedería la cuota diaria conocida. La estrategia prevista es una
llamada por incidente para la fase 4 (6), una para correlación (1) y dos para
informes (2): aproximadamente **9 llamadas por análisis completo**, solo cuando el
usuario las solicite y sin contar reintentos. La caché reduce llamadas repetidas,
pero actualmente no sobrevive a un reinicio del backend.

Antes de una prueba real, comprobar modelo y cuota. No enviar registros sensibles
sin autorización: la llamada seleccionada envía los datos del incidente a Google.
Las pruebas automatizadas no hacen llamadas de red.

## Siguiente paso

La fase 4 está implementada, probada automáticamente con mocks y validada en vivo
con I-02 usando `gemini-3.6-flash`. La fase 5 también está implementada y tuvo una
primera validación en vivo con los 35 hallazgos del Excel de referencia. El siguiente
bloque es la fase 6: informes ejecutivo y técnico.
