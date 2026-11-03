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
- **Fase 6: implementada; validada automáticamente con mocks.** Informes ejecutivo y técnico bajo demanda, con validación de referencias y caché separada por tipo/modelo. No se ha hecho una llamada real para probar estos informes.
- **Fase 7: implementada; validada con build.** El dashboard presenta cada informe por separado y permite imprimir/guardar cada resultado como PDF; también mantiene disponible el informe individual por incidente. Los PDF distinguen la línea base determinista y las advertencias de IA.

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

### 6. Informes ejecutivo y técnico — implementada; pruebas automáticas aprobadas

- En **Resumen**, dos botones independientes generan, solo bajo demanda, un informe ejecutivo o uno técnico. Cada informe consume como máximo una llamada nueva; no se invocan durante la carga ni el análisis.
- El informe ejecutivo incluye resumen, puntos clave y recomendaciones para revisión humana, con hallazgos y `Log_ID` verificables.
- El informe técnico cubre exactamente los incidentes deterministas, sus hallazgos y técnicas de baseline, además de todos los hallazgos informativos separados como tales.
- El backend rechaza IDs repetidos, hallazgos o incidentes omitidos, técnicas ajenas y evidencia que no corresponde al hallazgo. La respuesta conserva la línea base determinista y no puede alterar su riesgo.
- La caché se mantiene en memoria por tipo/modelo y se borra al cargar otro Excel, volver a analizar o reiniciar el backend.
- **Validación:** pruebas con respuestas simuladas cubren caché, cambio de modelo y rechazo de evidencia/técnicas inválidas. No se realizó una llamada real a Gemini para estos informes.

### 7. Dashboard y PDF — implementada; build aprobado

Los informes aparecen en el dashboard, con estado de caché, modelo, citas, limitaciones y línea base determinista. Cada resultado tiene su acción propia **Imprimir / Guardar PDF**; la impresión selecciona únicamente ese informe (o el informe individual elegido). No se genera un informe automáticamente. La interfaz se validó con `npm run build`; la salida PDF se produce desde el diálogo de impresión del navegador.

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

Las fases 1–7 están implementadas. Las fases 4 y 5 cuentan además con validaciones reales iniciales del usuario usando `gemini-3.6-flash`. Las fases 6 y 7 se verificaron con pruebas simuladas y compilación, respectivamente; el paso opcional pendiente es que el usuario genere cada informe en su entorno y revise su contenido antes de usarlo.
