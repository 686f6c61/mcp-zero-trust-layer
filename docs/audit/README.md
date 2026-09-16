# Auditoría de MCP Zero Trust Layer

> Historical baseline audit of 0.3.0. The 0.4.0 corrections and verification are recorded in [TESTING_0.4.0.md](../TESTING_0.4.0.md), [CHANGELOG](../../CHANGELOG.md) and [supported profile](../SUPPORTED_PROFILE.md). Reproduction scripts here describe the old revision; maintained regression tests live under `tests/`.

Fecha: 16 de septiembre de 2026. Versión 0.3.0, commit `4c1061daab2fa2a7442d42e7412cf3c6c85ae89f`.

## Dictamen

El proyecto implementa una capa de control útil, pero **todavía no cumple de forma consistente todas sus garantías anunciadas**. Los problemas prioritarios afectan al cumplimiento de decisiones, aislamiento de sesiones, uso único de aprobaciones y fiabilidad de auditoría. Deben resolverse antes de ampliar las afirmaciones de seguridad o compatibilidad.

La revisión se repartió entre tres agentes especializados y un coordinador: seguridad/políticas, aprobaciones/evidencia, compatibilidad/estado del arte, y validación independiente/transportes. Un agente se interrumpió por un filtro automático; el coordinador revisó sus hallazgos y ejecutó comprobaciones locales de los contratos de políticas. No es una certificación exhaustiva ni una prueba de penetración de un despliegue.

Solo se han añadido informes y reproducciones. No se ha cambiado el producto, añadido Grok al código, hecho commit, publicado ni enviado nada a terceros. Esta entrega permite decidir y ejecutar las mejoras sobre evidencia.

## Qué sí se ha comprobado

- Instalación editable con dependencias de desarrollo y `constraints.txt`, Python 3.14.4.
- **501 tests pasan; 100 % de cobertura de líneas** en 3.800 sentencias. Esa métrica no equivale a cobertura de escenarios concurrentes, protocolo o garantías.
- Ruff y mypy pasan (59 archivos fuente); wheel y sdist se construyen y pasan `twine check`.
- Aprobación vinculada a hash de argumentos y contexto; rechazo de reutilización secuencial. La garantía concurrente falla en una operación SQLite distinta de la propia consumición.
- Reproducciones locales adicionales de aprobaciones, auditoría, políticas y transporte stdio. Usan datos sintéticos, archivos temporales y procesos locales.
- Revisión de documentación oficial actual de MCP y clientes/proveedores, con fuentes en [compatibility.md](compatibility.md).

## Hallazgos que cambian el dictamen

| Prioridad | Hallazgo | Evidencia y condición |
| --- | --- | --- |
| P1 | Un rechazo OPA de salida sin `policy_id` deja pasar el resultado | Contrato reproducido localmente; coincide con las decisiones que genera el adaptador ante `false` o fallo cerrado. S-01. |
| P1 | La identidad JWT acepta campos de cabeceras no confiables | Reproducido en conversión de claims; afecta a políticas que confían en client/agent ID u otros campos aportados por el caller. No omite la verificación de firma. S-02. |
| P1 | `require_approval` no se aplica a métodos genéricos | Reproducido con un upstream simulado; listas tienen también una ruta distinta. S-03. |
| P1 | Sesiones HTTP sin aislamiento suficiente | Confirmado por código: clientes sin cabecera comparten clave de caché; falta vincular sesión a identidad. Impacto depende del servidor stateful. S-04. |
| P1 | Una actualización SQLite concurrente puede reactivar una aprobación consumida | Reproducción determinista: la misma aprobación se consume dos veces con un escritor de estado autorizado concurrente. A2. |
| P1 | `audit.strict` puede fallar después de producir el efecto | Reproducido: 1 llamada upstream antes del error de escritura; contradice la promesa de impedir ejecución sin registro. A1. |
| P1 | Stdio no respeta tamaño máximo ni plazo de lectura completo | Respuesta de 151 bytes aceptada con límite 32; plazo 0,1 s excedido hasta 0,5 s tras escritura parcial. T-01/T-02. |
| P1/P2 | Importación de configuración elimina opciones de seguridad del cliente | Reproducido con VS Code: desaparecen sandbox, inputs y opciones por servidor. C-02. |
| P2 | Las decisiones desde la UI no quedan auditadas | POST aprobado sin evento ni webhook; registros consultables sin autenticación. A3/A4. |
| P2 | La cadena de auditoría puede bifurcarse con concurrencia | Reproducido tanto con planificación controlada como en una ejecución normal de estrés. A5. |
| P2 | Auditoría incompleta ante errores y stdout incompatible con verificador | Excepción upstream sin evento; stdout genera secuencia 0 y sin encadenar. A6/A7. |
| P2 | Stdio no correlaciona mensajes/respuestas | Acepta ID distinto o notificación como respuesta. T-03/C-06, mismo defecto contado una sola vez. |
| P2 | Generación VS Code incorrecta y discovery sin paginación | Root `mcpServers` en vez de `servers`; `nextCursor` ignorado. C-01/C-05. |

Detalles: [seguridad](security.md), [aprobaciones y evidencia](approvals-audit.md), [stdio](stdio.md), [compatibilidad](compatibility.md).

## Promesa frente a implementación

| Promesa o expectativa | Resultado |
| --- | --- |
| Denegar antes de ejecutar | Funciona en rutas principales nativas; no es uniforme con decisiones externas/listas/métodos genéricos. |
| Aprobaciones de un solo uso | Funciona secuencialmente; hay una carrera de actualización SQLite que rompe la garantía global. |
| Decisiones de aprobación auditadas | CLI y UI no tienen comportamiento equivalente. |
| Auditoría estricta que impide acciones sin registro | El registro se escribe después del envío; incumplimiento confirmado. |
| Cadena verificable | Funciona en casos secuenciales de archivo; falla bajo una carrera de escritura y en stdout. |
| Límites de tamaño y timeout | La promesa debe restringirse o implementarse también en stdio. |
| Compatibilidad MCP | Subconjunto funcional, no conformidad completa: limitaciones de SSE ya documentadas; faltan otras de sesiones, multiplexación, negociación y paginación. |
| Configuración por cliente | Algunas salidas no respetan el esquema o los controles originales. |
| Prueba independiente de la llamada realmente ejecutada | No existe. El control del gateway y el log no prueban por sí solos el efecto producido en el destino. |

La vinculación actual incluye el identificador de política y servidor lógico, no un digest de su configuración. El hash de argumentos tampoco representa necesariamente todo el sobre reenviado. Son límites relevantes para evolucionar hacia recibos verificables, no motivos para afirmar que las comprobaciones existentes no tienen valor.

## Estado del arte y Grok

Se ha interpretado «actualizar el arte de todos los modelos» como actualizar estado del arte y compatibilidad. El repositorio **no invoca modelos ni mantiene un catálogo de versiones**: aplica políticas a MCP independientemente del modelo que use el cliente. Cambiar listas de nombres de modelos no resolvería estos fallos.

La mejora adecuada es una matriz fechada por cliente, transporte, autenticación y flujo de aprobación, con tres estados distintos: documentación disponible, pruebas locales de protocolo y prueba real del proveedor.

- **Grok Build:** añadir generador CLI/TOML y documentación de conexión HTTP/stdio.
- **xAI API:** añadir ejemplo MCP remoto autenticado; distinguirlo de Grok Build y documentar que `require_approval` del formato compatible con OpenAI no está soportado según la documentación de xAI revisada. La aprobación propia de MCPZT requiere un flujo de reintento probado.
- **Codex y Gemini CLI:** incorporar sus formatos específicos, sin tratarlos como JSON genérico.
- **VS Code, Cursor y Claude:** reparar formatos, preservar controles, documentar secretos mediante referencias y validar la secuencia de aprobación completa.
- **OpenAI Responses y Claude API:** ejemplos separados de clientes de escritorio; no confundir la aprobación del proveedor con la del gateway.

No se ha certificado conexión real con ninguno de estos proveedores ni realizado llamadas de pago. Las fuentes oficiales y diferencias concretas están en [compatibility.md](compatibility.md).

## Dependencias

`pip-audit` del entorno local informó 14 entradas, pero contiene duplicados: corresponden a **7 identificadores únicos en 2 paquetes**, no a 14 fallos del proyecto. Ver [dependency-findings.json](dependency-findings.json).

- `cryptography 49.0.0`: un aviso de descifrado PKCS#7, con corrección indicada en 50.0.0. No se ha identificado uso de esa función en MCPZT; no se afirma explotabilidad de esta aplicación.
- `pip 25.1.1`: seis avisos del instalador local. No es una dependencia runtime declarada de MCPZT. Actualizar las herramientas de construcción por separado y revisar aplicabilidad; algunos avisos dependen de versiones de Python o índices maliciosos.

Los avisos son resultados de la base consultada por pip-audit, pendientes de triage de alcance detallado; no deben mezclarse con los fallos funcionales reproducidos. Los constraints no son un lock completo y CI instala sin ellos, por lo que faltan garantías de repetir exactamente el entorno de publicación.

## Plan de mejoras y aceptación

### 1. Cumplir las decisiones y aislar clientes

Corregir S-01 a S-04 y A2. Añadir pruebas de decisiones explícitas sin metadatos opcionales, fallo OPA, métodos fuera de `CALL_METHODS`, claims sin fallback no confiable, sesiones de dos identidades y carreras entre revisión/consumo.

**Aceptación:** una denegación explícita nunca libera el resultado; una llamada pendiente de aprobación nunca se despacha; ninguna operación concurrente válida reactiva una aprobación terminal; ninguna identidad reutiliza una sesión ajena.

### 2. Auditoría fiel y consistente

Unificar CLI/UI; autenticar lectura de aprobaciones; preservar datos originales del revisor; añadir evento previo durable en modo estricto y resultado correlacionado; corregir bloqueo/flush y definir stdout. Incluir `approval_id`, digest de argumentos, dirección, fase y estado de resultado.

**Aceptación:** destino de auditoría inutilizable implica cero envíos en modo estricto; las cadenas verifican bajo concurrencia; cada intento tiene trazabilidad explícita. Los timeouts se registran como resultado desconocido cuando corresponda. No prometer transacciones exactamente una vez contra cualquier upstream.

### 3. Transportes y protocolo

Lecturas acotadas por bytes y deadline; dispatcher stdio por ID; paginación y negociación; ciclo de sesión HTTP y errores claros para capacidades no soportadas. Ensayos con servidor del SDK MCP real además de mocks.

**Aceptación:** inicialización, descubrimiento paginado, allow/deny, aprobación/reintento, errores, cancelación y notificaciones tienen pruebas de protocolo; no hay bloqueos indefinidos por tramas parciales.

### 4. Clientes y proveedores, incluido Grok

Generadores correctos, preservación segura de configuración y ejemplos por proveedor. Secretos por referencias, sin copiar credenciales en documentación. Pruebas offline por esquema y protocolo antes de etiquetar como compatible.

**Aceptación:** fixtures de Grok Build, Gemini, Codex, VS Code, Cursor y Claude; autenticación gateway documentada; matriz con estado real de pruebas y fecha. Pruebas cloud opcionales y separadas de CI normal.

### 5. Publicación y garantías

Actualizar README/PRODUCTION/SECURITY y notas de versión con límites reales. Incorporar regresiones de los defectos, rama/casos además de cobertura de líneas y controles de empaquetado/dependencias. La firma pública de recibos es una evolución posterior con modelo de confianza definido, no un parche que demuestre por sí solo la ejecución del destino.

**Aceptación:** toda garantía anunciada tiene una prueba identificable y limitaciones descritas. Una nueva versión solo se considera lista tras pasar las regresiones y el flujo de integración documentado.

## Cómo reproducir

```sh
.venv/bin/python docs/audit/reproduce_policy.py
.venv/bin/python docs/audit/reproduce_approvals.py
.venv/bin/python docs/audit/reproduce_stdio.py
```

Son observaciones diagnósticas de la versión auditada, no tests que deban perpetuar los defectos. Los casos deterministas deben convertirse en tests de regresión con el comportamiento correcto al acometer las mejoras.

## Límites de esta entrega

No se ha ejecutado la matriz Python completa 3.11–3.14, Windows, Docker/Kubernetes ni despliegues reales; solo Python 3.14.4 local. No hay fuzzing completo ni validación exhaustiva de cada SQL dialect, validador o condición. No se ha probado la compatibilidad de extremo a extremo con cuentas de proveedores. Una auditoría profunda reduce incertidumbre; no demuestra ausencia de otros fallos.
