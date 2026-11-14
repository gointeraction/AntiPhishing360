# Catálogo Técnico de Reglas Forenses — Detector360

Este documento resume las reglas deterministas del motor híbrido implementado en `worker/src/services/` y su ponderación en `ScoringService`.

| Código de Regla | Categoría | Severidad | Peso Base | Descripción Técnica |
| --- | --- | --- | --- | --- |
| `JS_C2_WEBHOOK_EXFILTRATION` | `JS_SCRIPT` | `CRITICAL` | 75 | Exfiltración directa hacia bots de Telegram (`api.telegram.org/bot...`) o webhooks de Discord embebidos en JS cliente. |
| `INSECURE_HTTP_SENSITIVE_FORM` | `DOM_FORM` | `CRITICAL` | 62 | Etiqueta `<form>` con campos sensibles servida sobre `http://` o con atributo `action="http://..."`. |
| `INSECURE_HTTP_SENSITIVE_INPUT` | `DOM_INPUT` | `CRITICAL` | 58 | Campo `<input>` sensible huérfano (fuera de `<form>`) servido sin cifrado TLS. |
| `JS_ASYNC_EXFILTRATION` | `JS_SCRIPT` | `CRITICAL` | 58 | Listeners de captura (`keyup`, `keydown`, `blur`, `change`, `submit`) combinados con `fetch()`, `XMLHttpRequest`, `sendBeacon` o `WebSocket` hacia dominios externos. |
| `CROSS_DOMAIN_FORM_ACTION` | `DOM_FORM` | `CRITICAL` / `HIGH` | 55 | El atributo `action` del formulario envía datos hacia un dominio raíz distinto al origen visitado (excluyendo pasarelas en lista blanca sobre HTTPS). |
| `MAILTO_FORM_EXFILTRATION` | `DOM_FORM` | `CRITICAL` | 55 | Formulario con credenciales apuntando a esquema `mailto:`. |
| `HTTPS_TO_HTTP_DOWNGRADE` | `TRANSPORT` | `CRITICAL` | 52 | La cadena de redirección `301/302` degrada una URL `https://` inicial hacia un destino `http://`. |
| `PLAINTEXT_PASSWORD_FIELD` | `DOM_INPUT` | `CRITICAL` | 45 | Nodo `<input type="password">` expuesto en página sin transporte HTTPS. |
| `PUNYCODE_HOMOGRAPH_DOMAIN` | `TRANSPORT` | `HIGH` | 38 | Dominio internacionalizado con prefijo ACE `xn--` susceptible a ataques homográficos IDN. |
| `JS_OBFUSCATION_DETECTED` | `JS_SCRIPT` | `CRITICAL` / `HIGH` | 36 | Uso de `eval(`, `Function(`, `atob(`, `String.fromCharCode` masivo o literales Base64/Hex > 100 caracteres. |
| `RAW_IP_HOST_PHISHING` | `TRANSPORT` | `HIGH` | 35 | Sitio servido directamente sobre dirección IPv4 numérica sin dominio DNS institucional. |
| `UNMASKED_PASSWORD_INPUT` | `DOM_INPUT` | `HIGH` | 32 | Campo identificado como contraseña, clave, PIN o CVV configurado con `type="text"` sin enmascarar. |
| `INSECURE_HTTP_TRANSPORT` | `TRANSPORT` | `HIGH` | 32 | Recurso web servido en texto plano sobre protocolo `http://`. |
| `SUSPICIOUS_EXTERNAL_SCRIPT_HOST` | `JS_SCRIPT` | `HIGH` | 32 | Inclusión `<script src="...">` desde IP literal externa o TLDs de alto abuso (`.xyz`, `.top`, `.click`, `.tk`, `.zip`, `.icu`, `.su`). |
| `MIXED_CONTENT_INSECURE_SCRIPT` | `JS_SCRIPT` | `HIGH` | 30 | Página `https://` que incluye un script externo vía `http://`. |
| `SUSPICIOUS_REDIRECT_CHAIN` | `TRANSPORT` | `MEDIUM` | 18 | Múltiples redirecciones atravesando dominios registrables distintos. |
| `JS_ANTI_INSPECTION` | `JS_SCRIPT` | `MEDIUM` | 16 | Bloqueo deliberado de menú contextual (`contextmenu`), tecla `F12` o trampa `debugger`. |
| `SUSPICIOUS_HIDDEN_INPUT` | `DOM_INPUT` | `MEDIUM` / `LOW` | 15 | Campos `<input type="hidden">` con URLs de redirección externa o tokens extensos sospechosos. |
| `MISSING_SECURITY_HEADERS` | `TRANSPORT` | `LOW` | 8 | Ausencia de 2 o más cabeceras defensivas (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`). |
| `TRUSTED_EXTERNAL_FORM_PROVIDER` | `DOM_FORM` | `LOW` | 0 | Envío cross-domain sobre HTTPS hacia proveedor de autenticación/pagos reconocido en lista blanca. |

## Umbrales del Semáforo Ciudadano
- **`0 – 29` (`SAFE` — Verde)**: Bajo riesgo / Sitio con cifrado activo y sin patrones maliciosos detectados.
- **`30 – 69` (`WARNING` — Amarillo)**: Precaución / Deficiencias de cifrado HTTP o advertencias estructurales.
- **`70 – 100` (`CRITICAL` — Rojo)**: Peligro Crítico / Estructura de phishing, captura de credenciales sin cifrado o exfiltración activa.
