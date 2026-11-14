# Detector360 — Escáner Forense Web Ciudadano Anti-Phishing

**Detector360** es una Progressive Web App (PWA) de análisis forense web en tiempo real desplegada 100% sobre el borde (**Cloudflare Edge**: Pages, Workers, D1, KV y R2). Combina **auditoría de capa de transporte (`HTTP/HTTPS`, TLS, redirecciones y cabeceras de seguridad)** con **análisis estático indexado por línea de código fuente (`DOM/HTML/JS`)** para detectar portales de *phishing*, captura de credenciales sin cifrar y scripts de exfiltración u ofuscación antes de que el ciudadano entregue sus datos.

---

## Arquitectura del Monorepo

```text
ProyectoAntiPhishing/
├── frontend/                         # PWA (Cloudflare Pages: HTML5, CSS3, ES6+, Service Worker)
│   ├── _headers                      # Cabeceras estrictas CSP, HSTS, X-Frame-Options, nosniff
│   ├── _redirects                    # Enrutamiento SPA limpio (/scan/:id, /dashboard, etc.)
│   ├── index.html                    # Interfaz accesible WCAG 2.1 AA (Cyber-Civic Shield)
│   ├── manifest.webmanifest          # Configuración PWA instalable + Web Share Target API
│   ├── sw.js                         # Service Worker (Cache-First estático + Network-First API)
│   ├── assets/                       # Isotipos vectoriales SVG (192x192 y 512x512 maskable)
│   ├── css/
│   │   ├── tokens.css                # Variables de diseño (paleta Hex, tipografías, escala 8px)
│   │   └── app.css                   # Layout mobile-first, visor Obsidiana #0B1120 y @media print PDF
│   └── js/
│       ├── app.js                    # Enrutador SPA, Web Share Target, formularios y vistas
│       ├── api-client.js             # Cliente fetch con cookies HttpOnly, anti-CSRF y auto-refresh
│       ├── forensic-viewer.js        # Renderizador forense 100% inmune a XSS (textContent puro)
│       ├── export-service.js         # Exportación JSON verificable SHA-256 e impresión PDF
│       └── offline-db.js             # Almacén local IndexedDB (últimos 30 análisis + cola offline)
├── worker/                           # API REST & Motor Forense (Cloudflare Workers + TypeScript 5.x)
│   ├── wrangler.toml                 # Bindings para D1 (DB), KV (KV_CACHE) y R2 (R2_EVIDENCE)
│   ├── tsconfig.json                 # Configuración TypeScript estricta
│   ├── migrations/
│   │   └── 0001_initial_schema.sql   # Esquema relacional 3FN en SQLite / Cloudflare D1
│   ├── src/
│   │   ├── index.ts                  # Entrypoint del Worker, middlewares y blindaje de errores
│   │   ├── router.ts                 # Enrutador REST sin dependencias externas
│   │   ├── middlewares/              # SecurityHeaders, CORS/CSRF, RateLimit (KV) y Auth JWT
│   │   ├── controllers/              # AuthController, ScanController y CommunityController
│   │   ├── services/                 # SsrfGuard, Transport, DomParser, JsAnalyzer, Scoring y Crypto
│   │   └── repositories/             # Persistencia parametrizada D1 (batch), KV (900s) y R2 (.txt)
│   └── tests/
│       └── forensic-security.test.ts # Suite de pruebas unitarias y de seguridad (Vitest)
├── .dev.vars.example                 # Plantilla de secretos locales para Wrangler
└── package.json
```

---

## Controles de Ciberseguridad Implementados

1. **Blindaje Anti-SSRF y Anti-DNS Rebinding (`ssrf-guard.service.ts`)**:
   - Acepta exclusivamente esquemas `http:` y `https:` en puertos web estándar (`80, 443, 8080, 8443`), rechazando credenciales embebidas (`user:pass@host`).
   - Bloquea rangos IPv4 e IPv6 privados/reservados (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `169.254.0.0/16` IMDS cloud, `::1`, `fc00::/7`, `fe80::/10` e IPv4-mapeadas `::ffff:127.0.0.1`).
   - Verifica previamente registros `A` y `AAAA` mediante **DNS-over-HTTPS (DoH)** y revalida cada salto de redirección HTTP (`redirect: 'manual'`, máx. 5 saltos, timeout 5s y tope estricto de lectura en streaming de **2 MB**).
2. **Inmunidad XSS en Visor Forense (`forensic-viewer.js` + CSP)**:
   - El código fuente capturado jamás se inserta con `innerHTML`; cada nodo y línea se construye mediante `document.createTextNode` / `textContent`.
   - Los snapshots opcionales en **Cloudflare R2** se almacenan escapados con `Content-Type: text/plain` y `Content-Disposition: attachment`.
3. **Autenticación Criptográfica Web Crypto (`crypto.service.ts`)**:
   - Contraseñas derivadas con **`PBKDF2-HMAC-SHA512` (210,000 iteraciones + salt CSPRNG de 16 bytes)** y comparación en tiempo constante (`timingSafeEqual`).
   - Tokens de acceso JWT **`HS256`** (15 min) + Refresh Tokens opacos rotativos (7 días, hasheados con `SHA-256` en D1) sobre cookies `__Host-d360_access` y `__Host-d360_refresh` (`HttpOnly; Secure; SameSite=Strict`) más cabecera anti-CSRF `X-Requested-With: Detector360-PWA`.
4. **Trazabilidad Forense Verificable (`integrity_sha256`)**:
   - Todo reporte exportado contiene `evidence_payload` determinista firmado con `SHA-256` para auditoría pericial por terceros.

---

## Guía de Instalación y Despliegue (Cloudflare)

### 1. Prerrequisitos
Instala **Node.js 20 LTS+** ([https://nodejs.org](https://nodejs.org)) y autentícate en Cloudflare:

```powershell
npm install
npx wrangler login
```

### 2. Aprovisionar Recursos Edge (D1, KV y R2)
Ejecuta los siguientes comandos una única vez y reemplaza los IDs generados en `worker/wrangler.toml`:

```powershell
npx wrangler d1 create detector360-db
npx wrangler kv namespace create KV_CACHE
npx wrangler kv namespace create KV_CACHE --preview
npx wrangler r2 bucket create detector360-evidence
```

### 3. Aplicar Migraciones SQL en D1 y Configurar Secretos

```powershell
# Entorno local:
Copy-Item .dev.vars.example worker\.dev.vars
npm run db:migrate:local

# Entorno de producción:
npm run db:migrate:prod
npx wrangler secret put JWT_SECRET --config worker/wrangler.toml
```

### 4. Desarrollo Local y Pruebas de Seguridad

```powershell
# Verificación estricta de tipos TypeScript y suite forense:
npm run typecheck
npm test

# Terminal 1 — Levantar API Forense en http://localhost:8787
npm run dev:worker

# Terminal 2 — Levantar PWA en http://localhost:8788 (con proxy hacia el Worker)
npm run dev:pages
```

### 5. Despliegue a Producción

```powershell
npm run deploy:worker
npm run deploy:pages
```
