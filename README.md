# Detector360 — Plataforma Comercial Anti-Phishing & Módulo Estratégico C.I.C.P.C

**Detector360** es una plataforma web comercial, Progressive Web App (PWA) de protección ciudadana anti-phishing y **Centro de Comando e Inteligencia Forense para la División de Investigaciones de Delitos Informáticos (C.I.C.P.C)**, impulsada por la arquitectura **Cloudflare Edge** (`Cloudflare Pages` + `Cloudflare Workers` + `D1` + `KV` + `R2`).

---

## Arquitectura y Módulos Incluidos

- **Motor Forense Híbrido "Rayos X Web" (`worker/src/services/`)**: Inspección en `< 2.5s` de transporte HTTP/HTTPS, cabeceras TLS (`HSTS`, `CSP`, `X-Frame-Options`), formularios DOM (`<form action>`, `<input>`) y scripts maliciosos (`keyloggers` / exfiltración), sellando cada reporte con huella criptográfica `SHA-256`.
- **Portada Comercial "Corporate Cyber Defense & Holographic Tech" (`frontend/index.html`)**:
  - Hero cinematográfico Widescreen `100svh` con streaming `HTTP 206 Partial Content`.
  - Escáner forense gratuito en vivo sin registro previo.
  - Simulador interactivo de Rayos X del Código, Bento Grid educativo de las 6 estafas más frecuentes, Muro de Amenazas en Vivo conectado a D1 y Planes Freemium.
  - Bloque institucional al pie de página con emblema oficial de la División de Investigaciones de Delitos Informáticos (**C.I.C.P.C**).
- **Flujo Ciudadano Completo y PWA**:
  - `/login`, `/register`, `/dashboard`, `/scan/new` y `/scan/:id` con envío directo de **Denuncias / Notificaciones Ciudadanas al C.I.C.P.C** (`EXP-DIDI-2026-...`).
- **Módulo Independiente de Acceso Restringido C.I.C.P.C (`/cicpc/login` y `/cicpc`)**:
  - Autenticación multifactor institucional de **3 factores criptográficos** (Credencial Oficial + Contraseña Operativa `PBKDF2-HMAC-SHA512` 210.000 iteraciones + Clave Maestra Institucional `SHA-256`).
  - Sala situacional con 6 KPIs nacionales, **Radar de Campañas Coordinadas por Dominio**, bandeja filtrable de denuncias, inspector forense completo, ejecución de **Acciones Estratégicas** (*Bloqueo DNS ISP/CONATEL*, *Alerta Interbancaria SUDEBAN*, *Takedown Internacional*, *Rastreo C2/IP*, *Investigación Penal*) y bitácora inmutable de cadena de custodia.

---

## Ejecución Local Instantánea (Node.js 22.6+ / 26)

```powershell
# 1. Iniciar servidor local Cloudflare Edge Simulator (http://localhost:8788)
node dev-server.ts

# 2. Ejecutar las 14 pruebas integrales de arquitectura, seguridad y producto
node tests/verify-all.ts
```

---

## Despliegue en Producción (Cloudflare)

```bash
# 1. Aplicar migraciones SQL (0001, 0002 y 0003) en Cloudflare D1
npx wrangler d1 migrations apply detector360-db --remote --config worker/wrangler.toml

# 2. Configurar secretos criptográficos en Cloudflare Workers
npx wrangler secret put JWT_SECRET --config worker/wrangler.toml
npx wrangler secret put CICPC_MASTER_KEY --config worker/wrangler.toml

# 3. Desplegar API Forense y Módulo C.I.C.P.C en Cloudflare Workers
npx wrangler deploy --config worker/wrangler.toml

# 4. Desplegar Frontend Comercial y PWA en Cloudflare Pages
npx wrangler pages deploy frontend --project-name=antiphishing360
```
