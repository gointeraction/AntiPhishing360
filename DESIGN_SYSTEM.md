# Detector360 — UI/UX Pro Max Design System (`MASTER.md`)

> Basado en la metodología de inteligencia de diseño **`nextlevelbuilder/ui-ux-pro-max-skill`**: arquitectura de tokens en 3 capas, cero emojis como iconos estructurales, accesibilidad crítica WCAG AA/AAA, `prefers-reduced-motion` y patrones SaaS de Ciberseguridad de primer nivel.

---

## 1. Clasificación de Dominio y Estilo

- **Categoría de Producto**: Plataforma SaaS de Ciberseguridad Ciudadana & Escáner Forense en Tiempo Real (PLG + PWA).
- **Dirección Estética**: **Obsidian Cyber-Shield (Dark Mode OLED Tonal + Bento Architecture + Specular Glass)**.
- **Referencias de Nivel Mundial**: Cloudflare Zero Trust, Linear, Vercel Security, Raycast.
- **Principio Rector**: *Autoridad forense de grado militar en la superficie; calidez y claridad ciudadana absoluta en el mensaje.*

---

## 2. Arquitectura de Tokens de Color en 3 Capas

### Capa 1 — Primitivos
- `obsidian-950`: `#060B19` (Lienzo principal, evita `#000000` puro para reducir fatiga ocular halación)
- `slate-925`: `#0A1122` (Superficie secundaria / Bento sutil)
- `slate-900`: `#0F172A` (Superficie de tarjetas base)
- `slate-850`: `#152038` (Superficie interactiva / hover tonal)
- `slate-800`: `#1E293B` (Superficie elevada / popovers)
- `cyan-400`: `#00E5FF` (Acento primario cuántico)
- `indigo-500`: `#6366F1` (Acento secundario Edge)

### Capa 2 — Semánticos y Elevación Especular
- `--surface-canvas`: `#060B19`
- `--surface-card`: `#0F172A` + `inset 0 1px 0 rgba(255, 255, 255, 0.07)` (luz cenital especular de 1px)
- `--text-primary`: `#F8FAFC` (Contraste **18.5:1** — WCAG AAA)
- `--text-secondary`: `#94A3B8` (Contraste **7.4:1** — WCAG AAA)
- `--cta-bg`: `#00E5FF` con `--cta-fg`: `#020617` (Contraste **13.8:1** — WCAG AAA)
- Semáforo Forense:
  - `SAFE`: `#10B981` sobre `#052E24` (borde `rgba(52, 211, 153, 0.45)`)
  - `WARNING`: `#F59E0B` sobre `#361905` (borde `rgba(251, 191, 36, 0.45)`)
  - `CRITICAL`: `#EF4444` sobre `#3B0A10` (borde `rgba(248, 113, 113, 0.5)`)

---

## 3. Reglas Estrictas Anti-Patrones (UI/UX Pro Max)

1. **Cero Emojis como Iconos de UI**: Prohibido usar emojis Unicode (`🔒`, `🚨`, `📋`, etc.). Todos los iconos son vectores SVG escalables (`24x24`, `stroke="currentColor"`, `stroke-width="1.75"`).
2. **Navbar Flotante Desacoplada**: Barra translúcida flotante (`top: 16px`, `border-radius: 16px`, `backdrop-filter: blur(18px)`) separada de los bordes del viewport.
3. **Números Tabulares (`tabular-nums`)**: Obligatorio en métricas en vivo, puntajes de riesgo `0-100`, precios y numeración de líneas de código para evitar micro-saltos horizontales.
4. **Cero Layout Shift en Hover**: Ningún estado `:hover` o `:focus` modifica `border-width`, `padding` o `font-weight`; solo se animan `transform`, `opacity`, `background-color`, `border-color` y `box-shadow`.
5. **Objetivos Táctiles $\ge 44\text{px}$ y `prefers-reduced-motion`**: Todo control interactivo respeta altura táctil cómoda y desactiva animaciones automáticamente cuando el sistema operativo solicita reducción de movimiento.
