/**
 * Detector360 — Precision Vector Icon System (UI/UX Pro Max)
 * 100% createElementNS (Zero innerHTML, Zero Emojis, Crisp 24x24 Stroke SVGs)
 */

const SVG_NS = 'http://www.w3.org/2000/svg';

const ICON_PATHS = {
  shieldCheck: [
    'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z',
    'm9 12 2 2 4-4',
  ],
  shieldAlert: [
    'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z',
    'M12 8v4',
    'M12 16h.01',
  ],
  alertTriangle: [
    'm21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z',
    'M12 9v4',
    'M12 17h.01',
  ],
  scanEye: [
    'M3 7V5a2 2 0 0 1 2-2h2',
    'M17 3h2a2 2 0 0 1 2 2v2',
    'M21 17v2a2 2 0 0 1-2 2h-2',
    'M7 21H5a2 2 0 0 1-2-2v-2',
    'M2 12s3.5-5 10-5 10 5 10 5-3.5 5-10 5-10-5-10-5Z',
    'M12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4Z',
  ],
  share2: [
    'M18 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z',
    'M6 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z',
    'M18 22a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z',
    'm8.59 13.51 6.83 3.98',
    'm15.41 6.51-6.82 3.98',
  ],
  download: [
    'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4',
    'm7 10 5 5 5-5',
    'M12 15V3',
  ],
  userPlus: [
    'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2',
    'M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z',
    'M19 8v6',
    'M22 11h-6',
  ],
  arrowRight: [
    'M5 12h14',
    'm12 5 7 7-7 7',
  ],
  checkCircle: [
    'M22 11.08V12a10 10 0 1 1-5.93-9.14',
    'm9 11 3 3L22 4',
  ],
  radar: [
    'M19.07 4.93A10 10 0 0 0 6.99 3.34',
    'M4 6h.01',
    'M2.29 9.62A10 10 0 1 0 21.31 8.35',
    'M16.24 7.76A6 6 0 1 0 8.23 16.67',
    'M12 18h.01',
    'M17.99 11.66A6 6 0 0 1 15.77 16.67',
    'M12 12l4.24-4.24',
  ],
};

export function createSvgIcon(name, size = 18) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('width', String(size));
  svg.setAttribute('height', String(size));
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '1.85');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('aria-hidden', 'true');
  svg.style.flexShrink = '0';

  const paths = ICON_PATHS[name] || ICON_PATHS.shieldCheck;
  for (const d of paths) {
    const p = document.createElementNS(SVG_NS, 'path');
    p.setAttribute('d', d);
    svg.appendChild(p);
  }
  return svg;
}
