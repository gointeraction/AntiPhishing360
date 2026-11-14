import { showToast } from './api-client.js';

let deferredInstallPrompt = null;

export function initPwaSupport(onSharedUrlDetected) {
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('/sw.js').catch(() => {});
    });
  }

  window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredInstallPrompt = e;
    const banner = document.getElementById('pwa-floating-banner');
    if (banner && !sessionStorage.getItem('d360_pwa_dismissed')) {
      banner.classList.add('visible');
    }
  });

  // Bind all install trigger buttons across page
  document.querySelectorAll('[data-pwa-install]').forEach((btn) => {
    btn.addEventListener('click', () => triggerPwaInstallFlow());
  });

  const dismissBtn = document.getElementById('pwa-banner-dismiss');
  if (dismissBtn) {
    dismissBtn.addEventListener('click', () => {
      sessionStorage.setItem('d360_pwa_dismissed', '1');
      document.getElementById('pwa-floating-banner')?.classList.remove('visible');
    });
  }

  // Close PWA guide modal if present
  const guideClose = document.getElementById('pwa-guide-close');
  const guideModal = document.getElementById('pwa-guide-modal');
  if (guideClose && guideModal) {
    guideClose.addEventListener('click', () => guideModal.classList.remove('active'));
    guideModal.addEventListener('click', (ev) => {
      if (ev.target === guideModal) guideModal.classList.remove('active');
    });
  }

  // Handle Web Share Target (?shared_url=... or ?shared_text=...)
  const params = new URLSearchParams(window.location.search);
  const sharedUrl = params.get('shared_url') || '';
  const sharedText = params.get('shared_text') || '';
  const candidate = extractFirstUrl(sharedUrl || sharedText);
  if (candidate && typeof onSharedUrlDetected === 'function') {
    onSharedUrlDetected(candidate);
  }
}

export async function triggerPwaInstallFlow() {
  if (deferredInstallPrompt) {
    deferredInstallPrompt.prompt();
    const choice = await deferredInstallPrompt.userChoice;
    if (choice.outcome === 'accepted') {
      showToast('¡Escudo Detector360 instalado en tu dispositivo!');
      document.getElementById('pwa-floating-banner')?.classList.remove('visible');
    }
    deferredInstallPrompt = null;
    return;
  }

  // Show visual 2-step guide modal for Android & iPhone
  const guideModal = document.getElementById('pwa-guide-modal');
  if (guideModal) {
    guideModal.classList.add('active');
  } else {
    showToast(
      'En tu móvil: abre el menú del navegador y pulsa "Instalar aplicación" o "Agregar a Inicio".'
    );
  }
}

function extractFirstUrl(text) {
  if (!text) return '';
  const match = text.match(/https?:\/\/[^\s"'<>]+/i);
  return match ? match[0] : '';
}
