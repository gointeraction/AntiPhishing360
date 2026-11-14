import { showToast } from './api-client.js';

export class ExportService {
  static downloadJsonEvidence(report) {
    if (!report) return;
    const exportEnvelope = {
      platform: 'Detector360 Forensic Edge Shield',
      schema_version: '1.0',
      exported_at: new Date().toISOString(),
      integrity_sha256: report.integrity_sha256,
      report,
    };

    const blob = new Blob([JSON.stringify(exportEnvelope, null, 2)], {
      type: 'application/json;charset=utf-8',
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `detector360-evidencia-${report.scan_id}.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    showToast('Evidencia forense JSON (con sello SHA-256) descargada.');
  }

  static printPdfReport() {
    window.print();
  }

  static buildCitizenShareSummary(report) {
    const safeDomain = (report.target_domain || '').replace(/\./g, '[.]');
    const levelLabel =
      report.risk_level === 'CRITICAL'
        ? '🔴 PELIGRO CRÍTICO'
        : report.risk_level === 'WARNING'
        ? '🟡 PRECAUCIÓN'
        : '🟢 SITIO SEGURO';

    const reportLink = `${window.location.origin}/scan/${encodeURIComponent(report.scan_id)}`;
    return [
      `🛡️ Alerta Ciudadana Detector360: ${levelLabel} (Puntaje ${report.risk_score}/100)`,
      `Sitio revisado: ${safeDomain}`,
      `Veredicto: ${report.citizen_verdict?.title || ''}`,
      `Ver reporte completo: ${reportLink}`,
    ].join('\n');
  }

  static async copyAlertSummary(report) {
    const summary = this.buildCitizenShareSummary(report);
    try {
      await navigator.clipboard.writeText(summary);
      showToast('Resumen preventivo copiado al portapapeles.');
    } catch {
      showToast('No se pudo copiar automáticamente, usa el botón de WhatsApp.', true);
    }
  }

  static shareOnWhatsApp(report) {
    const summary = this.buildCitizenShareSummary(report);
    const waUrl = `https://wa.me/?text=${encodeURIComponent(summary)}`;
    window.open(waUrl, '_blank', 'noopener,noreferrer');
  }
}
