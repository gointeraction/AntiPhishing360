import { OfflineDb } from './offline-db.js';

async function computeSha256Hex(input) {
  const encoded = new TextEncoder().encode(input);
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export const ExportService = {
  /**
   * Recomputes SHA-256 over reportData.evidence_payload using Web Crypto API
   * and verifies exact match against reportData.integrity_sha256.
   */
  async verifyReportIntegrity(reportData) {
    if (!reportData || !reportData.evidence_payload || !reportData.integrity_sha256) {
      return { valid: false, computedHash: null, expectedHash: reportData?.integrity_sha256 || null };
    }
    const canonicalString = JSON.stringify(reportData.evidence_payload);
    const computedHash = await computeSha256Hex(canonicalString);
    return {
      valid: computedHash === reportData.integrity_sha256,
      computedHash,
      expectedHash: reportData.integrity_sha256
    };
  },

  /**
   * Exports a verifiable, strictly JSON-encoded forensic report file (.json).
   */
  async downloadForensicJson(reportData) {
    if (!reportData) return;

    const exportPackage = {
      schema_version: 'detector360.forensic.v1',
      generated_by: 'Detector360 — Escáner Forense Web Ciudadano',
      exported_at_utc: new Date().toISOString(),
      verification_instructions:
        'Para verificar la integridad criptográfica, calcule SHA-256 sobre JSON.stringify(evidence_payload) sin espacios adicionales y compárelo con integrity_sha256.',
      scan_summary: {
        scan_id: reportData.scan_id,
        target_url: reportData.target_url,
        final_url: reportData.final_url,
        target_domain: reportData.target_domain,
        scanned_at: reportData.scanned_at,
        duration_ms: reportData.duration_ms,
        risk_score: reportData.risk_score,
        risk_level: reportData.risk_level,
        citizen_verdict: reportData.citizen_verdict,
        transport_audit: reportData.transport_audit
      },
      findings_detail: reportData.findings,
      source_preview: reportData.source_preview,
      evidence_payload: reportData.evidence_payload,
      integrity_sha256: reportData.integrity_sha256
    };

    const jsonString = JSON.stringify(exportPackage, null, 2);
    const blob = new Blob([jsonString], { type: 'application/json;charset=utf-8' });
    const blobUrl = URL.createObjectURL(blob);

    const safeDomain = (reportData.target_domain || 'sitio')
      .replace(/[^a-zA-Z0-9.-]/g, '_')
      .slice(0, 40);
    const fileName = `Detector360_Evidencia_${safeDomain}_${reportData.scan_id}.json`;

    const link = document.createElement('a');
    link.href = blobUrl;
    link.download = fileName;
    document.body.appendChild(link);
    link.click();
    link.remove();

    setTimeout(() => URL.revokeObjectURL(blobUrl), 3000);
    await OfflineDb.incrementExportCount();
  },

  /**
   * Triggers the clean @media print Citizen Forensic PDF report view.
   */
  async printForensicPdf() {
    await OfflineDb.incrementExportCount();
    window.print();
  }
};
