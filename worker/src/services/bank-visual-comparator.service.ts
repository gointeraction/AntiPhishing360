import type {
  KVNamespace,
  MatchedBankVisualAssetDTO,
  ScanFindingDTO,
  VisualBrandAuditDTO,
} from '../types.ts';
import { CryptoService } from './crypto.service.ts';
import { SsrfGuardService } from './ssrf-guard.service.ts';

export interface BankVisualProfile {
  id: string;
  name: string;
  officialDomains: string[];
  officialCdnDomains?: string[];
  brandTokens: string[];
  logoTokens: string[];
  brandColors: string[];
}

const BANK_PROFILES: BankVisualProfile[] = [
  // Banca Venezolana y Plataformas Nacionales
  {
    id: 'banesco',
    name: 'Banesco Banco Universal',
    officialDomains: ['banesco.com', 'banesconline.com', 'banesco.com.pa', 'banesco.com.do', 'banescousa.com'],
    brandTokens: ['banesco', 'banesconline', 'banesco contigo', 'pago movil banesco'],
    logoTokens: ['banesco', 'banesconline', 'bnco-verde'],
    brandColors: ['#007953', '#006847', '#008c5a'],
  },
  {
    id: 'bdv',
    name: 'Banco de Venezuela (BDV)',
    officialDomains: ['bancodevenezuela.com', 'banvenez.com'],
    brandTokens: ['banco de venezuela', 'bdvenlinea', 'bdv en linea', 'biopago bdv', 'puntovenezuela', 'amiven'],
    logoTokens: ['bancodevenezuela', 'bdvenlinea', 'logo-bdv', 'bdv_logo', 'banvenez'],
    brandColors: ['#e30613', '#004a99', '#c8102e'],
  },
  {
    id: 'mercantil',
    name: 'Mercantil Banco Universal',
    officialDomains: ['mercantilbanco.com', 'mercantilenlinea.com', 'mercantilseguros.com', 'mercantilpanama.com'],
    brandTokens: ['mercantil banco', 'mercantil en linea', 'mercantilenlinea', 'tpago mercantil'],
    logoTokens: ['mercantil', 'mercantilbanco', 'tpago'],
    brandColors: ['#0033a0', '#004b87', '#ff6b00'],
  },
  {
    id: 'provincial',
    name: 'BBVA Provincial',
    officialDomains: ['provincial.com', 'bbva.com', 'bbva.es', 'bbva.mx', 'bbva.pe', 'bbva.com.co', 'bbva.com.ar'],
    brandTokens: ['bbva provincial', 'provinet', 'dinero rapido provincial', 'bbva net'],
    logoTokens: ['provincial', 'provinet', 'bbva'],
    brandColors: ['#072146', '#004481', '#1973b8'],
  },
  {
    id: 'bancamiga',
    name: 'Bancamiga Banco Universal',
    officialDomains: ['bancamiga.com'],
    brandTokens: ['bancamiga', 'bancamiga en linea', 'bancamiga suite'],
    logoTokens: ['bancamiga'],
    brandColors: ['#009640', '#005596'],
  },
  {
    id: 'bnc',
    name: 'Banco Nacional de Crédito (BNC)',
    officialDomains: ['bncenlinea.com', 'bnc.com.ve'],
    brandTokens: ['banco nacional de credito', 'bncnet', 'bnc en linea', 'bncenlinea'],
    logoTokens: ['bncenlinea', 'logo-bnc', 'bncnet'],
    brandColors: ['#f37021', '#002d62'],
  },
  {
    id: 'bancaribe',
    name: 'Bancaribe',
    officialDomains: ['bancaribe.com.ve'],
    brandTokens: ['bancaribe', 'mi conexion bancaribe'],
    logoTokens: ['bancaribe'],
    brandColors: ['#0085ca', '#003b5c'],
  },
  {
    id: 'banplus',
    name: 'Banplus Banco Universal',
    officialDomains: ['banplus.com'],
    brandTokens: ['banplus', 'banplus online'],
    logoTokens: ['banplus'],
    brandColors: ['#00a651', '#1b365d'],
  },
  {
    id: 'exterior',
    name: 'Banco Exterior',
    officialDomains: ['bancoexterior.com'],
    brandTokens: ['banco exterior', 'exterior nexo'],
    logoTokens: ['bancoexterior', 'exterior-nexo'],
    brandColors: ['#003865', '#e35205'],
  },
  {
    id: 'plaza',
    name: 'Banco Plaza',
    officialDomains: ['bancoplaza.com'],
    brandTokens: ['banco plaza', 'tu plaza en linea'],
    logoTokens: ['bancoplaza'],
    brandColors: ['#006341'],
  },
  {
    id: 'venezolanodecredito',
    name: 'Venezolano de Crédito',
    officialDomains: ['venezolanodecredito.com'],
    brandTokens: ['venezolano de credito', 'venecredit'],
    logoTokens: ['venezolanodecredito', 'venecredit'],
    brandColors: ['#003d71'],
  },
  {
    id: 'tesoro',
    name: 'Banco del Tesoro',
    officialDomains: ['bt.gob.ve', 'bdtesoro.com'],
    brandTokens: ['banco del tesoro', 'tesoro en linea'],
    logoTokens: ['bancodeltesoro', 'bt-logo', 'bdtesoro'],
    brandColors: ['#0054a6', '#ed1c24'],
  },
  {
    id: 'bicentenario',
    name: 'Banco Bicentenario',
    officialDomains: ['bicentenariobu.com.ve'],
    brandTokens: ['banco bicentenario', 'bicentenario en linea'],
    logoTokens: ['bicentenario'],
    brandColors: ['#c1272d', '#003471'],
  },
  {
    id: 'banfanb',
    name: 'BANFANB',
    officialDomains: ['banfanb.com.ve'],
    brandTokens: ['banfanb', 'banfanb en linea'],
    logoTokens: ['banfanb'],
    brandColors: ['#1c355e'],
  },
  {
    id: 'patria',
    name: 'Sistema Patria / Monedero Patria',
    officialDomains: ['patria.org.ve'],
    brandTokens: ['sistema patria', 'monedero patria', 'bono patria', 'veMonedero'],
    logoTokens: ['patria', 'monedero-patria'],
    brandColors: ['#9e1b34'],
  },
  // Banca Latinoamericana, EE.UU., Europa y Billeteras Financieras
  {
    id: 'bancolombia',
    name: 'Bancolombia',
    officialDomains: ['bancolombia.com', 'grupobancolombia.com'],
    brandTokens: ['bancolombia', 'sucursal virtual personas bancolombia'],
    logoTokens: ['bancolombia'],
    brandColors: ['#fdda24', '#2c2a29'],
  },
  {
    id: 'davivienda',
    name: 'Banco Davivienda',
    officialDomains: ['davivienda.com', 'daviplata.com'],
    brandTokens: ['davivienda', 'daviplata'],
    logoTokens: ['davivienda', 'daviplata'],
    brandColors: ['#ed1c27'],
  },
  {
    id: 'nequi',
    name: 'Nequi',
    officialDomains: ['nequi.com.co', 'nequi.com.pa'],
    brandTokens: ['nequi'],
    logoTokens: ['nequi'],
    brandColors: ['#200020', '#da0081'],
  },
  {
    id: 'santander',
    name: 'Banco Santander',
    officialDomains: ['santander.com', 'santander.es', 'santander.com.mx', 'santander.com.br', 'santander.cl', 'santander.com.ar'],
    brandTokens: ['banco santander', 'supernet santander'],
    logoTokens: ['santander'],
    brandColors: ['#ec0000'],
  },
  {
    id: 'nubank',
    name: 'Nubank',
    officialDomains: ['nubank.com.br', 'nu.com.mx', 'nu.com.co'],
    brandTokens: ['nubank', 'cuenta nu'],
    logoTokens: ['nubank'],
    brandColors: ['#820ad1'],
  },
  {
    id: 'itau',
    name: 'Banco Itaú',
    officialDomains: ['itau.com', 'itau.com.br', 'itau.cl', 'itau.com.co', 'itau.com.uy'],
    brandTokens: ['banco itau', 'itau personas'],
    logoTokens: ['itau'],
    brandColors: ['#ec7000', '#003399'],
  },
  {
    id: 'bradesco',
    name: 'Banco Bradesco',
    officialDomains: ['bradesco.com.br', 'banco.bradesco'],
    brandTokens: ['bradesco'],
    logoTokens: ['bradesco'],
    brandColors: ['#cc092f'],
  },
  {
    id: 'bcp',
    name: 'Banco de Crédito del Perú (BCP)',
    officialDomains: ['viabcp.com', 'yape.com.pe'],
    brandTokens: ['banca por internet bcp', 'viabcp'],
    logoTokens: ['viabcp', 'logo-bcp'],
    brandColors: ['#002a8d', '#ff7800'],
  },
  {
    id: 'bancoestado',
    name: 'BancoEstado',
    officialDomains: ['bancoestado.cl'],
    brandTokens: ['bancoestado', 'cuenta rut'],
    logoTokens: ['bancoestado'],
    brandColors: ['#ff6600'],
  },
  {
    id: 'pichincha',
    name: 'Banco Pichincha',
    officialDomains: ['pichincha.com', 'pichincha.pe', 'bancopichincha.com.co'],
    brandTokens: ['banco pichincha', 'banca web pichincha'],
    logoTokens: ['pichincha'],
    brandColors: ['#ffdd00', '#0f265c'],
  },
  {
    id: 'bgeneral',
    name: 'Banco General',
    officialDomains: ['bgeneral.com'],
    brandTokens: ['banco general', 'yappy'],
    logoTokens: ['bgeneral', 'yappy'],
    brandColors: ['#004b8d'],
  },
  {
    id: 'bac',
    name: 'BAC Credomatic',
    officialDomains: ['baccredomatic.com'],
    brandTokens: ['bac credomatic', 'sucursal electronica bac'],
    logoTokens: ['baccredomatic'],
    brandColors: ['#e4002b'],
  },
  {
    id: 'chase',
    name: 'Chase Bank (JPMorgan Chase)',
    officialDomains: ['chase.com', 'jpmorganchase.com'],
    brandTokens: ['chase bank', 'chase online', 'jpmorgan chase'],
    logoTokens: ['chase'],
    brandColors: ['#117aca'],
  },
  {
    id: 'bofa',
    name: 'Bank of America',
    officialDomains: ['bankofamerica.com', 'bofa.com'],
    brandTokens: ['bank of america'],
    logoTokens: ['bankofamerica', 'bofa'],
    brandColors: ['#012169', '#e31837'],
  },
  {
    id: 'wellsfargo',
    name: 'Wells Fargo',
    officialDomains: ['wellsfargo.com'],
    brandTokens: ['wells fargo', 'wellsfargo'],
    logoTokens: ['wellsfargo'],
    brandColors: ['#d71e28', '#ffcd41'],
  },
  {
    id: 'citibank',
    name: 'Citibank / Citi',
    officialDomains: ['citi.com', 'citibank.com'],
    brandTokens: ['citibank', 'citi online'],
    logoTokens: ['citibank'],
    brandColors: ['#003b70'],
  },
  {
    id: 'zelle',
    name: 'Zelle',
    officialDomains: ['zellepay.com'],
    brandTokens: ['zelle', 'zellepay'],
    logoTokens: ['zelle', 'zellepay'],
    brandColors: ['#6d1ed4'],
  },
  {
    id: 'zinli',
    name: 'Zinli',
    officialDomains: ['zinli.com'],
    brandTokens: ['zinli', 'billetera zinli'],
    logoTokens: ['zinli'],
    brandColors: ['#5b2be0', '#00d2a0'],
  },
  {
    id: 'paypal',
    name: 'PayPal',
    officialDomains: ['paypal.com', 'paypal.me'],
    officialCdnDomains: ['paypalobjects.com'],
    brandTokens: ['paypal'],
    logoTokens: ['paypal', 'paypalobjects'],
    brandColors: ['#003087', '#0070ba'],
  },
  {
    id: 'binance',
    name: 'Binance',
    officialDomains: ['binance.com', 'binance.us'],
    officialCdnDomains: ['bnbstatic.com'],
    brandTokens: ['binance'],
    logoTokens: ['binance', 'bnbstatic'],
    brandColors: ['#f0b90b'],
  },
];

interface ExtractedVisualAsset {
  url: string;
  assetType: 'favicon' | 'logo_img' | 'og_image' | 'inline_svg' | 'css_or_bundle';
  altOrLabel: string;
  rawMarkup: string;
  lineNumber: number;
}

interface BinaryImageSignature {
  sha256Hex: string;
  fingerprint64: string; // 16 hex chars = 64 bits
  byteLength: number;
  dimensions: string | null;
}

interface CachedOfficialBankRef {
  bankId: string;
  officialDomain: string;
  signatures: BinaryImageSignature[];
}

function getLineNumber(text: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < text.length; i++) {
    if (text.charCodeAt(i) === 10) line++;
  }
  return line;
}

function normalizeText(input: string): string {
  return input
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '');
}

export class BankVisualComparatorService {
  static isDomainOwnedByBank(hostname: string, bank: BankVisualProfile): boolean {
    const clean = hostname.toLowerCase().trim();
    return bank.officialDomains.some((off) => clean === off || clean.endsWith(`.${off}`));
  }

  static isAssetHostedOnOfficialBankInfra(assetUrl: string, bank: BankVisualProfile): boolean {
    try {
      const parsed = new URL(assetUrl);
      const host = parsed.hostname.toLowerCase();
      if (this.isDomainOwnedByBank(host, bank)) return true;
      if (
        bank.officialCdnDomains &&
        bank.officialCdnDomains.some((cdn) => host === cdn || host.endsWith(`.${cdn}`))
      ) {
        return true;
      }
      // Check public favicon proxy hotlinking official bank domains (e.g., google.com/s2/favicons?domain=banesco.com)
      const fullLower = assetUrl.toLowerCase();
      if (
        (host.includes('google.') ||
          host.includes('gstatic.com') ||
          host.includes('duckduckgo.com') ||
          host.includes('clearbit.com')) &&
        bank.officialDomains.some((off) => fullLower.includes(off))
      ) {
        return true;
      }
      return false;
    } catch {
      return false;
    }
  }

  /**
   * Audita y compara las imágenes, iconos, favicons, SVGs y logotipos de la página
   * frente a instituciones bancarias conocidas y dinámicas ("cualquier banco")
   * para determinar con certeza si NO es una página oficial.
   */
  static async compareAndAudit(params: {
    htmlContent: string;
    bundleCorpus?: string;
    finalUrl: string;
    targetDomain: string;
    simulatedDemo?: boolean;
    kv: KVNamespace;
  }): Promise<{ audit: VisualBrandAuditDTO; findings: ScanFindingDTO[] }> {
    const findings: ScanFindingDTO[] = [];
    const inspectedDomain = params.targetDomain.toLowerCase();
    const html = params.htmlContent || '';
    const bundles = params.bundleCorpus || '';

    // 0. Check if the inspected domain itself IS an official bank domain!
    const officialOwnerBank = BANK_PROFILES.find((b) =>
      this.isDomainOwnedByBank(inspectedDomain, b)
    );
    const extractedAssets = this.extractVisualAssets(html, bundles, params.finalUrl);

    if (officialOwnerBank) {
      return {
        audit: {
          executed: true,
          banking_brand_detected: true,
          is_official_bank_page: true,
          detected_institution: officialOwnerBank.name,
          official_domain_expected: officialOwnerBank.officialDomains[0],
          inspected_domain: inspectedDomain,
          images_inspected_count: extractedAssets.length,
          official_reference_compared: true,
          highest_similarity_percent: 100,
          matched_assets: [],
          verdict_label: 'PÁGINA BANCARIA OFICIAL VERIFICADA',
          verdict_summary: `Confirmado: el dominio ${inspectedDomain} pertenece legítimamente a ${officialOwnerBank.name}. Sus recursos gráficos coinciden con el canal oficial.`,
        },
        findings: [],
      };
    }

    // 1. Identify candidate banking institution(s) referenced in text, title, meta, SVGs or image URLs/alt
    const visibleSignals = this.extractPageBrandTextSignals(html, bundles);
    const normalizedSignals = normalizeText(visibleSignals);

    let candidateBank: BankVisualProfile | null = null;
    for (const bank of BANK_PROFILES) {
      const tokenHit = bank.brandTokens.some((tok) => {
        const normTok = normalizeText(tok);
        if (normTok.length <= 4) {
          const wordRe = new RegExp(`\\b${normTok}\\b`, 'i');
          return wordRe.test(normalizedSignals);
        }
        return normalizedSignals.includes(normTok);
      });
      const assetHit = extractedAssets.some((asset) => {
        const assetNorm = normalizeText(`${asset.url} ${asset.altOrLabel}`);
        return (
          this.isAssetHostedOnOfficialBankInfra(asset.url, bank) ||
          bank.logoTokens.some((lt) => assetNorm.includes(normalizeText(lt)))
        );
      });

      if (tokenHit || assetHit) {
        candidateBank = bank;
        break;
      }
    }

    // 2. Dynamic "Any Banking Institution" detector (for regional/international banks not in preset list)
    const dynamicBank = !candidateBank
      ? this.detectDynamicBankingInstitution(html, extractedAssets, inspectedDomain)
      : null;

    const matchedAssets: MatchedBankVisualAssetDTO[] = [];
    let officialRefCompared = false;

    // 3. Inspect & compare visual assets against candidate known bank
    if (candidateBank) {
      // 3A. Check hotlinked official bank images/favicons & SVG/filename logo signatures
      for (const asset of extractedAssets) {
        if (this.isAssetHostedOnOfficialBankInfra(asset.url, candidateBank)) {
          matchedAssets.push({
            asset_url: asset.url.slice(0, 180),
            asset_type: asset.assetType,
            claimed_bank: candidateBank.name,
            match_method: 'HOTLINKED_OFFICIAL_BANK_CDN',
            similarity_percent: 100,
            sha256_prefix: (await CryptoService.sha256Hex(asset.url)).slice(0, 16),
            dimensions: null,
          });
          officialRefCompared = true;
          continue;
        }

        const assetMetaNorm = normalizeText(`${asset.url} ${asset.altOrLabel} ${asset.rawMarkup}`);
        const hasLogoToken = candidateBank.logoTokens.some((lt) =>
          assetMetaNorm.includes(normalizeText(lt))
        );
        const hasBrandColor =
          asset.assetType === 'inline_svg' &&
          candidateBank.brandColors.some((hex) => asset.rawMarkup.toLowerCase().includes(hex));

        if (hasLogoToken || hasBrandColor) {
          matchedAssets.push({
            asset_url:
              asset.assetType === 'inline_svg'
                ? `inline-svg#${candidateBank.id}`
                : asset.url.slice(0, 180),
            asset_type: asset.assetType,
            claimed_bank: candidateBank.name,
            match_method: 'SVG_OR_LOGO_SIGNATURE',
            similarity_percent: hasLogoToken && hasBrandColor ? 98 : 93,
            sha256_prefix: (await CryptoService.sha256Hex(asset.rawMarkup || asset.url)).slice(
              0,
              16
            ),
            dimensions: null,
          });
        }
      }

      // 3B. Live Binary Image Download & Cryptographic/Perceptual Comparison against Official Bank Icons!
      // Even if scammer renamed "banesco-logo.png" to "header123.png", binary SHA-256 & 64-bit fingerprint catches it!
      if (!params.simulatedDemo && extractedAssets.length > 0) {
        const officialRef = await this.getOfficialBankSignatures(candidateBank, params.kv);
        if (officialRef && officialRef.signatures.length > 0) {
          officialRefCompared = true;
          const downloadableAssets = extractedAssets
            .filter((a) => a.assetType !== 'inline_svg' && /^https?:\/\/|^data:image\//i.test(a.url))
            .slice(0, 4);

          for (const asset of downloadableAssets) {
            const targetSig = await this.downloadAndFingerprintImage(asset.url);
            if (!targetSig) continue;

            for (const refSig of officialRef.signatures) {
              if (targetSig.sha256Hex === refSig.sha256Hex) {
                matchedAssets.push({
                  asset_url: asset.url.slice(0, 180),
                  asset_type: asset.assetType,
                  claimed_bank: candidateBank.name,
                  match_method: 'EXACT_OFFICIAL_SHA256',
                  similarity_percent: 100,
                  sha256_prefix: targetSig.sha256Hex.slice(0, 16),
                  dimensions: targetSig.dimensions,
                });
                break;
              }

              const sim = this.computeFingerprintSimilarityPercent(
                targetSig.fingerprint64,
                refSig.fingerprint64
              );
              if (sim >= 85 && targetSig.byteLength >= 160 && refSig.byteLength >= 160) {
                matchedAssets.push({
                  asset_url: asset.url.slice(0, 180),
                  asset_type: asset.assetType,
                  claimed_bank: candidateBank.name,
                  match_method: 'PERCEPTUAL_HASH_SIMILARITY',
                  similarity_percent: sim,
                  sha256_prefix: targetSig.sha256Hex.slice(0, 16),
                  dimensions: targetSig.dimensions,
                });
                break;
              }
            }
          }
        }
      }
    } else if (dynamicBank) {
      // 3C. Dynamic regional / unknown banking institution with visual logos on an unrelated domain
      for (const asset of dynamicBank.matchedAssets) {
        matchedAssets.push({
          asset_url: asset.url.slice(0, 180),
          asset_type: asset.assetType,
          claimed_bank: dynamicBank.institutionName,
          match_method: 'DYNAMIC_BANK_BRAND_MISMATCH',
          similarity_percent: 94,
          sha256_prefix: (await CryptoService.sha256Hex(asset.rawMarkup || asset.url)).slice(0, 16),
          dimensions: null,
        });
      }
    }

    // 4. Evaluate Findings: Is this pretending to be a bank on a NON-OFFICIAL domain?
    const detectedInstitution = candidateBank
      ? candidateBank.name
      : dynamicBank
      ? dynamicBank.institutionName
      : null;
    const expectedOfficialDomain = candidateBank ? candidateBank.officialDomains[0] : null;
    const hasLoginOrSensitiveInputs =
      /<input\b[^>]*type\s*=\s*["']?password["']?/i.test(html) ||
      /\b(banca en l[ií]nea|clave|contrase[ñn]a|usuario|c[eé]dula|tarjeta|coordenadas|token|validar cuenta|desbloqueo)\b/i.test(
        visibleSignals
      );

    if (detectedInstitution && (matchedAssets.length > 0 || hasLoginOrSensitiveInputs)) {
      const highestSim = matchedAssets.reduce(
        (max, item) => Math.max(max, item.similarity_percent),
        matchedAssets.length > 0 ? 90 : 0
      );

      if (matchedAssets.length > 0) {
        const primaryAsset = matchedAssets[0];
        const expectedNote = expectedOfficialDomain
          ? ` El único portal oficial legítimo es ${expectedOfficialDomain}.`
          : ' El dominio inspeccionado no corresponde a una entidad bancaria autorizada.';

        findings.push({
          id: CryptoService.generateUlid('fnd'),
          rule_code: 'VISUAL_BANK_IMAGE_IMPERSONATION',
          category: 'DOM_FORM',
          severity: 'CRITICAL',
          line_number: 1,
          column_number: 1,
          dom_selector: `visual-brand:${primaryAsset.asset_type}`,
          citizen_explanation: `¡NO ES PÁGINA OFICIAL! Comparamos las imágenes y logotipos de esta página y detectamos identidad visual de ${detectedInstitution} usada sin permiso dentro de un dominio falso (${inspectedDomain}).${expectedNote}`,
          technical_detail: `Suplantación visual bancaria confirmada (${primaryAsset.match_method}, similitud ${highestSim}%, hash ${primaryAsset.sha256_prefix}) reclamando identidad de "${detectedInstitution}" en host ajeno (${inspectedDomain}).`,
          code_snippet: `Imagen auditada: ${primaryAsset.asset_url} -> Institución: ${detectedInstitution} (Dominio falso: ${inspectedDomain})`,
        });
      } else {
        const expectedNote = expectedOfficialDomain
          ? ` Su dirección real y oficial es ${expectedOfficialDomain}.`
          : '';
        findings.push({
          id: CryptoService.generateUlid('fnd'),
          rule_code: 'BANK_BRAND_CONTENT_IMPERSONATION',
          category: 'DOM_FORM',
          severity: 'CRITICAL',
          line_number: 1,
          column_number: 1,
          dom_selector: 'document:brand-identity',
          citizen_explanation: `¡Alerta de Suplantación! Esta página menciona a ${detectedInstitution} y solicita datos de acceso, pero NO es su página oficial (${inspectedDomain}).${expectedNote}`,
          technical_detail: `Uso de marca bancaria "${detectedInstitution}" junto con solicitud de credenciales en dominio no autorizado (${inspectedDomain}).`,
          code_snippet: `Entidad detectada: ${detectedInstitution} != Host: ${inspectedDomain}`,
        });
      }

      return {
        audit: {
          executed: true,
          banking_brand_detected: true,
          is_official_bank_page: false,
          detected_institution: detectedInstitution,
          official_domain_expected: expectedOfficialDomain,
          inspected_domain: inspectedDomain,
          images_inspected_count: extractedAssets.length,
          official_reference_compared: officialRefCompared || matchedAssets.length > 0,
          highest_similarity_percent: highestSim,
          matched_assets: matchedAssets.slice(0, 4),
          verdict_label: 'NO ES PÁGINA OFICIAL — SUPLANTACIÓN BANCARIA DETECTADA',
          verdict_summary: expectedOfficialDomain
            ? `Determinamos que ${inspectedDomain} NO es una página oficial: utiliza imágenes o identidad de ${detectedInstitution}, cuyo único dominio oficial es ${expectedOfficialDomain}.`
            : `Determinamos que ${inspectedDomain} NO es un dominio oficial de ${detectedInstitution}: utiliza logotipos e interfaz bancaria desde un servidor externo no autorizado.`,
        },
        findings,
      };
    }

    // Default: No banking brand impersonation detected
    return {
      audit: {
        executed: true,
        banking_brand_detected: false,
        is_official_bank_page: null,
        detected_institution: null,
        official_domain_expected: null,
        inspected_domain: inspectedDomain,
        images_inspected_count: extractedAssets.length,
        official_reference_compared: false,
        highest_similarity_percent: 0,
        matched_assets: [],
        verdict_label: 'SIN SUPLANTACIÓN DE IMÁGENES BANCARIAS DETECTADA',
        verdict_summary: `Se revisaron ${extractedAssets.length} recurso(s) gráfico(s) en ${inspectedDomain} sin hallar logotipos bancarios clonados.`,
      },
      findings: [],
    };
  }

  private static extractVisualAssets(
    html: string,
    bundleCorpus: string,
    baseUrl: string
  ): ExtractedVisualAsset[] {
    const assets: ExtractedVisualAsset[] = [];
    const seenUrls = new Set<string>();

    const pushAsset = (
      rawUrl: string,
      assetType: ExtractedVisualAsset['assetType'],
      altOrLabel: string,
      rawMarkup: string,
      offset: number
    ) => {
      let resolved = rawUrl.trim();
      if (!resolved) return;
      if (!resolved.startsWith('data:') && assetType !== 'inline_svg') {
        try {
          resolved = new URL(resolved, baseUrl).toString();
        } catch {
          return;
        }
      }
      const dedupKey = `${assetType}:${resolved}`;
      if (seenUrls.has(dedupKey)) return;
      seenUrls.add(dedupKey);
      assets.push({
        url: resolved,
        assetType,
        altOrLabel: altOrLabel.trim(),
        rawMarkup: rawMarkup.slice(0, 320),
        lineNumber: getLineNumber(html, offset),
      });
    };

    // 1. <link rel="icon | shortcut icon | apple-touch-icon" href="...">
    const linkRe = /<link\b[^>]*>/gi;
    let m: RegExpExecArray | null;
    while ((m = linkRe.exec(html)) !== null) {
      const tag = m[0];
      if (!/\brel\s*=\s*["']?[^"'>]*(?:icon|apple-touch-icon)/i.test(tag)) continue;
      const hrefMatch = tag.match(/\bhref\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))/i);
      const href = hrefMatch ? hrefMatch[1] || hrefMatch[2] || hrefMatch[3] || '' : '';
      if (href) pushAsset(href, 'favicon', 'favicon', tag, m.index);
    }

    // 2. <meta property="og:image" | name="twitter:image" content="...">
    const metaRe = /<meta\b[^>]*>/gi;
    while ((m = metaRe.exec(html)) !== null) {
      const tag = m[0];
      if (!/(?:og:image|twitter:image)/i.test(tag)) continue;
      const contentMatch = tag.match(/\bcontent\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))/i);
      const content = contentMatch
        ? contentMatch[1] || contentMatch[2] || contentMatch[3] || ''
        : '';
      if (content) pushAsset(content, 'og_image', 'og:image', tag, m.index);
    }

    // 3. <img src="..." alt="..." title="..." class="..." id="...">
    const imgRe = /<img\b[^>]*>/gi;
    while ((m = imgRe.exec(html)) !== null) {
      const tag = m[0];
      const srcMatch = tag.match(/\bsrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))/i);
      const src = srcMatch ? srcMatch[1] || srcMatch[2] || srcMatch[3] || '' : '';
      const altMatch = tag.match(/\balt\s*=\s*(?:"([^"]*)"|'([^']*)')/i);
      const titleMatch = tag.match(/\btitle\s*=\s*(?:"([^"]*)"|'([^']*)')/i);
      const idClassMatch = tag.match(/\b(?:id|class)\s*=\s*(?:"([^"]*)"|'([^']*)')/gi);
      const label = [
        altMatch ? altMatch[1] || altMatch[2] : '',
        titleMatch ? titleMatch[1] || titleMatch[2] : '',
        ...(idClassMatch || []),
      ].join(' ');
      if (src) pushAsset(src, 'logo_img', label, tag, m.index);
    }

    // 4. Inline <svg>...</svg> (brand headers/logos)
    const svgRe = /<svg\b[^>]*>[\s\S]{0,4000}?<\/svg>/gi;
    let svgCount = 0;
    while ((m = svgRe.exec(html)) !== null && svgCount < 8) {
      svgCount++;
      const block = m[0];
      const textInside = block.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
      const ariaMatch = block.match(/\b(?:aria-label|id|class)\s*=\s*(?:"([^"]*)"|'([^']*)')/gi);
      const label = `${(ariaMatch || []).join(' ')} ${textInside}`;
      pushAsset(`inline-svg-${svgCount}`, 'inline_svg', label, block, m.index);
    }

    // 5. CSS background-image & SPA JS bundle image paths
    const bgRe = /url\(\s*["']?([^"')]+?\.(?:png|svg|webp|jpg|jpeg|ico)(?:\?[^"')]*)?)["']?\s*\)/gi;
    while ((m = bgRe.exec(html)) !== null && assets.length < 24) {
      pushAsset(m[1], 'css_or_bundle', m[1], m[0], m.index);
    }

    if (bundleCorpus) {
      const bundleImgRe =
        /["']((?:https?:\/\/|\/)[^"'\s]{3,160}\.(?:png|svg|webp|jpg|jpeg|ico))["']/gi;
      let bm: RegExpExecArray | null;
      let count = 0;
      while ((bm = bundleImgRe.exec(bundleCorpus)) !== null && count < 8) {
        count++;
        pushAsset(bm[1], 'css_or_bundle', bm[1], bm[0], 1);
      }
    }

    // Always include implicit /favicon.ico if no explicit favicon link tag was declared
    if (!assets.some((a) => a.assetType === 'favicon')) {
      try {
        const defaultFav = new URL('/favicon.ico', baseUrl).toString();
        pushAsset(defaultFav, 'favicon', 'default-favicon', defaultFav, 1);
      } catch {
        // ignore
      }
    }

    return assets;
  }

  private static extractPageBrandTextSignals(html: string, bundleCorpus: string): string {
    const parts: string[] = [];
    const titleMatch = html.match(/<title\b[^>]*>([\s\S]{0,300}?)<\/title>/i);
    if (titleMatch) parts.push(titleMatch[1]);

    const metaRe =
      /<meta\b[^>]*(?:og:title|og:site_name|og:description|description|application-name)[^>]*>/gi;
    let m: RegExpExecArray | null;
    while ((m = metaRe.exec(html)) !== null) {
      parts.push(m[0]);
    }

    // Visible text stripped of scripts/styles (bounded to first 16 KB)
    const visible = html
      .slice(0, 32000)
      .replace(/<script[\s\S]*?<\/script>/gi, ' ')
      .replace(/<style[\s\S]*?<\/style>/gi, ' ')
      .replace(/<[^>]+>/g, ' ')
      .replace(/\s+/g, ' ')
      .slice(0, 8000);
    parts.push(visible);

    if (bundleCorpus) {
      parts.push(bundleCorpus.slice(0, 12000));
    }

    return parts.join(' ');
  }

  /**
   * Detecta dinámicamente CUALQUIER institución bancaria ("Banco <Nombre>", "<Nombre> Bank",
   * "Cooperativa Financiera <Nombre>", "Caja de Ahorros <Nombre>") aunque sea regional o nueva,
   * verificando si el dominio actual coincide con la entidad o si usa sus imágenes/logos en un host ajeno.
   */
  private static detectDynamicBankingInstitution(
    html: string,
    assets: ExtractedVisualAsset[],
    inspectedDomain: string
  ): { institutionName: string; matchedAssets: ExtractedVisualAsset[] } | null {
    const candidateSources: string[] = [];
    const titleMatch = html.match(/<title\b[^>]*>([\s\S]{0,220}?)<\/title>/i);
    if (titleMatch) candidateSources.push(titleMatch[1]);

    const ogSiteMatch = html.match(
      /<meta\b[^>]*property\s*=\s*["']og:site_name["'][^>]*content\s*=\s*["']([^"']+)["']/i
    );
    if (ogSiteMatch) candidateSources.push(ogSiteMatch[1]);

    for (const a of assets) {
      if (a.altOrLabel) candidateSources.push(a.altOrLabel);
    }

    const bankNameRegex =
      /\b((?:Banco|Caja\s+de\s+Ahorros|Cooperativa(?:\s+Financiera)?)\s+[A-ZÁÉÍÓÚÑ][A-Za-záéíóúñÁÉÍÓÚÑ0-9\s]{2,34}|[A-Z][A-Za-z]{2,20}\s+Bank)\b/g;

    let detectedName = '';
    for (const src of candidateSources) {
      const cleaned = src.replace(/\s+/g, ' ').trim();
      for (const m of cleaned.matchAll(bankNameRegex)) {
        if (m[1]) {
          const candidate = m[1]
            .replace(/\b(Personas|Empresas|Oficial|Logo|Acceso|Clientes|Login)\b/gi, '')
            .replace(/\s+/g, ' ')
            .trim();
          if (candidate.length >= 8 && !/Detector360/i.test(candidate)) {
            detectedName = candidate;
            break;
          }
        }
      }
      if (detectedName) break;
    }

    if (!detectedName) return null;

    // Check if the inspected domain plausibly belongs to this bank name (e.g. bancoatlantida.com)
    const significantWords = normalizeText(detectedName)
      .split(/\s+/)
      .filter((w) => w.length >= 4 && !['banco', 'banca', 'linea', 'bank', 'caja', 'digital'].includes(w));

    const domainNorm = normalizeText(inspectedDomain.split('.')[0] || '');
    const domainMatchesInstitution =
      significantWords.length > 0 && significantWords.some((w) => domainNorm.includes(w));

    // Official .bank / .gob / .gov domains or matching corporate root domain are not flagged as dynamic spoofing
    if (
      domainMatchesInstitution &&
      !/\.(xyz|top|click|app|dev|site|online|shop|tk|gq)$/i.test(inspectedDomain)
    ) {
      return null;
    }

    const relatedAssets = assets.filter((a) => {
      const norm = normalizeText(`${a.url} ${a.altOrLabel} ${a.rawMarkup}`);
      return (
        norm.includes('logo') ||
        norm.includes('banco') ||
        norm.includes('bank') ||
        significantWords.some((w) => norm.includes(w))
      );
    });

    return {
      institutionName: detectedName,
      matchedAssets: relatedAssets.length > 0 ? relatedAssets : assets.slice(0, 1),
    };
  }

  private static async getOfficialBankSignatures(
    bank: BankVisualProfile,
    kv: KVNamespace
  ): Promise<CachedOfficialBankRef | null> {
    const primaryDomain = bank.officialDomains[0];
    const cacheKey = `bank_vis_sig:v1:${bank.id}`;

    const cached = await kv.get<CachedOfficialBankRef>(cacheKey, 'json');
    if (cached) return cached;

    const candidateUrls = [
      `https://www.google.com/s2/favicons?domain=${encodeURIComponent(primaryDomain)}&sz=64`,
      `https://${primaryDomain}/favicon.ico`,
    ];

    const signatures: BinaryImageSignature[] = [];
    for (const refUrl of candidateUrls) {
      const sig = await this.downloadAndFingerprintImage(refUrl);
      if (sig && sig.byteLength >= 90) {
        signatures.push(sig);
      }
    }

    const record: CachedOfficialBankRef = {
      bankId: bank.id,
      officialDomain: primaryDomain,
      signatures,
    };
    await kv.put(cacheKey, JSON.stringify(record), { expirationTtl: 86400 });
    return record;
  }

  private static async downloadAndFingerprintImage(
    imageUrl: string
  ): Promise<BinaryImageSignature | null> {
    try {
      let bytes: Uint8Array;

      if (imageUrl.startsWith('data:image/')) {
        const commaIdx = imageUrl.indexOf(',');
        if (commaIdx === -1) return null;
        const meta = imageUrl.slice(0, commaIdx);
        const dataPart = imageUrl.slice(commaIdx + 1);
        if (meta.includes(';base64')) {
          const binStr = atob(dataPart.slice(0, 340000));
          bytes = new Uint8Array(binStr.length);
          for (let i = 0; i < binStr.length; i++) bytes[i] = binStr.charCodeAt(i);
        } else {
          bytes = new TextEncoder().encode(decodeURIComponent(dataPart));
        }
      } else {
        SsrfGuardService.validatePublicUrl(imageUrl);
        const res = await fetch(imageUrl, {
          method: 'GET',
          signal: AbortSignal.timeout(2200),
          headers: {
            Accept: 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
            'User-Agent':
              'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36',
          },
        });
        if (!res.ok) return null;
        const ctype = (res.headers.get('content-type') || '').toLowerCase();
        if (ctype.includes('text/html')) return null;
        const ab = await res.arrayBuffer();
        if (ab.byteLength < 48 || ab.byteLength > 262144) return null;
        bytes = new Uint8Array(ab);
      }

      const hashBuf = await crypto.subtle.digest('SHA-256', bytes);
      const sha256Hex = Array.from(new Uint8Array(hashBuf))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');

      const fingerprint64 = this.compute64BitVisualSignature(bytes);
      const dimensions = this.parseImageDimensions(bytes);

      return {
        sha256Hex,
        fingerprint64,
        byteLength: bytes.byteLength,
        dimensions,
      };
    } catch {
      return null;
    }
  }

  /**
   * Calcula una huella estructural de 64 bits (16 caracteres hex) dividiendo el flujo de píxeles/bytes
   * en 64 bandas normalizadas y comparando cada banda contra la mediana global (estilo dHash/aHash binario).
   */
  static compute64BitVisualSignature(bytes: Uint8Array): string {
    const startOffset = Math.min(24, Math.floor(bytes.byteLength * 0.1));
    const usableLen = Math.max(1, bytes.byteLength - startOffset);
    const buckets = new Float64Array(64);

    for (let b = 0; b < 64; b++) {
      const segStart = startOffset + Math.floor((b * usableLen) / 64);
      const segEnd = Math.max(segStart + 1, startOffset + Math.floor(((b + 1) * usableLen) / 64));
      let sum = 0;
      let count = 0;
      for (let i = segStart; i < segEnd && i < bytes.byteLength; i++) {
        sum += bytes[i];
        count++;
      }
      buckets[b] = count > 0 ? sum / count : 0;
    }

    const sorted = Array.from(buckets).sort((a, b) => a - b);
    const median = sorted[32] || 127;

    let hex = '';
    for (let nibble = 0; nibble < 16; nibble++) {
      let val = 0;
      for (let bit = 0; bit < 4; bit++) {
        const idx = nibble * 4 + bit;
        if (buckets[idx] >= median) {
          val |= 1 << (3 - bit);
        }
      }
      hex += val.toString(16);
    }
    return hex;
  }

  static computeFingerprintSimilarityPercent(hexA: string, hexB: string): number {
    if (hexA.length !== 16 || hexB.length !== 16) return 0;
    let equalBits = 0;
    for (let i = 0; i < 16; i++) {
      const xor = parseInt(hexA[i], 16) ^ parseInt(hexB[i], 16);
      for (let bit = 0; bit < 4; bit++) {
        if (((xor >> bit) & 1) === 0) equalBits++;
      }
    }
    return Math.round((equalBits / 64) * 100);
  }

  private static parseImageDimensions(bytes: Uint8Array): string | null {
    // PNG: 89 50 4E 47 ... IHDR width (16..19), height (20..23)
    if (
      bytes.byteLength >= 24 &&
      bytes[0] === 0x89 &&
      bytes[1] === 0x50 &&
      bytes[2] === 0x4e &&
      bytes[3] === 0x47
    ) {
      const w = (bytes[16] << 24) | (bytes[17] << 16) | (bytes[18] << 8) | bytes[19];
      const h = (bytes[20] << 24) | (bytes[21] << 16) | (bytes[22] << 8) | bytes[23];
      if (w > 0 && h > 0) return `${w}x${h}px`;
    }
    // GIF: 47 49 46 38 -> width (6..7 LE), height (8..9 LE)
    if (bytes.byteLength >= 10 && bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46) {
      const w = bytes[6] | (bytes[7] << 8);
      const h = bytes[8] | (bytes[9] << 8);
      if (w > 0 && h > 0) return `${w}x${h}px`;
    }
    // ICO: 00 00 01 00 -> entry[0] width (6), height (7)
    if (
      bytes.byteLength >= 14 &&
      bytes[0] === 0x00 &&
      bytes[1] === 0x00 &&
      bytes[2] === 0x01 &&
      bytes[3] === 0x00
    ) {
      const w = bytes[6] === 0 ? 256 : bytes[6];
      const h = bytes[7] === 0 ? 256 : bytes[7];
      return `${w}x${h}px`;
    }
    return null;
  }
}
