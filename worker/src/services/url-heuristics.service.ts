import type { KVNamespace, ScanFindingDTO } from '../types.ts';
import { CryptoService } from './crypto.service.ts';

/**
 * AntiphishingCtiService
 * Integra la metodología predictiva Day-Zero de julioliraup/Antiphishing:
 * 1. Detección DNSTwist / Typosquatting (distancia de edición Damerau-Levenshtein y permutaciones).
 * 2. Detección de Homógrafos IDN (Punycode xn--, Unicode confusable y normalización Leet 0/1/3/4/5/rn).
 * 3. Patrones de Suplantación de Marca + Keywords Multilenguaje (ES/PT/EN/FR/DE) y afijos con guiones/dígitos.
 * 4. Análisis estructural de URL (IPv4 literal, engaño userinfo @, entropía de Shannon y subdominios señuelo).
 * 5. Correlación opcional con datasets CTI de julioliraup/Antiphishing cacheados en Cloudflare KV.
 * 6. Generador nativo de reglas Suricata IDS/IPS (rango SID 6090000-6099999 compatible con Suricata 7/8).
 */

const NRD_FEED_URL =
  'https://raw.githubusercontent.com/julioliraup/Antiphishing/refs/heads/main/nrd_suspicious_domains.txt';
const PHISHING_IPS_URL =
  'https://raw.githubusercontent.com/julioliraup/Antiphishing/refs/heads/main/phishing_ips.lst';

interface BrandEntry {
  name: string;
  label: string;
  officialDomains: string[];
}

const PROTECTED_BRANDS: BrandEntry[] = [
  // Marcas globales de julioliraup/Antiphishing (nrd_processor.py)
  { name: 'paypal', label: 'PayPal', officialDomains: ['paypal.com', 'paypal.me'] },
  { name: 'chase', label: 'Chase Bank', officialDomains: ['chase.com'] },
  { name: 'bankofamerica', label: 'Bank of America', officialDomains: ['bankofamerica.com'] },
  { name: 'hsbc', label: 'HSBC', officialDomains: ['hsbc.com'] },
  { name: 'santander', label: 'Banco Santander', officialDomains: ['santander.com', 'santander.com.br', 'santander.es'] },
  { name: 'wellsfargo', label: 'Wells Fargo', officialDomains: ['wellsfargo.com'] },
  { name: 'revolut', label: 'Revolut', officialDomains: ['revolut.com'] },
  { name: 'wise', label: 'Wise', officialDomains: ['wise.com'] },
  { name: 'barclays', label: 'Barclays', officialDomains: ['barclays.com', 'barclays.co.uk'] },
  { name: 'citibank', label: 'Citibank', officialDomains: ['citibank.com', 'citi.com'] },
  { name: 'nubank', label: 'Nubank', officialDomains: ['nubank.com.br', 'nu.com.mx', 'nu.com.co'] },
  { name: 'bradesco', label: 'Bradesco', officialDomains: ['bradesco.com.br'] },
  { name: 'itau', label: 'Banco Itaú', officialDomains: ['itau.com.br', 'itau.cl'] },
  { name: 'caixa', label: 'Caixa', officialDomains: ['caixa.gov.br', 'caixabank.es'] },
  { name: 'amazon', label: 'Amazon', officialDomains: ['amazon.com', 'amazon.es', 'amazon.com.mx', 'amazon.com.br'] },
  { name: 'ebay', label: 'eBay', officialDomains: ['ebay.com'] },
  { name: 'mercadolibre', label: 'Mercado Libre', officialDomains: ['mercadolibre.com', 'mercadolibre.com.ve', 'mercadolibre.com.ar', 'mercadolibre.com.mx', 'mercadolivre.com.br'] },
  { name: 'mercadopago', label: 'Mercado Pago', officialDomains: ['mercadopago.com', 'mercadopago.com.ar', 'mercadopago.com.mx', 'mercadopago.com.br'] },
  { name: 'stripe', label: 'Stripe', officialDomains: ['stripe.com'] },
  { name: 'shopify', label: 'Shopify', officialDomains: ['shopify.com', 'myshopify.com'] },
  { name: 'apple', label: 'Apple / iCloud', officialDomains: ['apple.com', 'icloud.com'] },
  { name: 'google', label: 'Google', officialDomains: ['google.com', 'google.co.ve', 'gmail.com'] },
  { name: 'microsoft', label: 'Microsoft / Outlook', officialDomains: ['microsoft.com', 'live.com', 'office.com', 'outlook.com'] },
  { name: 'facebook', label: 'Facebook / Meta', officialDomains: ['facebook.com', 'fb.com', 'meta.com'] },
  { name: 'instagram', label: 'Instagram', officialDomains: ['instagram.com'] },
  { name: 'whatsapp', label: 'WhatsApp', officialDomains: ['whatsapp.com', 'whatsapp.net'] },
  { name: 'netflix', label: 'Netflix', officialDomains: ['netflix.com'] },
  { name: 'adobe', label: 'Adobe', officialDomains: ['adobe.com'] },
  { name: 'binance', label: 'Binance', officialDomains: ['binance.com'] },
  { name: 'coinbase', label: 'Coinbase', officialDomains: ['coinbase.com'] },
  { name: 'metamask', label: 'MetaMask', officialDomains: ['metamask.io'] },
  { name: 'trustwallet', label: 'Trust Wallet', officialDomains: ['trustwallet.com'] },
  { name: 'telegram', label: 'Telegram', officialDomains: ['telegram.org', 't.me'] },
  { name: 'discord', label: 'Discord', officialDomains: ['discord.com', 'discord.gg'] },
  { name: 'linkedin', label: 'LinkedIn', officialDomains: ['linkedin.com'] },
  { name: 'tiktok', label: 'TikTok', officialDomains: ['tiktok.com'] },

  // Banca, Pagos y Organismos Públicos Regionales / Venezuela
  { name: 'banesco', label: 'Banesco', officialDomains: ['banesco.com', 'banesconline.com', 'banesco.com.pa'] },
  { name: 'bancodevenezuela', label: 'Banco de Venezuela', officialDomains: ['bancodevenezuela.com', 'bdvenlinea.banvenez.com'] },
  { name: 'mercantil', label: 'Mercantil Banco', officialDomains: ['mercantilbanco.com', 'mercantilenlinea.com'] },
  { name: 'provincial', label: 'BBVA Provincial', officialDomains: ['provincial.com', 'bbva.com'] },
  { name: 'bancamiga', label: 'Bancamiga', officialDomains: ['bancamiga.com'] },
  { name: 'bncenlinea', label: 'Banco Nacional de Crédito (BNC)', officialDomains: ['bncenlinea.com', 'bnc.com.ve'] },
  { name: 'bancaribe', label: 'Bancaribe', officialDomains: ['bancaribe.com.ve'] },
  { name: 'banplus', label: 'Banplus', officialDomains: ['banplus.com'] },
  { name: 'zinli', label: 'Zinli', officialDomains: ['zinli.com'] },
  { name: 'patria', label: 'Sistema Patria', officialDomains: ['patria.org.ve'] },
  { name: 'saime', label: 'SAIME', officialDomains: ['saime.gob.ve'] },
  { name: 'seniat', label: 'SENIAT', officialDomains: ['seniat.gob.ve'] },
  { name: 'corpoelec', label: 'Corpoelec', officialDomains: ['corpoelec.gob.ve'] },
];

// Keywords multilenguaje de ingeniería social (julioliraup/Antiphishing nrd_processor.py + ES/LATAM)
const MULTILANGUAGE_KEYWORDS = [
  'login', 'signin', 'verify', 'account', 'security', 'update', 'support',
  'billing', 'secure', 'auth', 'portal', 'alert', 'restore', 'bank', 'wallet',
  'acesso', 'atendimento', 'seguranca', 'recuperar', 'confirmar', 'fatura',
  'pix', 'banco', 'atualizacao', 'cadastrar', 'cartao', 'bloqueio',
  'acceso', 'seguridad', 'cuenta', 'validar', 'soporte', 'clave', 'verificar',
  'ingreso', 'verificacion', 'desbloqueo', 'enlinea', 'personas', 'bono',
  'ayuda', 'paquete', 'entrega', 'pendiente', 'pago', 'cobro', 'premio',
];

const MULTI_PART_SUFFIXES = [
  'com.ve', 'gob.ve', 'org.ve', 'net.ve', 'edu.ve',
  'com.br', 'gov.br', 'org.br',
  'com.ar', 'com.co', 'com.mx', 'com.pe', 'com.pa', 'co.uk',
  'ejemplo.xyz', 'ejemplo.com', 'detector360.ejemplo',
];

const UNICODE_CONFUSABLES: Record<string, string> = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's',
  'α': 'a', 'β': 'b', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't',
  'á': 'a', 'é': 'e', 'í': 'i', 'ó': 'o', 'ú': 'u', 'ü': 'u',
};

const IPV4_REGEX = /^(?:\d{1,3}\.){3}\d{1,3}$/;

export interface ExtractedDomainParts {
  fullHost: string;
  registeredDomain: string;
  domainLabel: string;
  subdomain: string;
  suffix: string;
}

export class AntiphishingCtiService {
  static extractDomainParts(hostname: string): ExtractedDomainParts {
    const clean = hostname.toLowerCase().trim().replace(/\.$/, '');
    if (IPV4_REGEX.test(clean)) {
      return {
        fullHost: clean,
        registeredDomain: clean,
        domainLabel: clean,
        subdomain: '',
        suffix: '',
      };
    }

    for (const multiSuffix of MULTI_PART_SUFFIXES) {
      if (clean === multiSuffix) {
        return {
          fullHost: clean,
          registeredDomain: clean,
          domainLabel: clean.split('.')[0],
          subdomain: '',
          suffix: multiSuffix,
        };
      }
      if (clean.endsWith(`.${multiSuffix}`)) {
        const withoutSuffix = clean.slice(0, -(multiSuffix.length + 1));
        const labels = withoutSuffix.split('.');
        const domainLabel = labels[labels.length - 1] || '';
        const subdomain = labels.slice(0, -1).join('.');
        return {
          fullHost: clean,
          registeredDomain: `${domainLabel}.${multiSuffix}`,
          domainLabel,
          subdomain,
          suffix: multiSuffix,
        };
      }
    }

    const parts = clean.split('.');
    if (parts.length <= 2) {
      const domainLabel = parts[0] || clean;
      const suffix = parts[1] || '';
      return {
        fullHost: clean,
        registeredDomain: clean,
        domainLabel,
        subdomain: '',
        suffix,
      };
    }

    const suffix = parts[parts.length - 1];
    const domainLabel = parts[parts.length - 2];
    const subdomain = parts.slice(0, -2).join('.');
    return {
      fullHost: clean,
      registeredDomain: `${domainLabel}.${suffix}`,
      domainLabel,
      subdomain,
      suffix,
    };
  }

  static isOfficialWhitelistedDomain(hostname: string): boolean {
    const clean = hostname.toLowerCase().trim();
    if (
      clean.endsWith('.detector360.ejemplo') ||
      clean === 'banco-oficial-seguro.ejemplo.com' ||
      clean === 'comercio-seguro.ejemplo.com'
    ) {
      return true;
    }

    for (const brand of PROTECTED_BRANDS) {
      for (const official of brand.officialDomains) {
        if (clean === official || clean.endsWith(`.${official}`)) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Distancia Damerau-Levenshtein (omisión, inserción, sustitución y transposición adyacente tipo dnstwist)
   */
  static damerauLevenshtein(a: string, b: string): number {
    const lenA = a.length;
    const lenB = b.length;
    const dp: number[][] = Array.from({ length: lenA + 1 }, () =>
      new Array<number>(lenB + 1).fill(0)
    );

    for (let i = 0; i <= lenA; i++) dp[i][0] = i;
    for (let j = 0; j <= lenB; j++) dp[0][j] = j;

    for (let i = 1; i <= lenA; i++) {
      for (let j = 1; j <= lenB; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        dp[i][j] = Math.min(
          dp[i - 1][j] + 1, // deletion
          dp[i][j - 1] + 1, // insertion
          dp[i - 1][j - 1] + cost // substitution
        );
        if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
          dp[i][j] = Math.min(dp[i][j], dp[i - 2][j - 2] + cost); // transposition
        }
      }
    }
    return dp[lenA][lenB];
  }

  static normalizeLeetAndHomoglyphs(input: string): {
    normalized: string;
    hasUnicodeConfusable: boolean;
  } {
    let hasUnicodeConfusable = false;
    let skeleton = '';
    for (const ch of input) {
      if (UNICODE_CONFUSABLES[ch]) {
        hasUnicodeConfusable = true;
        skeleton += UNICODE_CONFUSABLES[ch];
      } else {
        skeleton += ch;
      }
    }

    const normalized = skeleton
      .replace(/0/g, 'o')
      .replace(/1/g, 'l')
      .replace(/3/g, 'e')
      .replace(/4/g, 'a')
      .replace(/5/g, 's')
      .replace(/8/g, 'b')
      .replace(/rn/g, 'm')
      .replace(/vv/g, 'w');

    return { normalized, hasUnicodeConfusable };
  }

  static shannonEntropy(str: string): number {
    if (!str) return 0;
    const freq: Record<string, number> = {};
    for (const ch of str) {
      freq[ch] = (freq[ch] || 0) + 1;
    }
    let entropy = 0;
    const len = str.length;
    for (const count of Object.values(freq)) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  /**
   * Consulta no bloqueante a los datasets CTI de julioliraup/Antiphishing (cacheados 6h en KV)
   */
  private static async checkExternalAntiphishingDatasets(
    registeredDomain: string,
    fullHost: string,
    kv?: KVNamespace
  ): Promise<'NRD_DATASET' | 'IPV4_DATASET' | null> {
    if (!kv) return null;

    try {
      if (IPV4_REGEX.test(fullHost)) {
        let ipText = await kv.get('cti:julioliraup:phishing_ips');
        if (ipText === null) {
          try {
            const res = await fetch(PHISHING_IPS_URL, { signal: AbortSignal.timeout(1500) });
            ipText = res.ok ? await res.text() : '';
          } catch {
            ipText = '';
          }
          await kv.put('cti:julioliraup:phishing_ips', ipText.slice(0, 350_000), {
            expirationTtl: 21600,
          });
        }
        if (ipText && ipText.split(/\r?\n/).some((line) => line.trim() === fullHost)) {
          return 'IPV4_DATASET';
        }
      } else {
        let nrdText = await kv.get('cti:julioliraup:nrd_domains');
        if (nrdText === null) {
          try {
            const res = await fetch(NRD_FEED_URL, { signal: AbortSignal.timeout(1500) });
            nrdText = res.ok ? await res.text() : '';
          } catch {
            nrdText = '';
          }
          await kv.put('cti:julioliraup:nrd_domains', nrdText.slice(0, 450_000), {
            expirationTtl: 21600,
          });
        }
        if (nrdText) {
          const lines = nrdText.split(/\r?\n/);
          if (
            lines.some((line) => {
              const d = line.trim().toLowerCase();
              return d === registeredDomain || d === fullHost;
            })
          ) {
            return 'NRD_DATASET';
          }
        }
      }
    } catch {
      // Non-blocking fallback when offline or sandboxed
    }
    return null;
  }

  /**
   * Ejecuta el pipeline heurístico completo de análisis de URL y dominio (Técnica julioliraup/Antiphishing)
   */
  static async analyzeUrl(rawOrFinalUrl: string, kv?: KVNamespace): Promise<ScanFindingDTO[]> {
    let parsed: URL;
    try {
      parsed = new URL(rawOrFinalUrl);
    } catch {
      return [];
    }

    const host = parsed.hostname.toLowerCase();
    if (this.isOfficialWhitelistedDomain(host)) {
      return [];
    }

    const findings: ScanFindingDTO[] = [];
    const parts = this.extractDomainParts(host);
    const fullHostAndSub = parts.subdomain
      ? `${parts.subdomain}.${parts.domainLabel}`
      : parts.domainLabel;
    const tokens = fullHostAndSub.split(/[.-]+/).filter(Boolean);

    // 1. Engaño de credenciales embebidas en URL (https://banco.com@sitio-trampa.xyz)
    if (parsed.username || parsed.password || rawOrFinalUrl.includes('@')) {
      const beforePath = rawOrFinalUrl.split('/').slice(0, 3).join('/');
      if (beforePath.includes('@')) {
        findings.push({
          id: CryptoService.generateUlid('fnd'),
          rule_code: 'CTI_URL_USERINFO_MASQUERADE',
          category: 'TRANSPORT',
          severity: 'CRITICAL',
          line_number: 1,
          column_number: 1,
          dom_selector: 'url:cti-userinfo-spoof',
          citizen_explanation:
            'Este enlace usa un truco con el símbolo "@" para mostrarte el nombre de una empresa conocida al principio, pero en realidad te lleva a otra página desconocida.',
          technical_detail: `Técnica Antiphishing CTI: Ofuscación de autoridad RFC 3986 mediante userinfo (@) redirigiendo realmente hacia "${host}".`,
          code_snippet: `URL engañosa detectada -> Destino real: ${host}`,
        });
      }
    }

    // 2. Host IPv4 directo (update_rules.py: is_ipv4 -> dataset ipv4 SID 6000002)
    if (IPV4_REGEX.test(host)) {
      findings.push({
        id: CryptoService.generateUlid('fnd'),
        rule_code: 'CTI_DIRECT_IPV4_PHISHING_HOST',
        category: 'TRANSPORT',
        severity: 'CRITICAL',
        line_number: 1,
        column_number: 1,
        dom_selector: 'url:cti-ipv4-literal',
        citizen_explanation:
          'En lugar de tener el nombre de una empresa o banco real, este enlace usa puros números (una dirección IP suelta). Ningún banco ni comercio legítimo te atiende así.',
        technical_detail: `Técnica Antiphishing CTI (SID 6000002): Acceso directo a literal IPv4 (${host}) evadiendo reputación DNS y certificados corporativos.`,
        code_snippet: `alert ipv4 $HOME_NET any -> [${host}] any (classtype:social-engineering;)`,
      });
    }

    // 3. Correlación con feeds CTI externos (nrd_suspicious_domains.txt / phishing_ips.lst)
    const feedMatch = await this.checkExternalAntiphishingDatasets(
      parts.registeredDomain,
      host,
      kv
    );
    if (feedMatch) {
      findings.push({
        id: CryptoService.generateUlid('fnd'),
        rule_code: 'CTI_ANTIPHISHING_DATASET_MATCH',
        category: 'TRANSPORT',
        severity: 'CRITICAL',
        line_number: 1,
        column_number: 1,
        dom_selector: 'url:cti-dataset-ioc',
        citizen_explanation:
          'Esta dirección web ya aparece reportada en las listas globales de inteligencia temprana contra estafas y dominios recién creados para engañar.',
        technical_detail: `Técnica Antiphishing CTI: Indicador confirmado en dataset público (${feedMatch}) para el host "${host}".`,
        code_snippet: `Dataset Match [${feedMatch}]: ${host}`,
      });
    }

    // 4. Detección de Punycode IDN (xn--) y Homógrafos / Sustitución Visual Leet (0->o, 1->l, 3->e, 4->a, 5->s, rn->m)
    const isPunycode = host.includes('xn--');
    const { normalized: normalizedDomainLabel, hasUnicodeConfusable } =
      this.normalizeLeetAndHomoglyphs(parts.domainLabel);
    const { normalized: normalizedFull } = this.normalizeLeetAndHomoglyphs(fullHostAndSub);

    let matchedBrandImpersonation = false;

    if (isPunycode || hasUnicodeConfusable) {
      findings.push({
        id: CryptoService.generateUlid('fnd'),
        rule_code: 'CTI_IDN_HOMOGLYPH_ATTACK',
        category: 'TRANSPORT',
        severity: 'CRITICAL',
        line_number: 1,
        column_number: 1,
        dom_selector: 'url:cti-idn-homoglyph',
        citizen_explanation:
          '¡Mucho cuidado! Esta dirección usa letras extranjeras o símbolos disfrazados (ataque homógrafo) para verse idéntica a una página real aunque es falsa.',
        technical_detail: `Técnica Antiphishing CTI: Detectada codificación IDN Punycode (xn--) o caracteres Unicode homógrafos en "${host}".`,
        code_snippet: `Host IDN / Homógrafo: ${host}`,
      });
      matchedBrandImpersonation = true;
    }

    // 5. Pipeline NRD / DNSTwist: Suplantación de Marca + Keywords Multilenguaje / Leet / Typosquatting
    for (const brand of PROTECTED_BRANDS) {
      if (matchedBrandImpersonation) break;

      // 5a. Sustitución visual Leet (ej: paypa1, banesc0, g00gle, rnicrosoft)
      const leetContainsBrand =
        (normalizedDomainLabel.includes(brand.name) && !parts.domainLabel.includes(brand.name)) ||
        (normalizedFull.includes(brand.name) && !fullHostAndSub.includes(brand.name));

      const altI = parts.domainLabel.replace(/1/g, 'i').replace(/0/g, 'o');
      const altIContainsBrand = altI.includes(brand.name) && !parts.domainLabel.includes(brand.name);

      if (leetContainsBrand || altIContainsBrand) {
        findings.push({
          id: CryptoService.generateUlid('fnd'),
          rule_code: 'CTI_LEET_HOMOGLYPH_BRAND_SPOOF',
          category: 'TRANSPORT',
          severity: 'CRITICAL',
          line_number: 1,
          column_number: 1,
          dom_selector: 'url:cti-homoglyph-brand',
          citizen_explanation: `¡Alerta de Imitación! La dirección "${host}" cambia letras por números parecidos (como un "0" por una "o" o un "1" por una "l") para hacerse pasar por ${brand.label}.`,
          technical_detail: `Técnica Antiphishing CTI (nrd_processor.py): Sustitución homoglífica/numérica detectada imitando la marca protegida "${brand.label}" (${brand.officialDomains[0]}).`,
          code_snippet: `Dominio falso: ${host} != Dominio oficial: ${brand.officialDomains[0]}`,
        });
        matchedBrandImpersonation = true;
        break;
      }

      // 5b. Combo-Squatting: Marca + Keyword Multilenguaje o Marca + Guion/Dígito o Subdominio engañoso
      if (fullHostAndSub.includes(brand.name)) {
        const matchedKeyword = MULTILANGUAGE_KEYWORDS.find(
          (kw) => fullHostAndSub.includes(kw) || parsed.pathname.toLowerCase().includes(kw)
        );
        const hasHyphenOrDigitAffix = new RegExp(
          `${brand.name}[-\\d]|[-\\d]${brand.name}`
        ).test(fullHostAndSub);
        const isBrandInSubdomain = parts.subdomain.includes(brand.name);

        if (matchedKeyword || hasHyphenOrDigitAffix || isBrandInSubdomain) {
          findings.push({
            id: CryptoService.generateUlid('fnd'),
            rule_code: 'CTI_BRAND_COMBOSQUATTING_IMPERSONATION',
            category: 'TRANSPORT',
            severity: 'CRITICAL',
            line_number: 1,
            column_number: 1,
            dom_selector: 'url:cti-brand-combosquatting',
            citizen_explanation: `¡Peligro de Suplantación! Este enlace usa el nombre de ${brand.label} mezclado con palabras como "${matchedKeyword || 'verificación'}" para engañarte, pero NO es su dirección oficial (${brand.officialDomains[0]}).`,
            technical_detail: `Técnica Antiphishing CTI (nrd_processor.py): Combo-squatting / suplantación estructural de "${brand.label}" en dominio no autorizado "${parts.registeredDomain}".`,
            code_snippet: `Host infractor: ${host} (Oficial esperado: ${brand.officialDomains[0]})`,
          });
          matchedBrandImpersonation = true;
          break;
        }
      }

      // 5c. Typosquatting DNSTwist (Distancia Damerau-Levenshtein 1 o 2 sobre tokens del dominio)
      if (brand.name.length >= 5) {
        const candidateTokens = [parts.domainLabel, ...tokens];
        for (const tok of candidateTokens) {
          if (tok === brand.name || Math.abs(tok.length - brand.name.length) > 2) continue;
          const dist = this.damerauLevenshtein(tok, brand.name);
          const maxAllowedDist = brand.name.length >= 9 ? 2 : 1;
          if (dist >= 1 && dist <= maxAllowedDist) {
            findings.push({
              id: CryptoService.generateUlid('fnd'),
              rule_code: 'CTI_DNSTWIST_TYPOSQUATTING',
              category: 'TRANSPORT',
              severity: 'CRITICAL',
              line_number: 1,
              column_number: 1,
              dom_selector: 'url:cti-dnstwist-typosquatting',
              citizen_explanation: `¡Atención! La dirección "${host}" tiene una letra cambiada, repetida o faltante ("${tok}") para que creas que estás entrando a ${brand.label} (${brand.officialDomains[0]}).`,
              technical_detail: `Técnica Antiphishing CTI (DNSTwist Fuzzer): Permutación typosquatting detectada (distancia Damerau-Levenshtein = ${dist}) respecto a "${brand.name}".`,
              code_snippet: `Token typosquatting: "${tok}" ~ "${brand.name}" (${brand.officialDomains[0]})`,
            });
            matchedBrandImpersonation = true;
            break;
          }
        }
      }
    }

    // 6. Análisis estructural Day-Zero: Múltiples keywords de ingeniería social + guiones múltiples o alta entropía DGA
    if (!matchedBrandImpersonation) {
      const urlLower = `${fullHostAndSub}${parsed.pathname.toLowerCase()}`;
      const matchedLures = MULTILANGUAGE_KEYWORDS.filter((kw) => urlLower.includes(kw));
      const hyphenCount = (parts.domainLabel.match(/-/g) || []).length;

      if (matchedLures.length >= 2 && hyphenCount >= 2) {
        findings.push({
          id: CryptoService.generateUlid('fnd'),
          rule_code: 'CTI_NRD_SOCIAL_ENGINEERING_STRUCTURE',
          category: 'TRANSPORT',
          severity: 'HIGH',
          line_number: 1,
          column_number: 1,
          dom_selector: 'url:cti-lure-structure',
          citizen_explanation: `La dirección web fue armada uniendo varias palabras de anzuelo (${matchedLures.slice(0, 3).join(', ')}) separadas por guiones, una táctica típica de enlaces falsos recién creados.`,
          technical_detail: `Técnica Antiphishing CTI: Patrón léxico de campaña efímera (${hyphenCount} guiones + señuelos: ${matchedLures.slice(0, 4).join(', ')}).`,
          code_snippet: `Estructura señuelo: ${host}${parsed.pathname}`,
        });
      }

      const entropy = this.shannonEntropy(parts.domainLabel.replace(/-/g, ''));
      if (parts.domainLabel.length >= 16 && entropy >= 3.95) {
        findings.push({
          id: CryptoService.generateUlid('fnd'),
          rule_code: 'CTI_HIGH_ENTROPY_EPHEMERAL_HOST',
          category: 'TRANSPORT',
          severity: 'MEDIUM',
          line_number: 1,
          column_number: 1,
          dom_selector: 'url:cti-shannon-entropy',
          citizen_explanation:
            'El nombre de esta página parece generado al azar por computadora, algo muy común en enlaces desechables usados para estafas rápidas.',
          technical_detail: `Técnica Antiphishing CTI: Entropía de Shannon elevada (${entropy.toFixed(2)} bits/símbolo) en etiqueta de dominio "${parts.domainLabel}".`,
          code_snippet: `Shannon H(X) = ${entropy.toFixed(2)} en "${parts.domainLabel}"`,
        });
      }
    }

    return findings;
  }

  /**
   * Genera reglas Suricata IDS/IPS listas para despliegue nacional (DNS, TLS SNI y HTTP)
   * siguiendo la especificación exacta de julioliraup/Antiphishing (rango SID 6090000+).
   */
  static generateSuricataRules(
    items: Array<{
      target_url: string;
      target_domain: string;
      case_number?: string;
      risk_score?: number;
    }>
  ): string {
    const now = new Date();
    const dateTag = now.toISOString().slice(0, 10).replace(/-/g, '_');
    const timestamp = now.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';

    const lines: string[] = [
      '# ============================================================================',
      '# Detector360 x Antiphishing CTI — Reglas Preventivas Suricata IDS/IPS',
      '# Metodología basada en github.com/julioliraup/Antiphishing (DNS / TLS SNI / HTTP)',
      `# Generado para C.I.C.P.C (DIDI): ${timestamp}`,
      '# SID Range Local Asignado: 6090000 - 6099999',
      '# ============================================================================',
      '',
    ];

    const seenDomains = new Set<string>();
    let sid = 6090001;

    for (const item of items) {
      const domain = (item.target_domain || '').toLowerCase().trim();
      if (!domain || seenDomains.has(domain)) continue;
      seenDomains.add(domain);

      let uriPath = '/';
      try {
        const parsed = new URL(item.target_url);
        uriPath = (parsed.pathname || '/').replace(/;/g, '|3b|').replace(/"/g, '');
      } catch {
        uriPath = '/';
      }

      const defanged = `${domain}${uriPath}`.replace(/\./g, ' .').replace(/;/g, '\\;');
      const refTag = item.case_number ? ` [${item.case_number}]` : '';

      if (IPV4_REGEX.test(domain)) {
        lines.push(
          `alert ipv4 $HOME_NET any -> [${domain}] any (msg:"D360-AT IP to phishing host (${domain})${refTag}"; classtype:social-engineering; sid:${sid++}; rev:1; metadata: signature_severity Major, created_et ${dateTag};)`
        );
      } else {
        // 1. Capa DNS (dns.query)
        lines.push(
          `alert dns $HOME_NET any -> any any (msg:"D360-AT DNS query to phishing domain (${domain})${refTag}"; dns.query; content:"${domain}"; nocase; endswith; classtype:social-engineering; sid:${sid++}; rev:1; metadata: signature_severity Major, created_et ${dateTag};)`
        );

        // 2. Capa TLS SNI sin descifrado HTTPS (tls.sni)
        lines.push(
          `alert tls $HOME_NET any -> any any (msg:"D360-AT TLS SNI to phishing domain (${domain})${refTag}"; tls.sni; content:"${domain}"; nocase; endswith; classtype:social-engineering; sid:${sid++}; rev:1; metadata: signature_severity Major, created_et ${dateTag};)`
        );

        // 3. Capa HTTP URI + Host (formato idéntico a update_rules.py de julioliraup/Antiphishing)
        lines.push(
          `alert http $HOME_NET any -> any any (msg:"D360-AT related malicious URL (${defanged})${refTag}"; flow:established,to_server; http.uri; content:"${uriPath}"; startswith; fast_pattern; http.host; content:"${domain}"; endswith; classtype:social-engineering; sid:${sid++}; rev:1; metadata: signature_severity Major, created_et ${dateTag};)`
        );
      }

      lines.push('');
    }

    return lines.join('\n');
  }
}
