import type {
  CurlInspectionResultDTO,
  ExfiltrationDestinationDTO,
  ExfiltrationDestinationType,
  HostingIntelDTO,
  KVNamespace,
  PhishingForensicsDossierDTO,
  RiskLevel,
  TransportAuditResult,
  WhoisRdapAuditDTO,
} from '../types.ts';
import { SsrfGuardService } from './ssrf-guard.service.ts';
import { AntiphishingCtiService } from './url-heuristics.service.ts';

interface DnsJsonAnswer {
  name?: string;
  type?: number;
  TTL?: number;
  data?: string;
}

interface IpWhoisResponse {
  success?: boolean;
  ip?: string;
  country?: string;
  region?: string;
  city?: string;
  connection?: {
    asn?: number;
    org?: string;
    isp?: string;
    domain?: string;
  };
}

function sanitizePreviewText(raw: string, maxChars = 620): string {
  return raw
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '')
    .trim()
    .slice(0, maxChars);
}

function isLabShowcaseDomain(hostname: string): boolean {
  const h = hostname.toLowerCase();
  return (
    h.endsWith('.ejemplo.xyz') ||
    h.endsWith('.phishing-demo.xyz') ||
    h.endsWith('.ejemplo.app') ||
    h.endsWith('.ejemplo.com') ||
    h.endsWith('.ejemplo.org') ||
    h.endsWith('.detector360.ejemplo') ||
    h.endsWith('.ejemplo')
  );
}

export class PhishingForensicsService {
  /**
   * Construye el expediente forense integral sobre infraestructura phishing:
   * 1. Hosting, IP, ASN, DNS (A, AAAA, CNAME, NS, MX, TXT) y software del servidor.
   * 2. Registros WHOIS / RDAP (Registrador, Creación, Antigüedad, Estado y Contacto Abuse).
   * 3. Análisis minucioso de repositorios y destinos donde se envía la información robada.
   * 4. Consultas tipo `curl -iLs` hacia la URL, archivos receptores en el mismo servidor,
   *    directorios padre expuestos (`Index of /`) y servidores receptores externos.
   */
  static async buildForensicDossier(params: {
    finalUrl: string;
    targetDomain: string;
    riskLevel: RiskLevel;
    riskScore: number;
    transport: TransportAuditResult;
    bundleCorpus?: string;
    kv: KVNamespace;
  }): Promise<PhishingForensicsDossierDTO> {
    const generatedAt = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
    const host = params.targetDomain.toLowerCase();
    const isSimulatedLab = params.transport.simulatedDemo && isLabShowcaseDomain(host);

    // 1 & 2. Run Hosting/DNS Intelligence and WHOIS/RDAP Lookup in parallel
    const hostingIntel = await this.resolveHostingIntelligence(
      host,
      params.transport,
      isSimulatedLab,
      params.kv
    );

    const whoisRdap = await this.resolveWhoisRdap(
      host,
      hostingIntel.nameservers,
      isSimulatedLab,
      params.kv
    );

    // 3. Deep Analysis of Exfiltration Destinations & Linked Code Repositories
    const exfiltrationDestinations = await this.analyzeExfiltrationDestinations({
      html: params.transport.htmlContent || '',
      bundleCorpus: params.bundleCorpus || '',
      finalUrl: params.finalUrl,
      pageHost: host,
      isSimulatedLab,
      kv: params.kv,
    });

    // 4. Execute safe `curl -iLs` inspections against entry page, SAME-SERVER files/directories & drop endpoints
    const curlInspections = await this.executeCurlInspections({
      finalUrl: params.finalUrl,
      pageHost: host,
      transport: params.transport,
      destinations: exfiltrationDestinations,
      isSimulatedLab,
    });

    const isPhishingOrSuspicious = params.riskLevel !== 'SAFE' || params.riskScore >= 30;
    const sameServerCount = exfiltrationDestinations.filter((d) => d.is_same_server).length;
    const externalCount = exfiltrationDestinations.length - sameServerCount;
    const ageLabel =
      whoisRdap.domain_age_days !== null
        ? `registrado hace ${whoisRdap.domain_age_days} día(s) vía ${whoisRdap.registrar_name}`
        : `gestionado bajo ${whoisRdap.registrar_name}`;

    const executiveSummary = [
      `Infraestructura alojada en ${hostingIntel.hosting_provider} (${hostingIntel.asn} • ${hostingIntel.country}), dominio ${ageLabel}.`,
      exfiltrationDestinations.length > 0
        ? `Se identificaron ${exfiltrationDestinations.length} destino(s)/repositorio(s) de envío de información (${sameServerCount} archivo(s) dentro del mismo servidor y ${externalCount} receptor(es) externo(s)) y se ejecutaron ${curlInspections.length} consulta(s) forenses tipo cURL.`
        : `Se ejecutaron ${curlInspections.length} consulta(s) forenses tipo cURL sobre la ruta activa del servidor sin detectar receptores abiertos adicionales.`,
    ].join(' ');

    return {
      executed: true,
      generated_at: generatedAt,
      is_phishing_or_suspicious: isPhishingOrSuspicious,
      executive_summary: executiveSummary,
      hosting_intel: hostingIntel,
      whois_rdap: whoisRdap,
      exfiltration_destinations: exfiltrationDestinations,
      curl_inspections: curlInspections,
    };
  }

  // --------------------------------------------------------------------------
  // 1. HOSTING, DNS, IP, ASN & SERVER FINGERPRINTING
  // --------------------------------------------------------------------------
  private static async resolveHostingIntelligence(
    host: string,
    transport: TransportAuditResult,
    isSimulatedLab: boolean,
    kv: KVNamespace
  ): Promise<HostingIntelDTO> {
    if (isSimulatedLab) {
      const isAppCloud = host.endsWith('.ejemplo.app');
      return {
        queried_host: host,
        ip_addresses: isAppCloud ? ['76.76.21.21', '76.76.21.98'] : ['185.215.113.44'],
        ipv6_addresses: isAppCloud ? ['2606:4700:3030::6815:1515'] : [],
        cname_chain: isAppCloud ? [`cname.edge-free-cloud.net`] : [],
        hosting_provider: isAppCloud
          ? 'Edge Serverless Free Cloud (Alojamiento Efímero)'
          : 'Bulletproof Offshore Shared Hosting (cPanel / LiteSpeed)',
        asn: isAppCloud ? 'AS13335 / AS16509 Cloud Edge' : 'AS209605 HostBaltic Networks UAB',
        isp_organization: isAppCloud ? 'Free Static App Hosting LLC' : 'Offshore VPS Datacenter Ltd',
        country: isAppCloud ? 'Estados Unidos (US)' : 'Países Bajos (NL)',
        region_city: isAppCloud ? 'Ashburn, Virginia' : 'Ámsterdam, Noord-Holland',
        server_software:
          transport.rawHeaders?.['server'] ||
          (isAppCloud ? 'cloudflare / edge-runtime' : 'LiteSpeed (PHP/8.1.29)'),
        cdn_or_waf_behind: isAppCloud ? 'Proxy CDN Edge Activo' : null,
        nameservers: isAppCloud
          ? ['ns1.free-cloud-dns.net', 'ns2.free-cloud-dns.net']
          : ['ns1.parking-offshore.xyz', 'ns2.parking-offshore.xyz'],
        mx_records: [],
        txt_records: ['v=spf1 +a +mx ~all'],
        infrastructure_notes: isAppCloud
          ? 'Despliegue gratuito efímero con certificado TLS automático para simular candado seguro.'
          : 'Servidor compartido con intérprete PHP activo utilizado para alojar kits de captura de credenciales.',
      };
    }

    const cacheKey = `forensic_host:v1:${host}`;
    const cached = await kv.get<HostingIntelDTO>(cacheKey, 'json');
    if (cached) return cached;

    const [aAns, aaaaAns, nsAns, mxAns, txtAns] = await Promise.all([
      this.queryDoh(host, 'A'),
      this.queryDoh(host, 'AAAA'),
      this.queryDoh(AntiphishingCtiService.extractDomainParts(host).registeredDomain, 'NS'),
      this.queryDoh(AntiphishingCtiService.extractDomainParts(host).registeredDomain, 'MX'),
      this.queryDoh(AntiphishingCtiService.extractDomainParts(host).registeredDomain, 'TXT'),
    ]);

    const ipAddresses = aAns
      .filter((r) => r.type === 1 && r.data)
      .map((r) => String(r.data).trim());
    const cnameChain = aAns
      .filter((r) => r.type === 5 && r.data)
      .map((r) => String(r.data).replace(/\.$/, ''));
    const ipv6Addresses = aaaaAns
      .filter((r) => r.type === 28 && r.data)
      .map((r) => String(r.data).trim());
    const nameservers = nsAns
      .filter((r) => r.type === 2 && r.data)
      .map((r) => String(r.data).replace(/\.$/, '').toLowerCase());
    const mxRecords = mxAns
      .filter((r) => r.type === 15 && r.data)
      .map((r) => String(r.data).replace(/\.$/, '').toLowerCase());
    const txtRecords = txtAns
      .filter((r) => r.type === 16 && r.data)
      .map((r) => String(r.data).replace(/^"|"$/g, '').slice(0, 140))
      .slice(0, 4);

    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) && ipAddresses.length === 0) {
      ipAddresses.push(host);
    }

    let asn = 'ASN no publicado';
    let ispOrg = 'Proveedor no determinado';
    let country = 'No determinado';
    let regionCity = 'N/A';

    if (ipAddresses.length > 0) {
      const ipInfo = await this.lookupIpAsn(ipAddresses[0], kv);
      if (ipInfo) {
        if (ipInfo.connection?.asn) {
          asn = `AS${ipInfo.connection.asn} ${ipInfo.connection.org || ipInfo.connection.isp || ''}`.trim();
        }
        ispOrg = ipInfo.connection?.org || ipInfo.connection?.isp || ispOrg;
        country = ipInfo.country || country;
        regionCity = [ipInfo.city, ipInfo.region].filter(Boolean).join(', ') || 'N/A';
      }
    }

    const headers = transport.rawHeaders || {};
    const serverHeader = headers['server'] || headers['Server'] || '';
    const poweredBy = headers['x-powered-by'] || headers['X-Powered-By'] || '';
    const serverSoftware =
      [serverHeader, poweredBy].filter(Boolean).join(' • ') || 'No revelado en cabeceras HTTP';

    let cdnOrWaf: string | null = null;
    if (headers['cf-ray'] || /cloudflare/i.test(serverHeader) || nameservers.some((n) => n.includes('cloudflare'))) {
      cdnOrWaf = 'Cloudflare Proxy / WAF (Oculta IP real del servidor origen)';
    } else if (headers['x-vercel-id'] || host.endsWith('.vercel.app')) {
      cdnOrWaf = 'Vercel Edge Network';
    } else if (headers['x-nf-request-id'] || host.endsWith('.netlify.app')) {
      cdnOrWaf = 'Netlify Edge CDN';
    } else if (headers['x-amz-cf-id'] || cnameChain.some((c) => c.includes('cloudfront.net'))) {
      cdnOrWaf = 'Amazon CloudFront CDN';
    } else if (cnameChain.some((c) => c.includes('fastly'))) {
      cdnOrWaf = 'Fastly CDN';
    }

    const hostingProvider = this.inferFriendlyHostingName(host, ispOrg, cnameChain, nameservers, serverHeader);

    const intel: HostingIntelDTO = {
      queried_host: host,
      ip_addresses: ipAddresses,
      ipv6_addresses: ipv6Addresses.slice(0, 3),
      cname_chain: cnameChain,
      hosting_provider: hostingProvider,
      asn,
      isp_organization: ispOrg,
      country,
      region_city: regionCity,
      server_software: serverSoftware,
      cdn_or_waf_behind: cdnOrWaf,
      nameservers: nameservers.slice(0, 6),
      mx_records: mxRecords.slice(0, 4),
      txt_records: txtRecords,
      infrastructure_notes:
        mxRecords.length === 0
          ? 'Dominio sin servidores de correo corporativo (MX vacíos), típico de dominios creados exclusivamente como páginas señuelo web.'
          : `Infraestructura DNS activa con ${ipAddresses.length} registro(s) IPv4 y ${nameservers.length} servidor(es) NS.`,
    };

    await kv.put(cacheKey, JSON.stringify(intel), { expirationTtl: 21600 });
    return intel;
  }

  private static inferFriendlyHostingName(
    host: string,
    ispOrg: string,
    cnames: string[],
    nameservers: string[],
    serverHeader: string
  ): string {
    const combined = `${host} ${ispOrg} ${cnames.join(' ')} ${nameservers.join(' ')} ${serverHeader}`.toLowerCase();
    if (host.endsWith('.vercel.app') || combined.includes('vercel')) return 'Vercel Inc. (Cloud App Hosting)';
    if (host.endsWith('.netlify.app') || combined.includes('netlify')) return 'Netlify, Inc. (Static/Edge Hosting)';
    if (host.endsWith('.pages.dev') || combined.includes('cloudflare')) return 'Cloudflare, Inc. (Edge / Proxy)';
    if (host.endsWith('.web.app') || host.endsWith('.firebaseapp.com')) return 'Google Firebase Hosting';
    if (host.endsWith('.github.io') || combined.includes('github')) return 'GitHub Pages (Microsoft)';
    if (combined.includes('namecheap') || combined.includes('registrar-servers')) return 'Namecheap, Inc. Hosting';
    if (combined.includes('hostinger')) return 'Hostinger International Ltd.';
    if (combined.includes('digitalocean')) return 'DigitalOcean, LLC';
    if (combined.includes('hetzner')) return 'Hetzner Online GmbH';
    if (combined.includes('ovh')) return 'OVH SAS';
    if (combined.includes('amazon') || combined.includes('aws')) return 'Amazon Web Services (AWS)';
    if (combined.includes('google')) return 'Google Cloud Platform (GCP)';
    if (ispOrg && ispOrg !== 'Proveedor no determinado') return ispOrg;
    return serverHeader ? `Servidor HTTP (${serverHeader})` : 'Hosting No Identificado / Servidor Caído';
  }

  // --------------------------------------------------------------------------
  // 2. WHOIS / RDAP OFFICIAL DOMAIN REGISTRY AUDIT
  // --------------------------------------------------------------------------
  private static async resolveWhoisRdap(
    host: string,
    dnsNameservers: string[],
    isSimulatedLab: boolean,
    kv: KVNamespace
  ): Promise<WhoisRdapAuditDTO> {
    const registeredDomain = AntiphishingCtiService.extractDomainParts(host).registeredDomain;

    if (isSimulatedLab) {
      const createdDate = new Date(Date.now() - 3 * 86400 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
      const expDate = new Date(Date.now() + 362 * 86400 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
      return {
        queried_domain: registeredDomain,
        lookup_source: 'Registro Forense Simulado (Entorno Demostrativo)',
        registrar_name: 'NameSilo, LLC',
        registrar_iana_id: '1479',
        creation_date: createdDate,
        updated_date: createdDate,
        expiration_date: expDate,
        domain_age_days: 3,
        domain_status: ['clientTransferProhibited'],
        registrant_organization: 'REDACTED FOR PRIVACY (PrivacyGuardian.org)',
        abuse_contact_email: 'abuse@namesilo.com',
        abuse_contact_phone: '+1.4805240066',
        nameservers: dnsNameservers,
        raw_whois_lines: [
          `Domain Name: ${registeredDomain.toUpperCase()}`,
          `Registrar: NameSilo, LLC`,
          `Registrar IANA ID: 1479`,
          `Creation Date: ${createdDate}`,
          `Registry Expiry Date: ${expDate}`,
          `Registrar Abuse Contact Email: abuse@namesilo.com`,
          `Registrar Abuse Contact Phone: +1.4805240066`,
          `Domain Status: clientTransferProhibited`,
          `Registrant Organization: REDACTED FOR PRIVACY (PrivacyGuardian.org)`,
          ...dnsNameservers.map((ns) => `Name Server: ${ns.toUpperCase()}`),
        ],
        forensic_assessment:
          'ALERTA CRÍTICA DE ANTIGÜEDAD: Dominio descartable registrado hace apenas 3 días con ocultamiento de identidad WHOIS.',
      };
    }

    const cacheKey = `forensic_whois:v1:${registeredDomain}`;
    const cached = await kv.get<WhoisRdapAuditDTO>(cacheKey, 'json');
    if (cached) return cached;

    try {
      const res = await fetch(
        `https://rdap.org/domain/${encodeURIComponent(registeredDomain)}`,
        {
          method: 'GET',
          redirect: 'follow',
          signal: AbortSignal.timeout(2800),
          headers: {
            Accept: 'application/rdap+json, application/json',
            'User-Agent': 'Detector360-RDAP-Client/1.0',
          },
        }
      );

      if (res.ok) {
        const rdap = (await res.json()) as Record<string, unknown>;
        const parsed = this.parseRdapDocument(registeredDomain, rdap, dnsNameservers);
        await kv.put(cacheKey, JSON.stringify(parsed), { expirationTtl: 21600 });
        return parsed;
      }
    } catch {
      // Fallback below when TLD lacks public RDAP responder
    }

    const tld = registeredDomain.split('.').pop()?.toLowerCase() || '';
    const nicHint =
      tld === 've'
        ? 'NIC.VE (CONATEL Venezuela — whois.nic.ve)'
        : `Registro TLD .${tld.toUpperCase()} (Sin pasarela RDAP pública abierta)`;

    const fallback: WhoisRdapAuditDTO = {
      queried_domain: registeredDomain,
      lookup_source: nicHint,
      registrar_name: tld === 've' ? 'NIC.VE - Centro de Información de Red de Venezuela' : `Registro Nacional/TLD (.${tld})`,
      registrar_iana_id: null,
      creation_date: null,
      updated_date: null,
      expiration_date: null,
      domain_age_days: null,
      domain_status: dnsNameservers.length > 0 ? ['active (DNS delegados)'] : ['no-rdap-record'],
      registrant_organization: 'Protegido por política del Registro TLD / GDPR',
      abuse_contact_email: tld === 've' ? 'abuso@nic.ve' : null,
      abuse_contact_phone: null,
      nameservers: dnsNameservers,
      raw_whois_lines: [
        `Domain Name: ${registeredDomain.toUpperCase()}`,
        `Registry / NIC: ${nicHint}`,
        `DNS Delegation: ${dnsNameservers.length > 0 ? 'ACTIVE' : 'UNRESOLVED'}`,
        ...dnsNameservers.map((ns) => `Name Server: ${ns.toUpperCase()}`),
      ],
      forensic_assessment:
        dnsNameservers.length > 0
          ? `Dominio activo en zona .${tld}; servidores autoritativos: ${dnsNameservers.join(', ')}.`
          : `El dominio ${registeredDomain} no presenta delegación DNS activa ni registro RDAP público.`,
    };

    await kv.put(cacheKey, JSON.stringify(fallback), { expirationTtl: 7200 });
    return fallback;
  }

  private static parseRdapDocument(
    registeredDomain: string,
    rdap: Record<string, unknown>,
    fallbackNs: string[]
  ): WhoisRdapAuditDTO {
    let creationDate: string | null = null;
    let updatedDate: string | null = null;
    let expirationDate: string | null = null;

    const events = Array.isArray(rdap.events) ? (rdap.events as Array<Record<string, unknown>>) : [];
    for (const ev of events) {
      const action = String(ev.eventAction || '').toLowerCase();
      const dateStr = typeof ev.eventDate === 'string' ? ev.eventDate : null;
      if (!dateStr) continue;
      if (action === 'registration') creationDate = dateStr;
      else if (action === 'expiration') expirationDate = dateStr;
      else if (action === 'last changed' || action === 'last update of rdap database') {
        if (!updatedDate) updatedDate = dateStr;
      }
    }

    let domainAgeDays: number | null = null;
    if (creationDate) {
      const createdMs = Date.parse(creationDate);
      if (!Number.isNaN(createdMs)) {
        domainAgeDays = Math.max(0, Math.floor((Date.now() - createdMs) / 86400000));
      }
    }

    let registrarName = 'Registrador acreditado ICANN';
    let registrarIanaId: string | null = null;
    let abuseEmail: string | null = null;
    let abusePhone: string | null = null;
    let registrantOrg = 'REDACTED FOR PRIVACY / Protección GDPR';

    const entities = Array.isArray(rdap.entities)
      ? (rdap.entities as Array<Record<string, unknown>>)
      : [];

    for (const ent of entities) {
      const roles = Array.isArray(ent.roles) ? ent.roles.map((r) => String(r).toLowerCase()) : [];
      const vcard = this.extractVcardFields(ent.vcardArray);

      if (roles.includes('registrar')) {
        if (vcard.fn || vcard.org) registrarName = vcard.fn || vcard.org || registrarName;
        if (Array.isArray(ent.publicIds)) {
          const iana = (ent.publicIds as Array<Record<string, unknown>>).find((p) =>
            String(p.type || '').toLowerCase().includes('iana')
          );
          if (iana?.identifier) registrarIanaId = String(iana.identifier);
        }
        // Inspect nested abuse contact inside registrar entity
        if (Array.isArray(ent.entities)) {
          for (const sub of ent.entities as Array<Record<string, unknown>>) {
            const subRoles = Array.isArray(sub.roles)
              ? sub.roles.map((r) => String(r).toLowerCase())
              : [];
            if (subRoles.includes('abuse')) {
              const subVc = this.extractVcardFields(sub.vcardArray);
              if (subVc.email) abuseEmail = subVc.email;
              if (subVc.tel) abusePhone = subVc.tel;
            }
          }
        }
      }

      if (roles.includes('abuse')) {
        if (vcard.email && !abuseEmail) abuseEmail = vcard.email;
        if (vcard.tel && !abusePhone) abusePhone = vcard.tel;
      }

      if (roles.includes('registrant') && (vcard.org || vcard.fn)) {
        registrantOrg = vcard.org || vcard.fn || registrantOrg;
      }
    }

    const domainStatus = Array.isArray(rdap.status)
      ? rdap.status.map((s) => String(s))
      : [];

    const rdapNs = Array.isArray(rdap.nameservers)
      ? (rdap.nameservers as Array<Record<string, unknown>>)
          .map((n) => String(n.ldhName || '').toLowerCase())
          .filter(Boolean)
      : [];
    const nameservers = rdapNs.length > 0 ? rdapNs : fallbackNs;

    const rawLines: string[] = [
      `Domain Name: ${String(rdap.ldhName || registeredDomain).toUpperCase()}`,
      `Registrar: ${registrarName}`,
      ...(registrarIanaId ? [`Registrar IANA ID: ${registrarIanaId}`] : []),
      ...(creationDate ? [`Creation Date: ${creationDate}`] : []),
      ...(updatedDate ? [`Updated Date: ${updatedDate}`] : []),
      ...(expirationDate ? [`Registry Expiry Date: ${expirationDate}`] : []),
      ...(abuseEmail ? [`Registrar Abuse Contact Email: ${abuseEmail}`] : []),
      ...(abusePhone ? [`Registrar Abuse Contact Phone: ${abusePhone}`] : []),
      `Registrant Organization: ${registrantOrg}`,
      ...domainStatus.map((st) => `Domain Status: ${st}`),
      ...nameservers.map((ns) => `Name Server: ${ns.toUpperCase()}`),
    ];

    let assessment = `Dominio registrado con ${registrarName}.`;
    if (domainAgeDays !== null && domainAgeDays <= 30) {
      assessment = `ALERTA DE DOMINIO RECIÉN CREADO (NRD): Registrado hace apenas ${domainAgeDays} día(s) en ${registrarName}. Altísima correlación con campañas efímeras de phishing.`;
    } else if (domainAgeDays !== null && domainAgeDays <= 180) {
      assessment = `Dominio de corta antigüedad (${domainAgeDays} días) gestionado en ${registrarName}.`;
    } else if (domainAgeDays !== null) {
      assessment = `Dominio con ${domainAgeDays} días de antigüedad registrado en ${registrarName} (si aloja phishing, podría tratarse de un subdominio gratuito o un sitio WordPress/cPanel comprometido).`;
    }

    return {
      queried_domain: registeredDomain,
      lookup_source: 'RDAP Oficial ICANN / Registro Autorizado en Vivo',
      registrar_name: registrarName,
      registrar_iana_id: registrarIanaId,
      creation_date: creationDate,
      updated_date: updatedDate,
      expiration_date: expirationDate,
      domain_age_days: domainAgeDays,
      domain_status: domainStatus,
      registrant_organization: registrantOrg,
      abuse_contact_email: abuseEmail,
      abuse_contact_phone: abusePhone,
      nameservers,
      raw_whois_lines: rawLines,
      forensic_assessment: assessment,
    };
  }

  private static extractVcardFields(vcardArray: unknown): {
    fn?: string;
    org?: string;
    email?: string;
    tel?: string;
  } {
    const out: { fn?: string; org?: string; email?: string; tel?: string } = {};
    if (!Array.isArray(vcardArray) || !Array.isArray(vcardArray[1])) return out;
    for (const entry of vcardArray[1] as unknown[]) {
      if (!Array.isArray(entry) || entry.length < 4) continue;
      const key = String(entry[0] || '').toLowerCase();
      const val = String(entry[3] || '').trim();
      if (!val) continue;
      if (key === 'fn' && !out.fn) out.fn = val;
      if (key === 'org' && !out.org) out.org = val;
      if (key === 'email' && !out.email) out.email = val;
      if (key === 'tel' && !out.tel) out.tel = val.replace(/^tel:/i, '');
    }
    return out;
  }

  // --------------------------------------------------------------------------
  // 3. DEEP ANALYSIS OF EXFILTRATION REPOSITORIES & DESTINATIONS
  // --------------------------------------------------------------------------
  private static async analyzeExfiltrationDestinations(params: {
    html: string;
    bundleCorpus: string;
    finalUrl: string;
    pageHost: string;
    isSimulatedLab: boolean;
    kv: KVNamespace;
  }): Promise<ExfiltrationDestinationDTO[]> {
    const destinations: ExfiltrationDestinationDTO[] = [];
    const seenUrls = new Set<string>();
    const fullCode = `${params.html}\n${params.bundleCorpus}`;

    const addDestination = (entry: ExfiltrationDestinationDTO) => {
      const key = `${entry.http_method}:${entry.destination_url}`;
      if (seenUrls.has(key)) return;
      seenUrls.add(key);
      destinations.push(entry);
    };

    // A. Inspect <form ...> blocks and extract exact input field names being stolen
    const formBlockRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
    let fm: RegExpExecArray | null;
    let formIdx = 0;
    while ((fm = formBlockRe.exec(params.html)) !== null) {
      formIdx++;
      const openAttrs = fm[1] || '';
      const innerHtml = fm[2] || '';

      const actionMatch = openAttrs.match(/\baction\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
      const methodMatch = openAttrs.match(/\bmethod\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
      const rawAction = actionMatch
        ? (actionMatch[1] ?? actionMatch[2] ?? actionMatch[3] ?? '').trim()
        : '';
      const method = (
        methodMatch ? methodMatch[1] ?? methodMatch[2] ?? methodMatch[3] ?? 'POST' : 'POST'
      ).toUpperCase();

      // Extract input field names inside this form
      const capturedFields: string[] = [];
      const inputRe = /<(?:input|select|textarea)\b[^>]*>/gi;
      let im: RegExpExecArray | null;
      while ((im = inputRe.exec(innerHtml)) !== null) {
        const tag = im[0];
        if (/type\s*=\s*["']?(?:submit|button|reset)["']?/i.test(tag)) continue;
        const nameM = tag.match(/\b(?:name|id|placeholder)\s*=\s*(?:"([^"]+)"|'([^']+)')/i);
        if (nameM) {
          const fieldName = (nameM[1] || nameM[2] || '').trim().slice(0, 42);
          if (fieldName && !capturedFields.includes(fieldName)) capturedFields.push(fieldName);
        }
      }

      if (capturedFields.length === 0 && !rawAction) continue;

      let resolvedActionUrl = params.finalUrl;
      if (rawAction && !rawAction.startsWith('javascript:') && rawAction !== '#') {
        try {
          resolvedActionUrl = new URL(rawAction, params.finalUrl).toString();
        } catch {
          continue;
        }
      }

      try {
        const parsedDest = new URL(resolvedActionUrl);
        const destHost = parsedDest.hostname.toLowerCase();
        const isSameServer = destHost === params.pageHost;
        const destType = this.classifyDestinationType(resolvedActionUrl, isSameServer);

        addDestination({
          destination_url: resolvedActionUrl,
          destination_host: destHost,
          destination_path: parsedDest.pathname + parsedDest.search,
          destination_type: destType,
          is_same_server: isSameServer,
          http_method: method,
          source_location: `Formulario HTML #${formIdx} (<form action="${rawAction || '(misma ruta)'}">)`,
          captured_fields: capturedFields.slice(0, 8),
          repository_or_collector_id: isSameServer
            ? `Archivo interno del servidor (${parsedDest.pathname})`
            : `Receptor remoto en ${destHost}`,
          resolved_ip_and_asn: null,
          forensic_detail: isSameServer
            ? `El formulario envía [${capturedFields.join(', ') || 'datos'}] mediante ${method} hacia el archivo interno ${parsedDest.pathname} alojado dentro del mismo servidor (${destHost}).`
            : `El formulario desvía [${capturedFields.join(', ') || 'credenciales'}] hacia un servidor receptor externo (${destHost}${parsedDest.pathname}).`,
        });
      } catch {
        // ignore invalid URL
      }
    }

    // B. Decode Base64 `atob("...")` hidden URLs inside phishing scripts!
    const atobRe = /\batob\s*\(\s*["']([A-Za-z0-9+/=]{12,260})["']\s*\)/g;
    let am: RegExpExecArray | null;
    while ((am = atobRe.exec(fullCode)) !== null) {
      try {
        const decoded = atob(am[1]).trim();
        if (/^https?:\/\/|^\/[a-zA-Z0-9_/-]+/i.test(decoded)) {
          const resolved = new URL(decoded, params.finalUrl);
          const isSame = resolved.hostname.toLowerCase() === params.pageHost;
          addDestination({
            destination_url: resolved.toString(),
            destination_host: resolved.hostname.toLowerCase(),
            destination_path: resolved.pathname + resolved.search,
            destination_type: this.classifyDestinationType(resolved.toString(), isSame),
            is_same_server: isSame,
            http_method: 'POST / BEACON',
            source_location: 'Script ofuscado Base64 atob(...)',
            captured_fields: ['pulsaciones_teclado_keyup', 'inputs_formulario'],
            repository_or_collector_id: `Payload Base64 decodificado -> ${resolved.hostname}${resolved.pathname}`,
            resolved_ip_and_asn: null,
            forensic_detail: `Dirección de exfiltración escondida con codificación Base64 (atob) para evadir revisiones superficiales.`,
          });
        }
      } catch {
        // ignore invalid base64
      }
    }

    // C. Inspect JS network calls (`fetch`, `sendBeacon`, `axios`, `XMLHttpRequest`) & Cloud/Bot Repos
    const jsEndpointPatterns: Array<{
      regex: RegExp;
      methodHint: string;
      sourceHint: string;
    }> = [
      {
        regex: /https?:\/\/api\.telegram\.org\/bot([0-9]{6,12}:[A-Za-z0-9_-]{10,})\/[A-Za-z]+(?:\?[^\s"'<>]*)?/gi,
        methodHint: 'POST',
        sourceHint: 'API de Bot de Telegram en JavaScript',
      },
      {
        regex: /https?:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/([0-9]+\/[A-Za-z0-9_-]+)/gi,
        methodHint: 'POST',
        sourceHint: 'Webhook de Discord en JavaScript',
      },
      {
        regex: /https?:\/\/raw\.githubusercontent\.com\/([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)\/[^\s"'<>]+/gi,
        methodHint: 'GET',
        sourceHint: 'Repositorio GitHub vinculado al kit',
      },
      {
        regex: /https?:\/\/(?:[a-z0-9-]+\.supabase\.co|[a-z0-9-]+\.firebaseio\.com|script\.google\.com\/macros\/s\/[A-Za-z0-9_-]+\/exec|formspree\.io\/f\/[A-Za-z0-9]+|webhook\.site\/[A-Za-z0-9-]+)[^\s"'<>]*/gi,
        methodHint: 'POST',
        sourceHint: 'Backend Cloud / Colector Serverless',
      },
      {
        regex: /\b(?:fetch|sendBeacon|axios\.post)\s*\(\s*["']((?:https?:\/\/|\/|\.\.?\/)[^"'\s]{2,180})["']/gi,
        methodHint: 'POST',
        sourceHint: 'Llamada asíncrona fetch/sendBeacon en JS',
      },
    ];

    for (const pat of jsEndpointPatterns) {
      let jm: RegExpExecArray | null;
      while ((jm = pat.regex.exec(fullCode)) !== null) {
        const candidateRaw = pat.regex.source.startsWith('\\b(?:fetch') ? jm[1] : jm[0];
        if (!candidateRaw) continue;
        try {
          const resolved = new URL(candidateRaw, params.finalUrl);
          const destHost = resolved.hostname.toLowerCase();
          // Ignore static images/fonts in generic fetch match
          if (/\.(?:png|jpg|jpeg|gif|svg|webp|woff2?|css)$/i.test(resolved.pathname)) continue;

          const isSame = destHost === params.pageHost;
          const destType = this.classifyDestinationType(resolved.toString(), isSame);
          let repoId = isSame
            ? `Script interno en el mismo servidor (${resolved.pathname})`
            : `Endpoint remoto (${destHost})`;

          if (destType === 'TELEGRAM_BOT_API') {
            const botIdMatch = resolved.pathname.match(/\/bot([0-9]+):([A-Za-z0-9_-]{5})/);
            const chatIdMatch = fullCode.match(/chat_id["'\s:=]+(-?[0-9]{5,15})/i);
            repoId = `Telegram Bot ID: ${botIdMatch ? botIdMatch[1] : 'detectado'}${
              chatIdMatch ? ` • Chat ID: ${chatIdMatch[1]}` : ''
            }`;
          } else if (destType === 'DISCORD_WEBHOOK') {
            const whMatch = resolved.pathname.match(/\/webhooks\/([0-9]+)/);
            repoId = `Discord Canal/Webhook ID: ${whMatch ? whMatch[1] : 'detectado'}`;
          } else if (destHost === 'raw.githubusercontent.com') {
            const parts = resolved.pathname.split('/').filter(Boolean);
            repoId = `Repositorio GitHub: ${parts.slice(0, 2).join('/')}`;
          }

          addDestination({
            destination_url: resolved.toString(),
            destination_host: destHost,
            destination_path: resolved.pathname + resolved.search,
            destination_type: destType,
            is_same_server: isSame,
            http_method: pat.methodHint,
            source_location: pat.sourceHint,
            captured_fields: ['credenciales_sesion', 'payload_json'],
            repository_or_collector_id: repoId,
            resolved_ip_and_asn: null,
            forensic_detail: isSame
              ? `El código JavaScript transmite los datos capturados hacia un archivo receptor alojado en el mismo servidor (${resolved.pathname}).`
              : `Conexión programada hacia infraestructura externa (${repoId}) para exfiltrar o sincronizar el kit de phishing.`,
          });
        } catch {
          // ignore malformed URL
        }
      }
    }

    // Enrich external drop servers with live DNS IP/ASN (up to 2 external hosts)
    if (!params.isSimulatedLab) {
      let enrichedCount = 0;
      for (const dest of destinations) {
        if (dest.is_same_server || enrichedCount >= 2) continue;
        if (
          dest.destination_type === 'TELEGRAM_BOT_API' ||
          dest.destination_type === 'DISCORD_WEBHOOK'
        ) {
          dest.resolved_ip_and_asn =
            dest.destination_type === 'TELEGRAM_BOT_API'
              ? '149.154.167.220 (AS62041 Telegram Messenger Inc)'
              : '162.159.135.232 (AS13335 Cloudflare / Discord API)';
          continue;
        }
        enrichedCount++;
        const aRecords = await this.queryDoh(dest.destination_host, 'A');
        const firstIp = aRecords.find((r) => r.type === 1 && r.data)?.data;
        if (firstIp) {
          const ipData = await this.lookupIpAsn(firstIp, params.kv);
          const asnTxt = ipData?.connection?.asn
            ? `AS${ipData.connection.asn} ${ipData.connection.org || ''}`.trim()
            : '';
          dest.resolved_ip_and_asn = `${firstIp}${asnTxt ? ` (${asnTxt})` : ''}`;
        }
      }
    } else {
      for (const dest of destinations) {
        if (dest.is_same_server) {
          dest.resolved_ip_and_asn = 'Misma IP del servidor auditado';
        } else if (dest.destination_type === 'TELEGRAM_BOT_API') {
          dest.resolved_ip_and_asn = '149.154.167.220 (AS62041 Telegram Messenger Inc)';
        } else if (dest.destination_type === 'DISCORD_WEBHOOK') {
          dest.resolved_ip_and_asn = '162.159.135.232 (AS13335 Discord / Cloudflare)';
        } else {
          dest.resolved_ip_and_asn = '91.215.85.19 (AS198953 Collector Drop Host)';
        }
      }
    }

    return destinations.slice(0, 8);
  }

  private static classifyDestinationType(
    url: string,
    isSameServer: boolean
  ): ExfiltrationDestinationType {
    const lower = url.toLowerCase();
    if (lower.includes('api.telegram.org/bot')) return 'TELEGRAM_BOT_API';
    if (lower.includes('discord.com/api/webhooks') || lower.includes('discordapp.com/api/webhooks')) {
      return 'DISCORD_WEBHOOK';
    }
    if (
      lower.includes('githubusercontent.com') ||
      lower.includes('github.com') ||
      lower.includes('gitlab.com') ||
      lower.includes('supabase.co') ||
      lower.includes('firebaseio.com')
    ) {
      return 'CLOUD_REPO_OR_BACKEND';
    }
    if (
      lower.includes('formspree.io') ||
      lower.includes('getform.io') ||
      lower.includes('web3forms.com') ||
      lower.includes('emailjs.com') ||
      lower.includes('webhook.site') ||
      lower.includes('script.google.com/macros')
    ) {
      return 'FORM_RELAY_SERVICE';
    }
    return isSameServer ? 'SAME_SERVER_FILE' : 'EXTERNAL_DROP_SERVER';
  }

  // --------------------------------------------------------------------------
  // 4. SAFE READ-ONLY `curl -iLs` INSPECTIONS ON SAME-SERVER FILES & DESTINATIONS
  // --------------------------------------------------------------------------
  private static async executeCurlInspections(params: {
    finalUrl: string;
    pageHost: string;
    transport: TransportAuditResult;
    destinations: ExfiltrationDestinationDTO[];
    isSimulatedLab: boolean;
  }): Promise<CurlInspectionResultDTO[]> {
    const results: CurlInspectionResultDTO[] = [];
    const inspectedSet = new Set<string>();

    // 4.1 Primary entry URL `curl` record from initial connection
    const entryHeaders = Object.entries(params.transport.rawHeaders || {}).map(([name, value]) => ({
      name,
      value,
    }));
    if (entryHeaders.length === 0) {
      entryHeaders.push(
        { name: 'content-type', value: params.transport.contentType || 'text/html' },
        { name: 'protocol', value: params.transport.protocol.toUpperCase() }
      );
    }

    const entryStatus = params.transport.httpStatusCode || 0;
    inspectedSet.add(params.finalUrl);
    results.push({
      target_url: params.finalUrl,
      target_role: 'PHISHING_DOCUMENT',
      is_same_server: true,
      curl_command: `curl -iLs -X GET "${params.finalUrl}" --max-time 5`,
      http_status_line: entryStatus > 0 ? `HTTP/1.1 ${entryStatus} OK` : 'Sin respuesta TCP/HTTP',
      status_code: entryStatus,
      response_time_ms: params.transport.responseTimeMs ?? 48,
      response_headers: entryHeaders.slice(0, 10),
      body_excerpt: sanitizePreviewText(params.transport.htmlContent || '', 520),
      directory_listing_exposed: /<title>\s*Index of \//i.test(params.transport.htmlContent || ''),
      collector_active: entryStatus >= 200 && entryStatus < 400,
      forensic_conclusion:
        entryStatus > 0
          ? `Documento principal servido activamente en ${params.pageHost} (HTTP ${entryStatus}).`
          : `El servidor ${params.pageHost} no devolvió cabeceras HTTP activas.`,
    });

    // 4.2 Collect same-server files + parent directories + external drop servers to inspect via `curl`
    const targetsToProbe: Array<{
      url: string;
      role: CurlInspectionResultDTO['target_role'];
      isSameServer: boolean;
    }> = [];

    for (const dest of params.destinations) {
      if (dest.is_same_server && !inspectedSet.has(dest.destination_url)) {
        inspectedSet.add(dest.destination_url);
        targetsToProbe.push({
          url: dest.destination_url,
          role: 'SAME_SERVER_COLLECTOR_FILE',
          isSameServer: true,
        });

        // Also check parent directory on the same server (e.g. /panel/guardar_claves.php -> /panel/) for open `Index of /`
        try {
          const parsed = new URL(dest.destination_url);
          const slashIdx = parsed.pathname.lastIndexOf('/');
          if (slashIdx > 0) {
            const parentDirUrl = `${parsed.origin}${parsed.pathname.slice(0, slashIdx + 1)}`;
            if (!inspectedSet.has(parentDirUrl)) {
              inspectedSet.add(parentDirUrl);
              targetsToProbe.push({
                url: parentDirUrl,
                role: 'SAME_SERVER_PARENT_DIRECTORY',
                isSameServer: true,
              });
            }
          }
        } catch {
          // ignore
        }
      } else if (
        !dest.is_same_server &&
        dest.destination_type === 'EXTERNAL_DROP_SERVER' &&
        !inspectedSet.has(dest.destination_url)
      ) {
        inspectedSet.add(dest.destination_url);
        targetsToProbe.push({
          url: dest.destination_url,
          role: 'EXTERNAL_DROP_ENDPOINT',
          isSameServer: false,
        });
      }
    }

    // If no explicit sub-file was referenced on a same-server page in subpath (e.g. /pago/login.html), probe parent dir
    if (targetsToProbe.length === 0) {
      try {
        const parsedMain = new URL(params.finalUrl);
        const slashIdx = parsedMain.pathname.lastIndexOf('/');
        if (slashIdx > 0) {
          const parentUrl = `${parsedMain.origin}${parsedMain.pathname.slice(0, slashIdx + 1)}`;
          if (!inspectedSet.has(parentUrl)) {
            inspectedSet.add(parentUrl);
            targetsToProbe.push({
              url: parentUrl,
              role: 'SAME_SERVER_PARENT_DIRECTORY',
              isSameServer: true,
            });
          }
        }
      } catch {
        // ignore
      }
    }

    // Execute up to 4 safe `curl` probes in parallel
    const probePromises = targetsToProbe.slice(0, 4).map((t) =>
      this.runSingleSafeCurlProbe(t.url, t.role, t.isSameServer, params.isSimulatedLab)
    );
    const probed = await Promise.all(probePromises);
    for (const item of probed) {
      if (item) results.push(item);
    }

    return results;
  }

  private static async runSingleSafeCurlProbe(
    targetUrl: string,
    role: CurlInspectionResultDTO['target_role'],
    isSameServer: boolean,
    isSimulatedLab: boolean
  ): Promise<CurlInspectionResultDTO | null> {
    if (isSimulatedLab || isLabShowcaseDomain(new URL(targetUrl).hostname)) {
      return this.buildSimulatedLabCurlResult(targetUrl, role, isSameServer);
    }

    try {
      SsrfGuardService.validatePublicUrl(targetUrl);
    } catch {
      return null;
    }

    const start = Date.now();
    try {
      const res = await fetch(targetUrl, {
        method: 'GET',
        redirect: 'manual',
        signal: AbortSignal.timeout(2600),
        headers: {
          'User-Agent': 'curl/8.7.1',
          Accept: '*/*',
        },
      });

      const latency = Math.max(10, Date.now() - start);
      const headers: Array<{ name: string; value: string }> = [];
      res.headers.forEach((val, key) => {
        headers.push({
          name: key,
          value: key.toLowerCase() === 'set-cookie' ? '[COOKIE REDACTADA]' : val.slice(0, 200),
        });
      });

      let bodyExcerpt = '';
      if (res.body) {
        const reader = res.body.getReader();
        const { value } = await reader.read();
        await reader.cancel().catch(() => {});
        if (value) {
          bodyExcerpt = sanitizePreviewText(
            new TextDecoder('utf-8', { fatal: false }).decode(value.slice(0, 2048)),
            560
          );
        }
      }

      const dirExposed = /Index of \//i.test(bodyExcerpt);
      const allowHeader = res.headers.get('allow') || '';
      const collectorActive =
        (res.status >= 200 && res.status < 400) || res.status === 405 || res.status === 403;

      let conclusion = `Respuesta HTTP ${res.status} obtenida en ${latency} ms.`;
      if (dirExposed) {
        conclusion =
          'HALLAZGO CRÍTICO EN EL MISMO SERVIDOR: El directorio tiene listado abierto ("Index of /"), exponiendo archivos internos del kit de phishing.';
      } else if (role === 'SAME_SERVER_COLLECTOR_FILE' && res.status === 405) {
        conclusion = `CONFIRMADO: El archivo receptor existe en el mismo servidor y exige método POST para recibir datos robados (HTTP 405${
          allowHeader ? ` • Allow: ${allowHeader}` : ''
        }).`;
      } else if (role === 'SAME_SERVER_COLLECTOR_FILE' && res.status >= 200 && res.status < 300) {
        conclusion =
          'CONFIRMADO: El script receptor dentro del mismo servidor existe y responde activamente (HTTP 200), listo para procesar credenciales capturadas.';
      } else if (res.status >= 300 && res.status < 400) {
        conclusion = `El archivo redirige (HTTP ${res.status}) hacia ${
          res.headers.get('location') || 'otra ruta'
        }, comportamiento habitual tras capturar claves para enviar a la víctima al banco real.`;
      } else if (res.status === 404) {
        conclusion = 'El archivo consultado devolvió 404 Not Found (eliminado o ruta dinámica).';
      }

      return {
        target_url: targetUrl,
        target_role: role,
        is_same_server: isSameServer,
        curl_command: `curl -i -s -X GET "${targetUrl}" --max-time 3`,
        http_status_line: `HTTP/1.1 ${res.status} ${res.statusText || ''}`.trim(),
        status_code: res.status,
        response_time_ms: latency,
        response_headers: headers.slice(0, 10),
        body_excerpt: bodyExcerpt || '(Cuerpo HTTP vacío — 0 bytes en petición GET sin parámetros POST)',
        directory_listing_exposed: dirExposed,
        collector_active: collectorActive,
        forensic_conclusion: conclusion,
      };
    } catch {
      return {
        target_url: targetUrl,
        target_role: role,
        is_same_server: isSameServer,
        curl_command: `curl -i -s -X GET "${targetUrl}" --max-time 3`,
        http_status_line: 'curl: (28) Connection timed out / Host unreachable',
        status_code: 0,
        response_time_ms: Date.now() - start,
        response_headers: [],
        body_excerpt: 'Sin respuesta desde el servidor destino.',
        directory_listing_exposed: false,
        collector_active: false,
        forensic_conclusion:
          'El endpoint receptor no respondió a la consulta directa cURL (posiblemente dado de baja o bloqueando conexiones fuera del formulario).',
      };
    }
  }

  private static buildSimulatedLabCurlResult(
    targetUrl: string,
    role: CurlInspectionResultDTO['target_role'],
    isSameServer: boolean
  ): CurlInspectionResultDTO {
    if (role === 'SAME_SERVER_PARENT_DIRECTORY') {
      return {
        target_url: targetUrl,
        target_role: role,
        is_same_server: true,
        curl_command: `curl -i -s -X GET "${targetUrl}" --max-time 3`,
        http_status_line: 'HTTP/1.1 200 OK',
        status_code: 200,
        response_time_ms: 39,
        response_headers: [
          { name: 'server', value: 'LiteSpeed' },
          { name: 'content-type', value: 'text/html; charset=UTF-8' },
        ],
        body_excerpt: [
          'Index of /panel/',
          '  guardar_claves.php      2026-11-12 03:14    2.4K',
          '  config_telegram.php     2026-11-12 03:14    0.8K',
          '  accesos_capturados.txt  2026-11-14 08:41   14.2K',
        ].join('\n'),
        directory_listing_exposed: true,
        collector_active: true,
        forensic_conclusion:
          'HALLAZGO CRÍTICO EN EL MISMO SERVIDOR: La consulta cURL al directorio interno reveló un listado abierto ("Index of /") con scripts PHP de captura y registros de víctimas.',
      };
    }

    if (role === 'SAME_SERVER_COLLECTOR_FILE') {
      return {
        target_url: targetUrl,
        target_role: role,
        is_same_server: true,
        curl_command: `curl -i -s -X GET "${targetUrl}" --max-time 3`,
        http_status_line: 'HTTP/1.1 405 Method Not Allowed',
        status_code: 405,
        response_time_ms: 34,
        response_headers: [
          { name: 'server', value: 'LiteSpeed' },
          { name: 'x-powered-by', value: 'PHP/8.1.29' },
          { name: 'allow', value: 'POST, OPTIONS' },
          { name: 'content-type', value: 'application/json; charset=utf-8' },
        ],
        body_excerpt: '{"ok":false,"error":"POST_REQUIRED","expect":["user","pass","token_sms"]}',
        directory_listing_exposed: false,
        collector_active: true,
        forensic_conclusion:
          'CONFIRMADO EN EL MISMO SERVIDOR: La consulta cURL demostró que el archivo PHP existe y está activo (Allow: POST, OPTIONS), esperando recibir usuario, clave y token SMS.',
      };
    }

    return {
      target_url: targetUrl,
      target_role: role,
      is_same_server: isSameServer,
      curl_command: `curl -i -s -X GET "${targetUrl}" --max-time 3`,
      http_status_line: 'HTTP/1.1 302 Found',
      status_code: 302,
      response_time_ms: 61,
      response_headers: [
        { name: 'server', value: 'nginx/1.24.0' },
        { name: 'x-powered-by', value: 'PHP/8.2.12' },
        { name: 'location', value: 'https://www.banesco.com/' },
      ],
      body_excerpt: '(Redirección 302 poscaptura hacia el banco legítimo para despistar a la víctima)',
      directory_listing_exposed: false,
      collector_active: true,
      forensic_conclusion:
        'El script colector externo está activo y aplica redirección 302 hacia la web real del banco después de robar las credenciales.',
    };
  }

  // --------------------------------------------------------------------------
  // DNS-over-HTTPS & IP/ASN Helpers
  // --------------------------------------------------------------------------
  private static async queryDoh(name: string, type: string): Promise<DnsJsonAnswer[]> {
    try {
      const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(
        name
      )}&type=${encodeURIComponent(type)}`;
      const res = await fetch(url, {
        method: 'GET',
        signal: AbortSignal.timeout(2200),
        headers: { Accept: 'application/dns-json' },
      });
      if (!res.ok) return [];
      const data = (await res.json()) as { Answer?: DnsJsonAnswer[] };
      return Array.isArray(data.Answer) ? data.Answer : [];
    } catch {
      return [];
    }
  }

  private static async lookupIpAsn(
    ip: string,
    kv: KVNamespace
  ): Promise<IpWhoisResponse | null> {
    const cacheKey = `ip_asn:v1:${ip}`;
    const cached = await kv.get<IpWhoisResponse>(cacheKey, 'json');
    if (cached) return cached;

    try {
      const res = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, {
        method: 'GET',
        signal: AbortSignal.timeout(2200),
        headers: { Accept: 'application/json' },
      });
      if (!res.ok) return null;
      const json = (await res.json()) as IpWhoisResponse;
      if (json && json.success !== false) {
        await kv.put(cacheKey, JSON.stringify(json), { expirationTtl: 43200 });
        return json;
      }
      return null;
    } catch {
      return null;
    }
  }
}
