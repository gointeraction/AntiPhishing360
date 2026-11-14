export interface D1PreparedStatement {
  bind(...values: unknown[]): D1PreparedStatement;
  first<T = Record<string, unknown>>(colName?: string): Promise<T | null>;
  run(): Promise<{ success: boolean; meta?: Record<string, unknown> }>;
  all<T = Record<string, unknown>>(): Promise<{ results: T[]; success: boolean }>;
}

export interface D1Database {
  prepare(query: string): D1PreparedStatement;
  batch<T = unknown>(statements: D1PreparedStatement[]): Promise<T[]>;
  exec(query: string): Promise<{ count: number; duration: number }>;
}

export interface KVNamespace {
  get(key: string, type?: 'text'): Promise<string | null>;
  get<T = unknown>(key: string, type: 'json'): Promise<T | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
}

export interface R2Bucket {
  put(
    key: string,
    value: string | ArrayBuffer | Uint8Array,
    options?: { httpMetadata?: { contentType?: string } }
  ): Promise<unknown>;
  get(key: string): Promise<{ text(): Promise<string> } | null>;
}

export interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
  passThroughOnException(): void;
}

export interface Env {
  DB: D1Database;
  KV_CACHE: KVNamespace;
  R2_EVIDENCE: R2Bucket;
  JWT_SECRET?: string;
  JWT_ISSUER?: string;
  CICPC_MASTER_KEY?: string;
  ALLOWED_ORIGIN?: string;
  ENVIRONMENT?: string;
}

export type CicpcOfficerRole = 'COMMANDER' | 'FORENSIC_ANALYST';
export type CicpcCaseStatus =
  | 'pending'
  | 'in_analysis'
  | 'strategic_action'
  | 'mitigated'
  | 'archived';
export type CicpcPriority = 'URGENT' | 'HIGH' | 'NORMAL';
export type CicpcIncidentImpact = 'PREVENTIVE' | 'CREDENTIALS_EXPOSED' | 'FINANCIAL_LOSS';
export type CicpcStrategicAction =
  | 'NONE'
  | 'ISP_DNS_BLOCK_REQUEST'
  | 'REGISTRAR_TAKEDOWN'
  | 'BANKING_FRAUD_ALERT'
  | 'TRACE_EXFILTRATION_SERVER'
  | 'PUBLIC_PREVENTION_BULLETIN'
  | 'FIELD_INVESTIGATION_OPENED';

export interface CicpcOfficer {
  id: string;
  badge_id: string;
  full_name: string;
  rank_title: string;
  role: CicpcOfficerRole;
}

export type PlanTier = 'citizen_free' | 'family_shield' | 'verified_merchant';
export type RiskLevel = 'SAFE' | 'WARNING' | 'CRITICAL';
export type FindingCategory = 'TRANSPORT' | 'DOM_FORM' | 'DOM_INPUT' | 'JS_SCRIPT';
export type FindingSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface AuthUser {
  id: string;
  alias: string;
  email: string;
  plan_tier: PlanTier;
  created_at?: string;
}

export interface RequestContext {
  request: Request;
  env: Env;
  ctx: ExecutionContext;
  params: Record<string, string>;
  clientIp: string;
  user: AuthUser | null;
}

export interface ScanFindingDTO {
  id: string;
  rule_code: string;
  category: FindingCategory;
  severity: FindingSeverity;
  line_number: number;
  column_number: number;
  dom_selector: string;
  citizen_explanation: string;
  technical_detail: string;
  code_snippet: string;
}

export interface SourcePreviewLine {
  line: number;
  content: string;
  has_finding: boolean;
}

export interface TransportAuditResult {
  finalUrl: string;
  targetDomain: string;
  protocol: 'http' | 'https';
  isHttps: boolean;
  httpStatusCode: number;
  redirectCount: number;
  responseTimeMs?: number;
  contentType?: string;
  redirectChain?: string[];
  rawHeaders?: Record<string, string>;
  securityHeaders: {
    strict_transport_security: boolean;
    content_security_policy: boolean;
    x_frame_options: boolean;
  };
  htmlContent: string;
  simulatedDemo: boolean;
}

export type LinkFunctionalityStatus =
  | 'ONLINE_FUNCTIONAL'
  | 'REDIRECT_UNMASKED'
  | 'CLOAKED_CLIENT_REDIRECT'
  | 'BOT_WAF_PROTECTED'
  | 'INACTIVE_OR_TAKEDOWN';

export interface LinkFunctionalityAuditDTO {
  checked_live: boolean;
  reachable: boolean;
  is_functional: boolean;
  functionality_status: LinkFunctionalityStatus;
  http_status_code: number;
  response_time_ms: number;
  content_type: string;
  initial_url: string;
  resolved_final_url: string;
  redirect_hops: number;
  redirect_chain: string[];
  client_redirect_detected: boolean;
  client_redirect_target: string | null;
  spa_bundles_inspected: number;
  login_or_financial_form_active: boolean;
  exfiltration_endpoints: string[];
  summary: string;
}

export interface MatchedBankVisualAssetDTO {
  asset_url: string;
  asset_type: 'favicon' | 'logo_img' | 'og_image' | 'inline_svg' | 'css_or_bundle';
  claimed_bank: string;
  match_method:
    | 'EXACT_OFFICIAL_SHA256'
    | 'PERCEPTUAL_HASH_SIMILARITY'
    | 'HOTLINKED_OFFICIAL_BANK_CDN'
    | 'SVG_OR_LOGO_SIGNATURE'
    | 'DYNAMIC_BANK_BRAND_MISMATCH';
  similarity_percent: number;
  sha256_prefix: string;
  dimensions: string | null;
}

export interface VisualBrandAuditDTO {
  executed: boolean;
  banking_brand_detected: boolean;
  is_official_bank_page: boolean | null;
  detected_institution: string | null;
  official_domain_expected: string | null;
  inspected_domain: string;
  images_inspected_count: number;
  official_reference_compared: boolean;
  highest_similarity_percent: number;
  matched_assets: MatchedBankVisualAssetDTO[];
  verdict_label: string;
  verdict_summary: string;
}

export interface HostingIntelDTO {
  queried_host: string;
  ip_addresses: string[];
  ipv6_addresses: string[];
  cname_chain: string[];
  hosting_provider: string;
  asn: string;
  isp_organization: string;
  country: string;
  region_city: string;
  server_software: string;
  cdn_or_waf_behind: string | null;
  nameservers: string[];
  mx_records: string[];
  txt_records: string[];
  infrastructure_notes: string;
}

export interface WhoisRdapAuditDTO {
  queried_domain: string;
  lookup_source: string;
  registrar_name: string;
  registrar_iana_id: string | null;
  creation_date: string | null;
  updated_date: string | null;
  expiration_date: string | null;
  domain_age_days: number | null;
  domain_status: string[];
  registrant_organization: string;
  abuse_contact_email: string | null;
  abuse_contact_phone: string | null;
  nameservers: string[];
  raw_whois_lines: string[];
  forensic_assessment: string;
}

export type ExfiltrationDestinationType =
  | 'SAME_SERVER_FILE'
  | 'EXTERNAL_DROP_SERVER'
  | 'TELEGRAM_BOT_API'
  | 'DISCORD_WEBHOOK'
  | 'CLOUD_REPO_OR_BACKEND'
  | 'FORM_RELAY_SERVICE';

export interface ExfiltrationDestinationDTO {
  destination_url: string;
  destination_host: string;
  destination_path: string;
  destination_type: ExfiltrationDestinationType;
  is_same_server: boolean;
  http_method: string;
  source_location: string;
  captured_fields: string[];
  repository_or_collector_id: string;
  resolved_ip_and_asn: string | null;
  forensic_detail: string;
}

export interface CurlInspectionResultDTO {
  target_url: string;
  target_role:
    | 'PHISHING_DOCUMENT'
    | 'SAME_SERVER_COLLECTOR_FILE'
    | 'SAME_SERVER_PARENT_DIRECTORY'
    | 'EXTERNAL_DROP_ENDPOINT';
  is_same_server: boolean;
  curl_command: string;
  http_status_line: string;
  status_code: number;
  response_time_ms: number;
  response_headers: Array<{ name: string; value: string }>;
  body_excerpt: string;
  directory_listing_exposed: boolean;
  collector_active: boolean;
  forensic_conclusion: string;
}

export interface PhishingForensicsDossierDTO {
  executed: boolean;
  generated_at: string;
  is_phishing_or_suspicious: boolean;
  executive_summary: string;
  hosting_intel: HostingIntelDTO;
  whois_rdap: WhoisRdapAuditDTO;
  exfiltration_destinations: ExfiltrationDestinationDTO[];
  curl_inspections: CurlInspectionResultDTO[];
}

export interface ScanReportDTO {
  scan_id: string;
  target_url: string;
  final_url?: string;
  target_domain: string;
  scanned_at: string;
  duration_ms: number;
  risk_score: number;
  risk_level: RiskLevel;
  citizen_verdict: {
    title: string;
    summary: string;
    action_steps: string[];
  };
  transport_audit: {
    protocol: 'http' | 'https';
    is_https: boolean;
    http_status_code?: number;
    redirect_count: number;
    security_headers: {
      strict_transport_security: boolean;
      content_security_policy: boolean;
      x_frame_options: boolean;
    };
  };
  link_functionality?: LinkFunctionalityAuditDTO;
  visual_brand_audit?: VisualBrandAuditDTO;
  phishing_forensics?: PhishingForensicsDossierDTO;
  findings: ScanFindingDTO[];
  source_preview: SourcePreviewLine[];
  integrity_sha256: string;
}
