export type RiskLevel = 'SAFE' | 'WARNING' | 'CRITICAL';

export type FindingCategory = 'TRANSPORT' | 'DOM_FORM' | 'DOM_INPUT' | 'JS_SCRIPT';

export type FindingSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type UserAgentProfile = 'mobile_android' | 'mobile_ios' | 'desktop_chrome';

export type AlertChannel = 'whatsapp' | 'telegram' | 'sms' | 'email' | 'social' | 'web';

export interface SecurityHeadersAudit {
  strict_transport_security: boolean;
  content_security_policy: boolean;
  x_frame_options: boolean;
  x_content_type_options?: boolean;
  referrer_policy?: boolean;
}

export interface RedirectHop {
  step: number;
  from_url: string;
  to_url: string;
  status_code: number;
}

export interface TransportAudit {
  protocol: 'http' | 'https';
  is_https: boolean;
  http_status_code: number;
  redirect_count: number;
  redirect_chain: RedirectHop[];
  tls_verified: boolean;
  content_type: string;
  response_bytes: number;
  security_headers: SecurityHeadersAudit;
}

export interface ScanFinding {
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
  rule_codes?: string[];
}

export interface CitizenVerdict {
  title: string;
  summary: string;
}

export interface CanonicalEvidencePayload {
  scan_id: string;
  target_url: string;
  final_url: string;
  target_domain: string;
  scanned_at: string;
  protocol: 'http' | 'https';
  http_status_code: number;
  redirect_count: number;
  security_headers: {
    strict_transport_security: boolean;
    content_security_policy: boolean;
    x_frame_options: boolean;
  };
  risk_score: number;
  risk_level: RiskLevel;
  findings: Array<{
    rule_code: string;
    category: FindingCategory;
    severity: FindingSeverity;
    line_number: number;
    column_number: number;
    dom_selector: string;
    code_snippet: string;
  }>;
}

export interface ScanReportData {
  scan_id: string;
  target_url: string;
  final_url: string;
  target_domain: string;
  scanned_at: string;
  duration_ms: number;
  risk_score: number;
  risk_level: RiskLevel;
  citizen_verdict: CitizenVerdict;
  transport_audit: TransportAudit;
  findings: ScanFinding[];
  source_preview: SourcePreviewLine[];
  r2_snapshot_saved?: boolean;
  case_note?: string | null;
  evidence_payload: CanonicalEvidencePayload;
  integrity_sha256: string;
}

export interface UserRecord {
  id: string;
  alias: string;
  email: string;
  password_hash: string;
  is_active: number;
  created_at: string;
  updated_at: string;
}

export interface RefreshTokenRecord {
  id: string;
  user_id: string;
  token_hash: string;
  user_agent: string | null;
  expires_at: string;
  revoked_at: string | null;
  created_at: string;
}

export interface JwtAccessPayload {
  sub: string;
  alias: string;
  email: string;
  iat: number;
  exp: number;
  iss: string;
  type: 'access';
}
