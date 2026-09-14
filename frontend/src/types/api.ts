/**
 * Types mirroring AMNIX backend response/request schemas exactly (see
 * backend/app/schemas/*.py). Kept 1:1 with the real Pydantic contracts
 * discovered by direct source inspection during Step 12A — nothing here
 * is guessed or invented. If a backend schema changes, this file is the
 * one place to update.
 */

// ---------------------------------------------------------------------------
// Shared enums (mirror backend CHECK constraints / Python enums exactly)
// ---------------------------------------------------------------------------

export type UserRole = 'analyst' | 'admin'

export type DetectionSeverity = 'low' | 'medium' | 'high' | 'critical'
export type DetectionConfidence = 'low' | 'medium' | 'high'

export type AlertStatus = 'new' | 'acknowledged' | 'investigating' | 'resolved' | 'escalated'

// ---------------------------------------------------------------------------
// Auth (app/schemas/auth.py, app/api/auth.py)
// ---------------------------------------------------------------------------

export interface UserRead {
  id: string
  email: string
  role: UserRole
  is_active: boolean
  created_at: string
  updated_at: string
}

export interface LoginRequest {
  email: string
  password: string
}

export interface TokenResponse {
  access_token: string
  refresh_token: string
  token_type: 'Bearer'
  expires_in: number
}

export interface LoginResponse extends TokenResponse {
  user: UserRead
}

export interface RefreshRequest {
  refresh_token: string
}

// ---------------------------------------------------------------------------
// Security Events (app/schemas/security_event.py)
// ---------------------------------------------------------------------------

export type EventSeverity = 'informational' | 'low' | 'medium' | 'high' | 'critical'

export interface SecurityEventCreate {
  event_timestamp: string
  event_type: string
  source: string
  source_event_id?: string | null
  hostname?: string | null
  username?: string | null
  source_ip?: string | null
  source_port?: number | null
  destination_ip?: string | null
  destination_port?: number | null
  process_name?: string | null
  process_id?: number | null
  parent_process_name?: string | null
  command_line?: string | null
  file_hash?: string | null
  file_path?: string | null
  severity?: EventSeverity | null
  raw_data: Record<string, unknown>
  event_metadata?: Record<string, unknown> | null
}

export interface SecurityEventRead extends SecurityEventCreate {
  id: string
  created_at: string
}

/** GET /events (Step 12B, backend/app/schemas/security_event.py::SecurityEventListResponse).
 * No `total` field exists -- the backend deliberately omits it (no
 * COUNT(*) query) -- `items.length` is only ever the size of THIS
 * bounded page, never a global count. See dashboardService.ts for how
 * this is surfaced truthfully in the UI.
 */
export interface SecurityEventListResponse {
  items: SecurityEventRead[]
  limit: number
  offset: number
}

/** Step 12X: hostname/username/source_ip/destination_ip added to the
 * real GET /events contract -- exact-match only, each backed by an
 * index that already existed on this table (see backend/app/
 * repositories/security_event.py::list_recent's own docstring).
 */
export interface ListEventsParams {
  limit?: number
  offset?: number
  event_type?: string
  source?: string
  since?: string
  until?: string
  hostname?: string
  username?: string
  source_ip?: string
  destination_ip?: string
}

// ---------------------------------------------------------------------------
// Alerts (app/schemas/alert.py)
// ---------------------------------------------------------------------------

export interface AlertCreate {
  rule_id: string
  title: string
  description: string
  severity: DetectionSeverity
  confidence: DetectionConfidence
  first_seen: string
  last_seen?: string | null
  evidence: Record<string, unknown>
  alert_metadata?: Record<string, unknown> | null
  source_event_ids: string[]
}

export interface AlertRead {
  id: string
  rule_id: string
  title: string
  description: string
  severity: DetectionSeverity
  confidence: DetectionConfidence
  status: AlertStatus
  first_seen: string
  last_seen: string
  created_at: string
  updated_at: string
  evidence: Record<string, unknown>
  alert_metadata: Record<string, unknown> | null
  source_event_ids: string[]
}

export interface AlertStatusUpdate {
  status: AlertStatus
}

/** GET /alerts (Step 12B, backend/app/schemas/alert.py::AlertListResponse).
 * No `total` field -- same reasoning as SecurityEventListResponse above.
 */
export interface AlertListResponse {
  items: AlertRead[]
  limit: number
  offset: number
}

export interface ListAlertsParams {
  limit?: number
  offset?: number
  status?: AlertStatus
  severity?: DetectionSeverity
  rule_id?: string
  since?: string
  until?: string
}

// ---------------------------------------------------------------------------
// Investigation (app/schemas/investigation.py)
// ---------------------------------------------------------------------------

export interface TimelineEntry {
  event_id: string
  event_timestamp: string
  event_type: string
  source: string
  hostname: string | null
  username: string | null
  source_ip: string | null
  destination_ip: string | null
  process_name: string | null
  command_line: string | null
}

export interface InvestigationEntities {
  hostnames: string[]
  usernames: string[]
  source_ips: string[]
  destination_ips: string[]
  process_names: string[]
  file_hashes: string[]
}

export interface InvestigationSummary {
  text: string
  event_count: number
  unique_host_count: number
  unique_user_count: number
  timespan_seconds: number | null
  first_event_at: string | null
  last_event_at: string | null
}

export interface InvestigationContext {
  alert: AlertRead
  timeline: TimelineEntry[]
  entities: InvestigationEntities
  summary: InvestigationSummary
  generated_at: string
}

// ---------------------------------------------------------------------------
// Copilot (app/schemas/ai.py)
// ---------------------------------------------------------------------------

export type CopilotVerdict = 'likely_malicious' | 'suspicious' | 'likely_benign' | 'inconclusive'
export type CopilotConfidence = 'low' | 'medium' | 'high'
export type CopilotRecommendedAction = 'investigate' | 'monitor' | 'escalate' | 'close'
export type CopilotFindingType = 'fact' | 'inference' | 'concern'

export interface CopilotKeyFinding {
  type: CopilotFindingType
  statement: string
  supporting_event_refs: string[]
}

export interface CopilotEvidenceItem {
  field: string
  value: string
  event_ref: string | null
  explanation: string
}

export interface CopilotMitreAnalysisEntry {
  technique_id: string
  technique_name: string
  tactic: string
  confidence: CopilotConfidence
  rationale: string
  supporting_event_refs: string[]
}

export interface CopilotRecommendedInvestigationAction {
  action_id: string
  label: string
  description: string
  supporting_event_refs: string[]
}

export interface CopilotAssessment {
  verdict: CopilotVerdict
  confidence: CopilotConfidence
  summary: string
  key_findings: CopilotKeyFinding[]
  evidence: CopilotEvidenceItem[]
  mitre_analysis: CopilotMitreAnalysisEntry[]
  recommended_next_steps: string[]
  recommended_action: CopilotRecommendedAction
  recommended_actions: CopilotRecommendedInvestigationAction[]
  limitations: string[]
}

export interface CopilotQuestionRequest {
  question: string
}

export interface CopilotResponse {
  alert_id: string
  provider: string
  model: string
  assessment: CopilotAssessment
  generated_at: string
  usage: Record<string, unknown> | null
}

export type CopilotMessageRole = 'user' | 'assistant'

export interface CopilotMessage {
  role: CopilotMessageRole
  content: string
}

export interface CopilotFollowUpRequest {
  question: string
  history: CopilotMessage[]
}

export interface CopilotFollowUpResponse {
  alert_id: string
  provider: string
  model: string
  answer: string
  generated_at: string
  supporting_event_refs: string[]
  mitre_refs: CopilotMitreAnalysisEntry[]
  recommended_actions: CopilotRecommendedInvestigationAction[]
  limitations: string[]
  usage: Record<string, unknown> | null
}

// ---------------------------------------------------------------------------
// Copilot Audits (app/schemas/copilot_audit.py)
// ---------------------------------------------------------------------------

export type CopilotAuditRequestType = 'ask' | 'follow_up'
export type CopilotAuditOutcome = 'success' | 'failure'
export type CopilotAuditValidationStatus = 'passed' | 'failed' | 'not_applicable'

export interface CopilotAuditResponse {
  id: string
  alert_id: string
  request_type: CopilotAuditRequestType
  provider_name: string
  model_name: string | null
  outcome: CopilotAuditOutcome
  validation_status: CopilotAuditValidationStatus
  http_status: number
  question_fingerprint: string
  question_length: number
  history_turn_count: number | null
  duration_ms: number | null
  created_at: string
}

export interface CopilotAuditListResponse {
  items: CopilotAuditResponse[]
  limit: number
  offset: number
}

// ---------------------------------------------------------------------------
// Admin Audits (app/schemas/admin_audit.py)
// ---------------------------------------------------------------------------

export type AdminAuditAction = 'USER_STATUS_CHANGED'

export interface AdminAuditResponse {
  id: string
  actor_user_id: string
  target_user_id: string
  action: AdminAuditAction
  previous_is_active: boolean
  new_is_active: boolean
  created_at: string
}

export interface AdminAuditListResponse {
  items: AdminAuditResponse[]
  limit: number
  offset: number
}

export interface UserStatusUpdate {
  is_active: boolean
}

// ---------------------------------------------------------------------------
// Cases (app/schemas/case.py, Step 12R)
// ---------------------------------------------------------------------------

export type CaseStatus = 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'CLOSED'
export type CasePriority = 'critical' | 'high' | 'medium' | 'low'

export interface CaseCreate {
  title: string
  description: string
  priority?: CasePriority
}

/** PATCH /cases/{id} -- every field omitted/null means "do not change
 * this field" (backend never distinguishes omitted from explicit null
 * for title/description here -- see CaseUpdate's own docstring).
 */
export interface CaseUpdate {
  title?: string | null
  description?: string | null
  priority?: CasePriority | null
}

export interface CaseStatusUpdate {
  status: CaseStatus
  closure_reason?: string | null
}

/** `owner_id: null` releases ownership -- see CaseOwnerUpdate's own
 * docstring for the self-assign/release/admin-reassign authorization
 * rules CaseService enforces server-side.
 */
export interface CaseOwnerUpdate {
  owner_id?: string | null
}

export interface CaseAlertLink {
  alert_id: string
}

export interface CaseNoteCreate {
  body: string
}

/** `severity` is never a stored column -- CaseService derives it fresh
 * per request as the max severity among the case's currently-linked
 * alerts, or null if none are linked. See app/models/case.py.
 */
export interface CaseRead {
  id: string
  case_number: number
  title: string
  description: string
  status: CaseStatus
  priority: CasePriority
  severity: DetectionSeverity | null
  created_at: string
  updated_at: string
  created_by: string
  owner_id: string | null
  closed_at: string | null
  closure_reason: string | null
}

/** GET /cases -- no `total` field, same reasoning as every other list
 * endpoint in AMNIX (no COUNT(*) query).
 */
export interface CaseListResponse {
  items: CaseRead[]
  limit: number
  offset: number
}

export interface ListCasesParams {
  limit?: number
  offset?: number
  status?: CaseStatus
  priority?: CasePriority
  owner_id?: string
}

export type CaseAuditAction =
  | 'CASE_CREATED'
  | 'CASE_TITLE_CHANGED'
  | 'CASE_DESCRIPTION_CHANGED'
  | 'CASE_STATUS_CHANGED'
  | 'CASE_PRIORITY_CHANGED'
  | 'CASE_OWNER_CHANGED'
  | 'CASE_ALERT_LINKED'
  | 'CASE_ALERT_UNLINKED'
  | 'CASE_CLOSED'
  | 'CASE_REOPENED'

export interface CaseAuditResponse {
  id: string
  case_id: string
  actor_user_id: string
  action: CaseAuditAction
  related_alert_id: string | null
  previous_value: string | null
  new_value: string | null
  created_at: string
}

export interface CaseAuditListResponse {
  items: CaseAuditResponse[]
  limit: number
  offset: number
}

export interface CaseNoteResponse {
  id: string
  case_id: string
  author_id: string
  body: string
  created_at: string
}

export interface CaseNoteListResponse {
  items: CaseNoteResponse[]
  limit: number
  offset: number
}

// ---------------------------------------------------------------------------
// Error envelope (FastAPI's default + AMNIX's own HTTPException detail shape)
// ---------------------------------------------------------------------------

export interface ApiErrorBody {
  detail: string | Array<{ type: string; loc: (string | number)[]; msg: string }>
}
