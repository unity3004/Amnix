/**
 * Step 12U: a pure client-side navigation breadcrumb carrying "which
 * Case did the analyst arrive from" through Case -> Alert ->
 * Investigation routing.
 *
 * This deliberately does NOT touch the backend. Discovery for this step
 * confirmed (by direct source inspection of app/models/alert.py,
 * app/repositories/alert.py, app/api/alerts.py, app/schemas/alert.py)
 * that Alert has zero reverse reference to Case anywhere in the
 * backend -- there is no GET /cases?alert_id=... and no
 * GET /alerts/{id}/cases. Given the approved architectural principle
 * that Case must not duplicate evidence or gain a new query surface
 * just to support frontend presentation, the only honest way to answer
 * "which case did the analyst arrive from" is to carry that context
 * through the URL itself, exactly like AlertsPage/CasesPage already
 * carry filter state -- never persisted, never sent as a request body/
 * header to any endpoint, and never presented as "this alert belongs to
 * Case #N" (a database claim this mechanism cannot make and doesn't try
 * to) -- only ever "you opened this from Case #N".
 */

const CASE_CONTEXT_PARAM = 'case'
const CASE_CONTEXT_NUMBER_PARAM = 'caseNumber'

export interface CaseNavigationContext {
  caseId: string
  caseNumber: number
}

export function buildCaseContextQuery(context: CaseNavigationContext): string {
  const params = new URLSearchParams({
    [CASE_CONTEXT_PARAM]: context.caseId,
    [CASE_CONTEXT_NUMBER_PARAM]: String(context.caseNumber),
  })
  return `?${params.toString()}`
}

/** Returns null unless BOTH fields are present and the number actually
 * parses -- a partial/malformed/tampered query string degrades to "no
 * case context" rather than rendering a broken or misleading affordance.
 */
export function readCaseContext(searchParams: URLSearchParams): CaseNavigationContext | null {
  const caseId = searchParams.get(CASE_CONTEXT_PARAM)
  const caseNumberRaw = searchParams.get(CASE_CONTEXT_NUMBER_PARAM)
  if (!caseId || !caseNumberRaw) return null
  const caseNumber = Number(caseNumberRaw)
  if (!Number.isFinite(caseNumber)) return null
  return { caseId, caseNumber }
}
