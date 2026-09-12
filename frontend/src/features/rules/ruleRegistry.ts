import type { DetectionConfidence, DetectionSeverity } from '@/types/api'

/**
 * Step 12H discovery finding: AMNIX's detection rules are NOT database
 * records. They are static, application-controlled Python classes
 * (backend/app/detections/rules/*.py, see DetectionRule in
 * backend/app/detections/base.py), registered once into an in-memory
 * DetectionRuleRegistry at process startup
 * (backend/app/detections/registry.py::build_default_registry). There
 * is no enable/disable persistence, no rule-authoring UI, and --
 * critically -- no backend API endpoint that exposes this registry to
 * a client at all (confirmed: backend/app/main.py registers only
 * health/auth/events/alerts/admin routers).
 *
 * This file is therefore a static, hand-verified mirror of the real
 * rule source -- the same established pattern as
 * features/dashboard/mitreRegistry.ts mirroring backend/app/mitre/registry.py
 * -- not a fetched resource. Every field below was copied verbatim from
 * the real Python class attributes (rule_id/name/description/severity/
 * confidence are literal class attributes; eventTypes/requiresProcess
 * are read directly from each rule's evaluate() logic). Nothing here is
 * guessed.
 *
 * Two things are DELIBERATELY NOT mirrored:
 *   - `SUSPICIOUS_COMMAND_LINE_INDICATORS` (the exact literal
 *     command-line substrings suspicious_powershell_execution matches
 *     on): the rule's own module docstring calls this a "curated"
 *     internal list; publishing the exact strings would hand an
 *     adversary a precise evasion checklist for no analyst benefit the
 *     rule's own public `description` doesn't already provide in
 *     category form ("hidden-window execution, execution-policy
 *     bypass, in-memory download-and-execute cradles").
 *   - brute_force_authentication's exact threshold/window-seconds
 *     VALUES as guaranteed facts: they are not hardcoded in the rule at
 *     all -- BruteForceDetectionRule.__init__ reads them from
 *     app.core.config.Settings (brute_force_threshold defaults to 5,
 *     brute_force_window_seconds defaults to 300 -- see
 *     backend/app/core/config.py), which is environment-configurable
 *     per deployment. No API exposes the currently-active value. The
 *     numbers shown below are the real checked-in DEFAULTS, explicitly
 *     labeled as such -- never asserted as this deployment's live
 *     configuration.
 */

export interface DetectionRuleDefinition {
  ruleId: string
  name: string
  description: string
  severity: DetectionSeverity
  confidence: DetectionConfidence
  /** SecurityEvent.event_type value(s) this rule evaluates. */
  eventTypes: string[]
  /** Additional real qualifying condition beyond event_type, if any --
   * copied from the rule's own evaluate()/matches() logic. */
  additionalCondition?: string
  /** Analyst-friendly description of the detection/correlation logic.
   * Any numeric threshold/window mentioned is the real checked-in
   * default and is explicitly labeled as configurable, never presented
   * as this deployment's confirmed live value.
   */
  detectionLogic: string
}

export const DETECTION_RULES: DetectionRuleDefinition[] = [
  {
    ruleId: 'brute_force_authentication',
    name: 'Brute Force Authentication',
    description:
      'Detects repeated authentication failures for the same user and source IP within a short time window, indicative of a credential-guessing (brute force) attempt.',
    severity: 'high',
    confidence: 'high',
    eventTypes: ['authentication_failure'],
    detectionLogic:
      'Correlates authentication failures by (username, source IP) and triggers when the count within a rolling window meets or exceeds a threshold. By default, AMNIX ships with a threshold of 5 failures within a 300-second window -- both are server-configurable and the currently-active values are not exposed by any API, so this is the application default, not a confirmed live setting for this deployment.',
  },
  {
    ruleId: 'suspicious_powershell_execution',
    name: 'Suspicious PowerShell Execution',
    description:
      'Detects PowerShell process executions whose command line contains indicators commonly associated with malicious use, such as hidden-window execution, execution-policy bypass, or in-memory download-and-execute cradles.',
    severity: 'medium',
    confidence: 'medium',
    eventTypes: ['process_creation'],
    additionalCondition: 'process_name identifies a PowerShell executable (powershell.exe, powershell, pwsh.exe, or pwsh)',
    detectionLogic:
      'Triggers only when both a PowerShell process execution is observed AND its command line matches at least one of a curated set of malicious-use indicators. Running PowerShell alone, with no matching indicator, does not trigger this rule. The exact indicator strings are an internal detection detail and are not published here.',
  },
  {
    ruleId: 'encoded_powershell_command',
    name: 'Encoded PowerShell Command',
    description:
      'Detects PowerShell process executions using the -EncodedCommand (or -enc) flag to pass a base64-encoded command, a common technique for hiding payload content from casual log review.',
    severity: 'high',
    confidence: 'high',
    eventTypes: ['process_creation'],
    additionalCondition: 'process_name identifies a PowerShell executable (powershell.exe, powershell, pwsh.exe, or pwsh)',
    detectionLogic:
      'Triggers when a PowerShell process execution\'s command line contains the -EncodedCommand or -enc flag as a distinct token. Deliberately narrow: does not match on the word "powershell" alone, and does not match unrelated flags that merely start with "-enc" (e.g. -Encoding).',
  },
]

const RULES_BY_ID = new Map(DETECTION_RULES.map((rule) => [rule.ruleId, rule]))

/** The only supported lookup, mirroring the real backend registry's own
 * "unknown rule_id returns nothing, never an invented fallback" contract
 * (see app.mitre.registry.get_techniques_for_rule's docstring for the
 * same philosophy applied to MITRE mappings).
 */
export function getRuleDefinition(ruleId: string): DetectionRuleDefinition | null {
  return RULES_BY_ID.get(ruleId) ?? null
}
