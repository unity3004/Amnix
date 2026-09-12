import { CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { getMitreTechniquesForRule } from '@/features/dashboard/mitreRegistry'
import type { CopilotMitreAnalysisEntry } from '@/types/api'

/** Section E: MITRE ATT&CK presentation.
 *
 * Two distinct, separately-labeled data sources, never merged:
 *
 * 1. "Candidates based on the detection rule" -- the static,
 *    application-controlled rule_id -> technique mapping (mirrors
 *    backend/app/mitre/registry.py exactly). These are candidates, not
 *    a claim that the technique was confirmed -- shown for every alert
 *    with a mapped rule_id regardless of whether Copilot has been
 *    asked anything yet.
 *
 * 2. "Copilot-reasoned analysis" -- populated ONLY after the analyst
 *    has asked Copilot a question and the backend returned
 *    mitre_analysis/mitre_refs. Every entry here was already validated
 *    server-side (CopilotService cross-checks technique_id against the
 *    exact candidate set above and overwrites technique_name/tactic
 *    from the trusted registry -- see app.services.copilot_service) --
 *    this UI does not invent, verify, or re-derive any of it. Absent
 *    until the analyst explicitly asks.
 */
export function MitrePanel({ ruleId, copilotAnalysis }: { ruleId: string; copilotAnalysis: CopilotMitreAnalysisEntry[] }) {
  const candidates = getMitreTechniquesForRule(ruleId)

  return (
    <div>
      <CardHeader title="MITRE ATT&CK Context" subtitle="Candidates based on the detection rule -- not independently verified" />
      <div className="px-5 pb-5">
        {candidates.length === 0 ? (
          <p className="text-xs text-fg-subtle">No MITRE ATT&CK mapping exists for rule "{ruleId}".</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {candidates.map((technique) => (
              <li
                key={technique.techniqueId}
                className="flex items-center justify-between rounded-md border border-border-faint bg-bg-inset px-3 py-2"
              >
                <div>
                  <p className="font-mono text-xs font-semibold text-accent-strong">{technique.techniqueId}</p>
                  <p className="mt-0.5 text-sm text-fg">{technique.name}</p>
                </div>
                <Badge tone="neutral">{technique.tactic}</Badge>
              </li>
            ))}
          </ul>
        )}

        {copilotAnalysis.length > 0 && (
          <div className="mt-4 border-t border-border pt-4">
            <p className="text-[11px] uppercase tracking-wide text-fg-subtle">
              Copilot-reasoned analysis <span className="normal-case text-fg-subtle/70">(from the AI assessment, backend-validated)</span>
            </p>
            <ul className="mt-2 flex flex-col gap-2">
              {copilotAnalysis.map((entry, i) => (
                <li key={`${entry.technique_id}-${i}`} className="rounded-md border border-accent/20 bg-accent-dim px-3 py-2">
                  <div className="flex items-center justify-between gap-2">
                    <p className="font-mono text-xs font-semibold text-accent-strong">
                      {entry.technique_id} — {entry.technique_name}
                    </p>
                    <span className="text-[11px] text-fg-subtle">confidence: {entry.confidence}</span>
                  </div>
                  <p className="mt-1 text-xs text-fg-muted">{entry.rationale}</p>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  )
}
