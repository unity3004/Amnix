import { Card, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { EmptyState } from '@/components/ui/EmptyState'
import type { MitreTechnique } from '@/features/dashboard/mitreRegistry'

/** MITRE ATT&CK coverage for this case, grouped by tactic -- derived
 * entirely from the linked alerts' own real rule_ids via the existing
 * static mitreRegistry (see groupMitreByTactic in logic.ts). No ATT&CK
 * Navigator export, no fabricated coverage percentage -- a rule either
 * maps to a technique in the registry or it doesn't.
 */
export function MitreCoveragePanel({ byTactic }: { byTactic: Map<string, MitreTechnique[]> }) {
  const tactics = Array.from(byTactic.keys()).sort()

  return (
    <Card id="console-mitre" className="scroll-mt-20 overflow-hidden">
      <CardHeader title="MITRE ATT&CK Coverage" subtitle="Technique candidates for this case's linked alerts, grouped by tactic." />
      {tactics.length === 0 ? (
        <EmptyState title="No MITRE ATT&CK mapping exists for this case's linked alerts." />
      ) : (
        <div className="flex flex-col gap-4 px-5 pb-5">
          {tactics.map((tactic) => (
            <div key={tactic}>
              <p className="mb-2 text-[11px] uppercase tracking-wide text-fg-subtle">{tactic}</p>
              <ul className="flex flex-col gap-1.5">
                {(byTactic.get(tactic) ?? []).map((technique) => (
                  <li
                    key={technique.techniqueId}
                    className="flex items-center justify-between rounded-md border border-border-faint bg-bg-inset px-3 py-2"
                  >
                    <div>
                      <p className="font-mono text-xs font-semibold text-accent-strong">{technique.techniqueId}</p>
                      <p className="mt-0.5 text-sm text-fg">{technique.name}</p>
                    </div>
                    <Badge tone="neutral">{tactic}</Badge>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}
