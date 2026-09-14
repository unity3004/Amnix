import { CheckCircle2, Circle } from 'lucide-react'
import { CardHeader } from '@/components/ui/Card'
import { deriveClosureReadiness } from '../caseEvidence'
import type { AlertRead, CaseNoteResponse, CaseRead } from '@/types/api'

/** Step 13A §14 -- a deterministic documentation checklist, NEVER a
 * numeric score. Each item is a plain boolean derived from this case's
 * already-loaded alerts/notes (see caseEvidence.ts's own docstring for
 * exactly why); "Complete" only ever means that specific, named
 * documentation exists -- it is not a risk/closure/confidence score,
 * and completing every item does not itself imply the incident was
 * benign or malicious, or that the case is ready to close. The real
 * closing action, and the backend's own closure_reason requirement,
 * remain entirely in CaseStatusPanel/PATCH /cases/{id}/status.
 */
export function CaseClosureReadinessPanel({
  caseItem,
  alerts,
  notes,
}: {
  caseItem: CaseRead
  alerts: AlertRead[]
  notes: CaseNoteResponse[]
}) {
  const items = deriveClosureReadiness({ caseItem, alerts, notes })

  return (
    <>
      <CardHeader
        title="Closure Readiness"
        subtitle="A documentation checklist only. It does not evaluate, score, or draw any conclusion about this case."
      />
      <ul className="flex flex-col gap-2 px-5 pb-5">
        {items.map((item) => (
          <li key={item.key} className="flex items-center gap-2 text-sm">
            {item.complete ? (
              <CheckCircle2 className="size-4 shrink-0 text-success" strokeWidth={1.75} aria-hidden="true" />
            ) : (
              <Circle className="size-4 shrink-0 text-fg-subtle" strokeWidth={1.75} aria-hidden="true" />
            )}
            <span className="text-fg">{item.label}</span>
            <span className={`ml-auto text-xs font-medium ${item.complete ? 'text-success' : 'text-fg-subtle'}`}>
              {item.complete ? 'Complete' : 'Not yet documented'}
            </span>
          </li>
        ))}
      </ul>
    </>
  )
}
