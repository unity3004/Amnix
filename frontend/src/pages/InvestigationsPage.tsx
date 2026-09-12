import { Navigate, useSearchParams } from 'react-router-dom'
import { SearchCode } from 'lucide-react'
import { PageHeader } from '@/components/layout/PageHeader'
import { Card } from '@/components/ui/Card'
import { EmptyState } from '@/components/ui/EmptyState'

/** Step 12E: the dense, alert-scoped investigation experience now lives
 * at the canonical /alerts/:alertId/investigation route (see
 * InvestigationWorkspacePage) -- combining evidence, findings, MITRE
 * context, and Copilot reasoning in one workspace, per the brief's
 * explicit "do not create a second competing investigation route"
 * instruction. `?alert=<id>` here (the pre-12E link shape, still
 * possibly bookmarked) redirects to that route rather than rendering a
 * second, thinner implementation of the same view. With no `alert`
 * param at all, this page keeps its original Step 12A placeholder,
 * since a general "browse all investigations" view has no backing list
 * endpoint (there is no investigation list endpoint, and no step has
 * asked for one).
 */
export function InvestigationsPage() {
  const [searchParams] = useSearchParams()
  const alertId = searchParams.get('alert')

  if (alertId) {
    return <Navigate to={`/alerts/${alertId}/investigation`} replace />
  }

  return (
    <div className="mx-auto max-w-[1400px] px-6 py-6">
      <PageHeader title="Investigations" description="Deterministic, alert-scoped investigation context" />
      <Card>
        <EmptyState
          icon={SearchCode}
          title="No investigation selected"
          description="Open an alert and choose “Investigate Alert” to see its timeline, related entities, and summary here."
        />
      </Card>
    </div>
  )
}
