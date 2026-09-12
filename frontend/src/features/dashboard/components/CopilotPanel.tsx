import { useNavigate } from 'react-router-dom'
import { Bot, ArrowRight } from 'lucide-react'
import { Button } from '@/components/ui/Button'

/** STATIC UI STATE -- "Ready" reflects that the Copilot endpoint is
 * always reachable (mock or real provider, wired since Step 10), not a
 * fetched status. Deliberately does NOT display an invented metric
 * like "N investigations assisted" -- no such count is computed
 * anywhere in AMNIX today (see the Step 12C report's Demo Data Audit).
 */
export function CopilotPanel({ selectedAlertId }: { selectedAlertId?: string | null }) {
  const navigate = useNavigate()

  return (
    <div className="flex flex-col gap-3 px-5 py-4">
      <div className="flex items-center gap-3">
        <div className="flex size-9 items-center justify-center rounded-md bg-accent-dim text-accent">
          <Bot className="size-4" strokeWidth={1.75} aria-hidden="true" />
        </div>
        <div>
          <p className="text-sm font-semibold text-fg">AMNIX Copilot</p>
          <p className="flex items-center gap-1.5 text-xs text-success">
            <span className="size-1.5 rounded-full bg-success" aria-hidden="true" />
            Ready
          </p>
        </div>
      </div>
      <p className="text-xs text-fg-subtle">
        {selectedAlertId
          ? 'AI-assisted investigation is available for the selected alert.'
          : 'Select an alert to begin AI-assisted investigation.'}
      </p>
      <Button
        variant="secondary"
        size="sm"
        className="w-full justify-between"
        onClick={() => navigate(selectedAlertId ? `/copilot?alert=${selectedAlertId}` : '/alerts')}
      >
        {selectedAlertId ? 'Open with Copilot' : 'Open Alerts'}
        <ArrowRight className="size-3.5" strokeWidth={2} aria-hidden="true" />
      </Button>
    </div>
  )
}
