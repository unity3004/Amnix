import { Server } from 'lucide-react'
import { cn } from '@/lib/cn'
import type { HealthResponse } from '@/services/healthService'

type ApiState = 'operational' | 'unreachable' | 'checking'

const STATE_STYLE: Record<ApiState, { dot: string; text: string; label: string }> = {
  operational: { dot: 'bg-success', text: 'text-success', label: 'Operational' },
  unreachable: { dot: 'bg-danger', text: 'text-danger', label: 'Unreachable' },
  checking: { dot: 'bg-fg-subtle animate-pulse', text: 'text-fg-subtle', label: 'Checking…' },
}

/** REAL BACKEND DATA -- `health`/`isLoading`/`isError` come from the
 * one centralized useDashboardData() poll (never its own independent
 * query -- every panel shares one refresh cycle, see brief §4/§6).
 *
 * GET /health reports only overall API reachability -- it has no
 * Database/Redis/AI-Provider sub-status (confirmed by reading the real
 * handler: backend/app/api/health.py returns a static status/service
 * pair only). Showing separate Database/Redis/AI Provider rows here
 * would mean inventing signals the backend does not provide, which the
 * brief explicitly prohibits (§17) -- so only the one row this
 * endpoint can truthfully support is shown.
 */
export function SystemStatusPanel({
  health,
  isLoading,
  isError,
}: {
  health: HealthResponse | null
  isLoading: boolean
  isError: boolean
}) {
  const state: ApiState = isLoading && !health ? 'checking' : isError ? 'unreachable' : 'operational'
  const style = STATE_STYLE[state]

  return (
    <div className="flex flex-col gap-2 px-5 pb-4">
      <div className="flex items-center justify-between text-sm">
        <span className="flex items-center gap-2 text-fg-muted">
          <Server className="size-3.5 text-fg-subtle" strokeWidth={1.75} aria-hidden="true" />
          AMNIX API
        </span>
        <span className={cn('flex items-center gap-1.5 text-xs font-medium', style.text)}>
          <span className={cn('size-1.5 rounded-full', style.dot)} aria-hidden="true" />
          {style.label}
        </span>
      </div>
      {health && <p className="text-[11px] text-fg-subtle">Reporting as “{health.service}”</p>}
    </div>
  )
}
