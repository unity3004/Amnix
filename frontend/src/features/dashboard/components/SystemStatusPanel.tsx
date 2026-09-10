import { useQuery } from '@tanstack/react-query'
import { Database, Server, Sparkles, Zap } from 'lucide-react'
import { getHealth } from '@/services/healthService'
import { cn } from '@/lib/cn'

interface StatusRow {
  label: string
  icon: typeof Server
  state: 'online' | 'unreachable' | 'checking' | 'unmonitored'
}

const STATE_STYLES: Record<StatusRow['state'], { dot: string; text: string; label: string }> = {
  online: { dot: 'bg-success', text: 'text-success', label: 'Online' },
  unreachable: { dot: 'bg-danger', text: 'text-danger', label: 'Unreachable' },
  checking: { dot: 'bg-fg-subtle animate-pulse', text: 'text-fg-subtle', label: 'Checking…' },
  unmonitored: { dot: 'bg-fg-subtle', text: 'text-fg-subtle', label: 'Not monitored' },
}

export function SystemStatusPanel() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['health'],
    queryFn: getHealth,
    retry: false,
    refetchInterval: 30_000,
  })

  const apiState: StatusRow['state'] = isLoading ? 'checking' : isError ? 'unreachable' : 'online'

  // Database/Redis/AI Provider have no dedicated health signal in the
  // backend today (GET /health does not check them — see
  // healthService.ts) — shown honestly as unmonitored rather than
  // faked. See brief §19.
  const rows: StatusRow[] = [
    { label: 'API', icon: Server, state: apiState },
    { label: 'Database', icon: Database, state: 'unmonitored' },
    { label: 'Redis', icon: Zap, state: 'unmonitored' },
    { label: 'AI Provider', icon: Sparkles, state: 'unmonitored' },
  ]

  return (
    <ul className="flex flex-col gap-2.5 px-5 pb-4">
      {rows.map((row) => {
        const style = STATE_STYLES[row.state]
        return (
          <li key={row.label} className="flex items-center justify-between text-sm">
            <span className="flex items-center gap-2 text-fg-muted">
              <row.icon className="size-3.5 text-fg-subtle" strokeWidth={1.75} aria-hidden="true" />
              {row.label}
            </span>
            <span className={cn('flex items-center gap-1.5 text-xs font-medium', style.text)}>
              <span className={cn('size-1.5 rounded-full', style.dot)} aria-hidden="true" />
              {style.label}
            </span>
          </li>
        )
      })}
      {data && <p className="mt-1 text-[11px] text-fg-subtle">Reporting as “{data.service}”</p>}
    </ul>
  )
}
