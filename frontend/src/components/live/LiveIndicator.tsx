import { useEffect, useState } from 'react'
import { motion, useReducedMotion } from 'motion/react'
import { cn } from '@/lib/cn'
import type { LiveQueryState } from '@/lib/liveRefresh'

const STATE_STYLE: Record<LiveQueryState, { label: string; dot: string; text: string }> = {
  loading: { label: 'CONNECTING', dot: 'bg-fg-subtle', text: 'text-fg-subtle' },
  live: { label: 'LIVE', dot: 'bg-success', text: 'text-success' },
  degraded: { label: 'DEGRADED', dot: 'bg-warning', text: 'text-warning' },
  error: { label: 'OFFLINE', dot: 'bg-danger', text: 'text-danger' },
}

function secondsAgoLabel(date: Date | null, now: Date): string {
  if (!date) return '—'
  const seconds = Math.max(0, Math.round((now.getTime() - date.getTime()) / 1000))
  if (seconds < 2) return 'just now'
  if (seconds < 60) return `${seconds} sec ago`
  const minutes = Math.round(seconds / 60)
  return `${minutes} min ago`
}

/** `state` and `lastSuccessfulRefreshAt` come directly from
 * useDashboardData() -- REAL BACKEND DATA (or the honest absence of
 * it), never a decorative animation with no backing state.
 */
export function LiveIndicator({ state, lastSuccessfulRefreshAt }: { state: LiveQueryState; lastSuccessfulRefreshAt: Date | null }) {
  const [now, setNow] = useState(() => new Date())

  useEffect(() => {
    const interval = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(interval)
  }, [])

  const style = STATE_STYLE[state]
  const prefersReducedMotion = useReducedMotion()

  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="flex items-center gap-1.5">
        <span className="relative flex size-2">
          {state === 'live' && !prefersReducedMotion && (
            <motion.span
              className="absolute inline-flex size-full rounded-full bg-success"
              initial={{ opacity: 0.6, scale: 1 }}
              animate={{ opacity: 0, scale: 2.2 }}
              transition={{ duration: 1.6, repeat: Infinity, ease: 'easeOut' }}
            />
          )}
          <span className={cn('relative inline-flex size-2 rounded-full', style.dot)} />
        </span>
        <span className={cn('font-semibold tracking-wide', style.text)}>{style.label}</span>
      </span>
      <span className="text-fg-subtle">
        {state === 'degraded' ? 'Last successful update: ' : 'Last updated: '}
        {secondsAgoLabel(lastSuccessfulRefreshAt, now)}
      </span>
    </div>
  )
}
