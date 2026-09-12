import { motion, useReducedMotion } from 'motion/react'
import { cn } from '@/lib/cn'
import type { ThreatPulseState } from '../types'

const STATE_STYLE: Record<ThreatPulseState, { label: string; color: string; ring: string }> = {
  quiet: { label: 'Quiet', color: 'text-fg-muted', ring: 'bg-fg-subtle' },
  guarded: { label: 'Guarded', color: 'text-low', ring: 'bg-low' },
  elevated: { label: 'Elevated', color: 'text-medium', ring: 'bg-medium' },
  active: { label: 'Active', color: 'text-high', ring: 'bg-high' },
  critical: { label: 'Critical', color: 'text-critical', ring: 'bg-critical' },
}

/** DERIVED FROM REAL BACKEND DATA -- see deriveThreatPulse.ts for the
 * exact, documented formula. This is an activity STATE, never a
 * numeric "threat score" the backend does not calculate.
 */
export function ThreatPulsePanel({ state }: { state: ThreatPulseState }) {
  const style = STATE_STYLE[state]
  const prefersReducedMotion = useReducedMotion()
  const isRestless = (state === 'active' || state === 'critical') && !prefersReducedMotion

  return (
    <div className="flex items-center gap-4 px-5 py-4">
      <div className="relative flex size-11 shrink-0 items-center justify-center">
        {isRestless && (
          <motion.span
            className={cn('absolute inset-0 rounded-full', style.ring)}
            initial={{ opacity: 0.35, scale: 0.8 }}
            animate={{ opacity: 0, scale: 1.6 }}
            transition={{ duration: 1.8, repeat: Infinity, ease: 'easeOut' }}
          />
        )}
        <span className={cn('relative size-3.5 rounded-full', style.ring)} aria-hidden="true" />
        <span className="absolute inset-0 rounded-full border border-border-strong" aria-hidden="true" />
      </div>
      <div>
        <p className="text-[11px] font-medium uppercase tracking-wide text-fg-subtle">Threat Pulse</p>
        <p className={cn('text-lg font-semibold uppercase tracking-wide', style.color)}>{style.label}</p>
      </div>
    </div>
  )
}
