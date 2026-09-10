import { useEffect, useState } from 'react'
import { motion } from 'motion/react'
import type { LucideIcon } from 'lucide-react'
import { Card } from '@/components/ui/Card'
import { formatCount } from '@/lib/format'
import { cn } from '@/lib/cn'

/** Animates from 0 up to `value` once, on mount — a restrained entrance
 * (brief §14/§32), not a decorative loop.
 */
function useCountUp(value: number, durationMs = 600) {
  const [display, setDisplay] = useState(0)

  useEffect(() => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      setDisplay(value)
      return
    }
    let frame: number
    const start = performance.now()
    function tick(now: number) {
      const progress = Math.min(1, (now - start) / durationMs)
      const eased = 1 - Math.pow(1 - progress, 3)
      setDisplay(Math.round(eased * value))
      if (progress < 1) frame = requestAnimationFrame(tick)
    }
    frame = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frame)
  }, [value, durationMs])

  return display
}

export function MetricCard({
  label,
  value,
  icon: Icon,
  tone = 'neutral',
  supporting,
}: {
  label: string
  value: number
  icon: LucideIcon
  tone?: 'neutral' | 'critical' | 'accent'
  supporting?: string
}) {
  const displayValue = useCountUp(value)

  const toneClasses = {
    neutral: 'text-fg-muted bg-surface-elevated',
    critical: 'text-critical bg-critical-dim',
    accent: 'text-accent bg-accent-dim',
  }[tone]

  return (
    <Card interactive className="p-5">
      <div className="flex items-start justify-between">
        <p className="text-xs font-medium uppercase tracking-wide text-fg-subtle">{label}</p>
        <div className={cn('flex size-8 items-center justify-center rounded-md', toneClasses)}>
          <Icon className="size-4" strokeWidth={1.75} aria-hidden="true" />
        </div>
      </div>
      <motion.p
        initial={{ opacity: 0, y: 4 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
        className="mt-3 text-2xl font-semibold tabular-nums text-fg"
      >
        {formatCount(displayValue)}
      </motion.p>
      {supporting && <p className="mt-1.5 text-xs text-fg-subtle">{supporting}</p>}
    </Card>
  )
}
