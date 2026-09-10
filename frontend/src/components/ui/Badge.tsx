import type { ReactNode } from 'react'
import { cn } from '@/lib/cn'
import type { DetectionSeverity } from '@/types/api'

type BadgeTone = 'neutral' | 'accent' | 'success' | 'warning' | 'danger' | DetectionSeverity

const toneClasses: Record<BadgeTone, string> = {
  neutral: 'bg-surface-hover text-fg-muted border-border-strong',
  accent: 'bg-accent-dim text-accent-strong border-accent/30',
  success: 'bg-success-dim text-success border-success/30',
  warning: 'bg-warning-dim text-warning border-warning/30',
  danger: 'bg-danger-dim text-danger border-danger/30',
  critical: 'bg-critical-dim text-critical border-critical/40',
  high: 'bg-high-dim text-high border-high/40',
  medium: 'bg-medium-dim text-medium border-medium/40',
  low: 'bg-low-dim text-low border-low/40',
}

export function Badge({
  tone = 'neutral',
  children,
  dot = false,
  className,
}: {
  tone?: BadgeTone
  children: ReactNode
  dot?: boolean
  className?: string
}) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-sm border px-2 py-0.5 text-xs font-medium uppercase tracking-wide',
        toneClasses[tone],
        className,
      )}
    >
      {dot && <span className="size-1.5 rounded-full bg-current" aria-hidden="true" />}
      {children}
    </span>
  )
}

/** Severity is never color-only — see brief §17. Renders the label as
 * text and the color as a supporting dot, so it reads correctly even
 * without color perception.
 */
export function SeverityBadge({ severity }: { severity: DetectionSeverity }) {
  return (
    <Badge tone={severity} dot>
      {severity}
    </Badge>
  )
}
