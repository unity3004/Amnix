import { motion } from 'motion/react'
import { ShieldAlert } from 'lucide-react'
import { SeverityBadge, Badge } from '@/components/ui/Badge'
import { EmptyState } from '@/components/ui/EmptyState'
import { formatRelativeTime } from '@/lib/format'
import type { ActiveThreatSummary } from '../types'

const STATUS_TONE: Record<ActiveThreatSummary['status'], 'accent' | 'neutral' | 'success' | 'warning'> = {
  new: 'accent',
  acknowledged: 'neutral',
  investigating: 'warning',
  resolved: 'success',
  escalated: 'accent',
}

/** REAL BACKEND DATA -- every row is an actual Alert row from
 * GET /alerts (see deriveActiveThreats.ts). `mitre` is the only
 * DERIVED field (a static rule_id -> technique lookup, never a
 * provider/AI-generated value).
 */
export function ActiveThreatsPanel({ threats, onSelect }: { threats: ActiveThreatSummary[]; onSelect?: (id: string) => void }) {
  if (threats.length === 0) {
    return (
      <EmptyState
        icon={ShieldAlert}
        title="No active threats"
        description="Environment is currently quiet. AMNIX has not raised any recent alerts."
      />
    )
  }

  return (
    <ul className="divide-y divide-border-faint">
      {threats.map((threat, index) => (
        <motion.li
          key={threat.id}
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.25, delay: index * 0.035, ease: [0.16, 1, 0.3, 1] }}
        >
          <button
            type="button"
            onClick={() => onSelect?.(threat.id)}
            className="flex w-full items-center gap-4 px-5 py-3 text-left transition-colors duration-fast hover:bg-surface-hover"
          >
            <SeverityBadge severity={threat.severity} />
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm font-medium text-fg">{threat.title}</p>
              <p className="flex items-center gap-1.5 truncate font-mono text-[11px] text-fg-subtle">
                {threat.ruleId}
                {threat.mitre && (
                  <span className="text-accent-strong">· {threat.mitre.techniqueId}</span>
                )}
              </p>
            </div>
            <Badge tone={STATUS_TONE[threat.status]}>{threat.status}</Badge>
            <span className="w-20 shrink-0 text-right text-xs text-fg-subtle">
              {formatRelativeTime(threat.firstSeen)}
            </span>
          </button>
        </motion.li>
      ))}
    </ul>
  )
}
