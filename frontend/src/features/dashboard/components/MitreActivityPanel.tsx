import { Crosshair } from 'lucide-react'
import type { MitreActivityEntry } from '../types'

export function MitreActivityPanel({ entries }: { entries: MitreActivityEntry[] }) {
  return (
    <ul className="flex flex-col divide-y divide-border-faint">
      {entries.map((entry) => (
        <li key={entry.techniqueId} className="flex items-center gap-3 px-5 py-3">
          <div className="flex size-8 shrink-0 items-center justify-center rounded-md bg-secondary-dim text-secondary">
            <Crosshair className="size-4" strokeWidth={1.75} aria-hidden="true" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs font-medium text-accent-strong">{entry.techniqueId}</span>
              <span className="truncate text-sm text-fg">{entry.name}</span>
            </div>
            <p className="mt-0.5 text-[11px] text-fg-subtle">{entry.tactic}</p>
          </div>
          <span className="shrink-0 text-xs tabular-nums text-fg-subtle">{entry.detectionCount} detections</span>
        </li>
      ))}
    </ul>
  )
}
