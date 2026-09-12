import { cn } from '@/lib/cn'

interface StripItem {
  label: string
  value: string
  tone?: 'default' | 'critical' | 'success'
}

/** REAL BACKEND DATA -- every value here is derived from the exact
 * items currently held in the bounded GET /events / GET /alerts pages
 * this render cycle fetched (see DashboardPage.tsx). Deliberately
 * labeled "Recent" / scoped, never "Total": GET /events and GET
 * /alerts are paginated and intentionally omit a total count (Step
 * 12B), so a page length must never be presented as a global count
 * (brief §9's explicit instruction).
 */
export function SecurityStateBar({ items }: { items: StripItem[] }) {
  return (
    <div className="flex flex-wrap items-stretch divide-x divide-border rounded-lg border border-border bg-surface">
      {items.map((item) => (
        <div key={item.label} className="flex flex-1 flex-col gap-0.5 px-5 py-3">
          <span className="text-[10px] font-medium uppercase tracking-wider text-fg-subtle">{item.label}</span>
          <span
            className={cn(
              'text-xl font-semibold tabular-nums',
              item.tone === 'critical' ? 'text-critical' : item.tone === 'success' ? 'text-success' : 'text-fg',
            )}
          >
            {item.value}
          </span>
        </div>
      ))}
    </div>
  )
}
