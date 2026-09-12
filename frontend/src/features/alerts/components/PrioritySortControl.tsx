export type AlertSortMode = 'recent' | 'priority'

/** Step 12G: GET /alerts only supports server-side ordering by
 * first_seen (see backend/app/repositories/alert.py::list_recent --
 * there is no `sort` query parameter). A true, globally-correct
 * priority ordering across the entire alert backlog would require a
 * backend change (a `sort=priority` parameter or equivalent) -- not
 * implemented here per the "prefer frontend-only" policy, since a
 * page-scoped client-side re-sort is a real, honest, deterministic
 * improvement that needs no backend change at all. This control makes
 * that scope explicit rather than silently implying a global sort.
 */
export function PrioritySortControl({ mode, onChange }: { mode: AlertSortMode; onChange: (mode: AlertSortMode) => void }) {
  return (
    <div className="flex items-center gap-1.5">
      <label htmlFor="alerts-sort-mode" className="text-xs text-fg-subtle">
        Sort
      </label>
      <select
        id="alerts-sort-mode"
        value={mode}
        onChange={(e) => onChange(e.target.value as AlertSortMode)}
        className="h-8 rounded-md border border-border bg-surface px-2 text-xs text-fg-muted transition-colors duration-fast hover:border-border-strong focus:border-accent/50 focus:outline-none"
      >
        <option value="recent">Newest first</option>
        <option value="priority">Priority (this page)</option>
      </select>
    </div>
  )
}
