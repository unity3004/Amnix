import { RotateCw } from 'lucide-react'
import { cn } from '@/lib/cn'

export function RefreshButton({ onRefresh, isRefreshing }: { onRefresh: () => void; isRefreshing: boolean }) {
  return (
    <button
      type="button"
      onClick={onRefresh}
      disabled={isRefreshing}
      aria-label="Refresh dashboard data"
      className="flex items-center gap-1.5 rounded-md border border-border px-2.5 py-1.5 text-xs font-medium text-fg-muted transition-colors duration-fast hover:border-border-strong hover:bg-surface-hover hover:text-fg disabled:cursor-wait disabled:opacity-60"
    >
      <RotateCw className={cn('size-3.5', isRefreshing && 'animate-spin')} strokeWidth={1.75} aria-hidden="true" />
      Refresh
    </button>
  )
}
