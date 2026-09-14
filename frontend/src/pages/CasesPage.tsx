import { useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { FolderKanban, Plus, X } from 'lucide-react'
import { PageHeader } from '@/components/layout/PageHeader'
import { Card } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { SkeletonRow } from '@/components/ui/Skeleton'
import { Pagination } from '@/components/ui/Pagination'
import { LiveIndicator } from '@/components/live/LiveIndicator'
import { RefreshButton } from '@/components/live/RefreshButton'
import { CasesFilterToolbar } from '@/features/cases/components/CasesFilterToolbar'
import { CaseCreateForm } from '@/features/cases/components/CaseCreateForm'
import { CaseRow } from '@/features/cases/components/CaseRow'
import { useCasesListQuery } from '@/features/cases/useCasesListQuery'
import type { CasesFilters } from '@/features/cases/types'
import type { CasePriority, CaseStatus } from '@/types/api'

/** AMNIX SOC Cases (Step 12S) -- the real, persistent case-management
 * workspace, backed entirely by the Case/CaseAlert/CaseAudit/CaseNote
 * domain built in Step 12R. Every row, badge, and count on this page is
 * a real GET /cases response -- nothing here is proposed, conceptual, or
 * a static mockup (see git history for the honest Step 12P placeholder
 * this page replaces once persistence actually existed).
 */
export function CasesPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [showCreateForm, setShowCreateForm] = useState(false)

  const page = Math.max(1, Number(searchParams.get('page') ?? '1') || 1)
  const filters: CasesFilters = useMemo(
    () => ({
      status: (searchParams.get('status') as CaseStatus) || undefined,
      priority: (searchParams.get('priority') as CasePriority) || undefined,
      owner_id: searchParams.get('owner_id') || undefined,
    }),
    [searchParams],
  )

  const { cases, hasNextPage, liveState, lastSuccessfulRefreshAt, isRefreshing, refresh } = useCasesListQuery(page, filters)

  function applyFilters(next: CasesFilters) {
    const params = new URLSearchParams()
    if (next.status) params.set('status', next.status)
    if (next.priority) params.set('priority', next.priority)
    if (next.owner_id) params.set('owner_id', next.owner_id)
    setSearchParams(params)
  }

  function goToPage(nextPage: number) {
    const params = new URLSearchParams(searchParams)
    params.set('page', String(nextPage))
    setSearchParams(params)
  }

  const hasFilters = Boolean(filters.status || filters.priority || filters.owner_id)

  return (
    <div className="mx-auto max-w-[1200px] px-6 py-6">
      <PageHeader
        title="SOC Cases"
        description="Persistent operational containers grouping related alerts, with their own lifecycle and ownership."
        action={
          <div className="flex items-center gap-3">
            <LiveIndicator state={liveState} lastSuccessfulRefreshAt={lastSuccessfulRefreshAt} />
            <RefreshButton onRefresh={refresh} isRefreshing={isRefreshing} />
            <Button variant="primary" size="sm" onClick={() => setShowCreateForm((v) => !v)}>
              {showCreateForm ? <X className="size-3.5" strokeWidth={2} aria-hidden="true" /> : <Plus className="size-3.5" strokeWidth={2} aria-hidden="true" />}
              {showCreateForm ? 'Cancel' : 'New Case'}
            </Button>
          </div>
        }
      />

      <Card className="overflow-hidden">
        {showCreateForm && <CaseCreateForm onClose={() => setShowCreateForm(false)} />}

        <CasesFilterToolbar filters={filters} onApply={applyFilters} onClear={() => setSearchParams({})} />

        {liveState === 'error' ? (
          <ErrorState title="Cases could not be loaded" onRetry={refresh} />
        ) : liveState === 'loading' ? (
          <div>
            {Array.from({ length: 6 }).map((_, i) => (
              <SkeletonRow key={i} />
            ))}
          </div>
        ) : cases.length === 0 ? (
          <EmptyState
            icon={FolderKanban}
            title={hasFilters ? 'No cases match the selected filters.' : 'No cases have been created yet.'}
            description={hasFilters ? 'Try clearing or widening the current filters.' : 'Create a case to start grouping related alerts.'}
          />
        ) : (
          <>
            <ul className="list-none">
              {cases.map((caseItem) => (
                <li key={caseItem.id}>
                  <CaseRow caseItem={caseItem} />
                </li>
              ))}
            </ul>
            <Pagination page={page} hasNext={hasNextPage} onPrevious={() => goToPage(page - 1)} onNext={() => goToPage(page + 1)} />
          </>
        )}
      </Card>
    </div>
  )
}
