import { SearchCode } from 'lucide-react'
import { PageHeader } from '@/components/layout/PageHeader'
import { Card } from '@/components/ui/Card'
import { EmptyState } from '@/components/ui/EmptyState'

export function InvestigationsPage() {
  return (
    <div className="mx-auto max-w-[1400px] px-6 py-6">
      <PageHeader title="Investigations" description="Deterministic, alert-scoped investigation context" />
      <Card>
        <EmptyState
          icon={SearchCode}
          title="No investigations yet"
          description="Open an alert's investigation context to see its timeline, related entities, and summary here."
        />
      </Card>
    </div>
  )
}
