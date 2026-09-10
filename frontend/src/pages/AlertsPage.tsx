import { ShieldAlert } from 'lucide-react'
import { PageHeader } from '@/components/layout/PageHeader'
import { Card } from '@/components/ui/Card'
import { EmptyState } from '@/components/ui/EmptyState'

export function AlertsPage() {
  return (
    <div className="mx-auto max-w-[1400px] px-6 py-6">
      <PageHeader title="Alerts" description="Triaged detection output across your environment" />
      <Card>
        <EmptyState
          icon={ShieldAlert}
          title="Alert triage is coming in a future milestone"
          description="This screen will list every alert AMNIX has generated, with filtering, status transitions, and links into investigation context."
        />
      </Card>
    </div>
  )
}
