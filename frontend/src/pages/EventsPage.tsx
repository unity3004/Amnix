import { Activity } from 'lucide-react'
import { PageHeader } from '@/components/layout/PageHeader'
import { Card } from '@/components/ui/Card'
import { EmptyState } from '@/components/ui/EmptyState'

export function EventsPage() {
  return (
    <div className="mx-auto max-w-[1400px] px-6 py-6">
      <PageHeader title="Events" description="Raw security telemetry ingested by AMNIX" />
      <Card>
        <EmptyState
          icon={Activity}
          title="Event exploration is coming in a future milestone"
          description="This screen will let you search and inspect the raw SecurityEvent stream that feeds AMNIX's detection engine."
        />
      </Card>
    </div>
  )
}
