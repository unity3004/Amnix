import { ScrollText } from 'lucide-react'
import { PageHeader } from '@/components/layout/PageHeader'
import { Card } from '@/components/ui/Card'
import { EmptyState } from '@/components/ui/EmptyState'

export function AuditsPage() {
  return (
    <div className="mx-auto max-w-[1400px] px-6 py-6">
      <PageHeader title="Audit Logs" description="Copilot and administrative accountability trails" />
      <Card>
        <EmptyState
          icon={ScrollText}
          title="Audit review is coming in a future milestone"
          description="This screen will surface Copilot audit records and, for admins, the durable administrative audit trail."
        />
      </Card>
    </div>
  )
}
