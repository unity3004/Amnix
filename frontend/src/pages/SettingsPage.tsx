import { Settings } from 'lucide-react'
import { PageHeader } from '@/components/layout/PageHeader'
import { Card } from '@/components/ui/Card'
import { EmptyState } from '@/components/ui/EmptyState'

export function SettingsPage() {
  return (
    <div className="mx-auto max-w-[1400px] px-6 py-6">
      <PageHeader title="Settings" description="Account and workspace configuration" />
      <Card>
        <EmptyState
          icon={Settings}
          title="Settings are coming in a future milestone"
          description="Profile, notification, and workspace preferences will live here."
        />
      </Card>
    </div>
  )
}
