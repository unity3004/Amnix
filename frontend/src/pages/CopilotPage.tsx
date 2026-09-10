import { Bot } from 'lucide-react'
import { PageHeader } from '@/components/layout/PageHeader'
import { Card } from '@/components/ui/Card'
import { EmptyState } from '@/components/ui/EmptyState'

export function CopilotPage() {
  return (
    <div className="mx-auto max-w-[1400px] px-6 py-6">
      <PageHeader title="AI Copilot" description="AI-assisted reasoning over an alert's investigation context" />
      <Card>
        <EmptyState
          icon={Bot}
          title="No Copilot conversations yet"
          description="Ask AMNIX's AI Copilot about a specific alert from its investigation view to start a conversation here."
        />
      </Card>
    </div>
  )
}
