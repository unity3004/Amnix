import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AuthProvider } from '@/features/auth/AuthContext'
import { ProtectedRoute, RedirectIfAuthenticated } from '@/features/auth/ProtectedRoute'
import { AppShell } from '@/layouts/AppShell'
import { LoginPage } from '@/pages/LoginPage'
import { DashboardPage } from '@/pages/DashboardPage'
import { AlertsPage } from '@/pages/AlertsPage'
import { AlertDetailPage } from '@/pages/AlertDetailPage'
import { InvestigationWorkspacePage } from '@/pages/InvestigationWorkspacePage'
import { EventsPage } from '@/pages/EventsPage'
import { EventDetailPage } from '@/pages/EventDetailPage'
import { ThreatHuntingPage } from '@/pages/ThreatHuntingPage'
import { InvestigationsPage } from '@/pages/InvestigationsPage'
import { CopilotPage } from '@/pages/CopilotPage'
import { RuleExplorerPage } from '@/pages/RuleExplorerPage'
import { RuleDetailPage } from '@/pages/RuleDetailPage'
import { TelemetryHealthPage } from '@/pages/TelemetryHealthPage'
import { DetectionOperationsPage } from '@/pages/DetectionOperationsPage'
import { SocMetricsPage } from '@/pages/SocMetricsPage'
import { DetectionHealthPage } from '@/pages/DetectionHealthPage'
import { CasesPage } from '@/pages/CasesPage'
import { CaseDetailPage } from '@/pages/CaseDetailPage'
import { IncidentConsolePage } from '@/pages/IncidentConsolePage'
import { AuditsPage } from '@/pages/AuditsPage'
import { SettingsPage } from '@/pages/SettingsPage'
import { NotFoundPage } from '@/pages/NotFoundPage'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
})

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          <Routes>
            <Route element={<RedirectIfAuthenticated />}>
              <Route path="/login" element={<LoginPage />} />
            </Route>

            <Route element={<ProtectedRoute />}>
              <Route element={<AppShell />}>
                <Route path="/dashboard" element={<DashboardPage />} />
                <Route path="/alerts" element={<AlertsPage />} />
                <Route path="/alerts/:alertId" element={<AlertDetailPage />} />
                <Route path="/alerts/:alertId/investigation" element={<InvestigationWorkspacePage />} />
                <Route path="/events" element={<EventsPage />} />
                <Route path="/events/:eventId" element={<EventDetailPage />} />
                <Route path="/threat-hunting" element={<ThreatHuntingPage />} />
                <Route path="/investigations" element={<InvestigationsPage />} />
                <Route path="/copilot" element={<CopilotPage />} />
                <Route path="/rules" element={<RuleExplorerPage />} />
                <Route path="/rules/:ruleId" element={<RuleDetailPage />} />
                <Route path="/telemetry" element={<TelemetryHealthPage />} />
                <Route path="/operations" element={<DetectionOperationsPage />} />
                <Route path="/metrics" element={<SocMetricsPage />} />
                <Route path="/detection-health" element={<DetectionHealthPage />} />
                <Route path="/cases" element={<CasesPage />} />
                <Route path="/cases/:caseId" element={<CaseDetailPage />} />
                <Route path="/cases/:caseId/console" element={<IncidentConsolePage />} />
                <Route path="/audits" element={<AuditsPage />} />
                <Route path="/settings" element={<SettingsPage />} />
              </Route>
            </Route>

            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  )
}
