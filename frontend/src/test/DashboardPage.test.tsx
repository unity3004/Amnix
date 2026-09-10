import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import { DashboardPage } from '@/pages/DashboardPage'
import { renderWithProviders } from './utils'
import * as dashboardService from '@/features/dashboard/dashboardService'
import type { DashboardOverview } from '@/features/dashboard/types'

const originalMatchMedia = window.matchMedia

// Force reduced-motion for these assertions so MetricCard's count-up
// resolves to its final value synchronously instead of racing
// requestAnimationFrame timing in jsdom -- item 14's own dedicated test
// (reducedMotion.test.tsx) is what actually verifies this behavior;
// here it's just used to make value assertions deterministic.
beforeEach(() => {
  window.matchMedia = (query: string) =>
    ({
      matches: query.includes('prefers-reduced-motion'),
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }) as MediaQueryList
})

afterEach(() => {
  window.matchMedia = originalMatchMedia
})

const overview: DashboardOverview = {
  metrics: { totalAlerts: 128, criticalAlerts: 7, openInvestigations: 4, eventsToday: 3842 },
  activity: [{ timestamp: '2026-01-01T00:00:00Z', critical: 1, high: 2, medium: 3, low: 4 }],
  recentAlerts: [
    {
      id: 'a1',
      title: 'Brute Force Authentication',
      ruleId: 'brute_force_authentication',
      severity: 'critical',
      status: 'new',
      occurredAt: new Date().toISOString(),
    },
  ],
  severityDistribution: [
    { severity: 'critical', count: 7 },
    { severity: 'high', count: 22 },
  ],
  mitreActivity: [
    { techniqueId: 'T1110', name: 'Brute Force', tactic: 'Credential Access', detectionCount: 41, sourceRuleId: 'brute_force_authentication' },
  ],
}

describe('DashboardPage', () => {
  it('renders the dashboard shell immediately (item 6)', () => {
    vi.spyOn(dashboardService, 'getDashboardOverview').mockReturnValue(new Promise(() => {}))
    renderWithProviders(<DashboardPage />)
    expect(screen.getByText(/security operations overview/i)).toBeInTheDocument()
  })

  it('shows skeleton loading state before data resolves (item 9)', () => {
    vi.spyOn(dashboardService, 'getDashboardOverview').mockReturnValue(new Promise(() => {}))
    const { container } = renderWithProviders(<DashboardPage />)
    expect(container.querySelectorAll('.animate-pulse').length).toBeGreaterThan(0)
  })

  it('renders metric cards with real values once data resolves (item 7)', async () => {
    vi.spyOn(dashboardService, 'getDashboardOverview').mockResolvedValue(overview)
    renderWithProviders(<DashboardPage />)

    expect(await screen.findByText('Total Alerts')).toBeInTheDocument()
    await waitFor(() => {
      expect(screen.getByText('128')).toBeInTheDocument()
    })
    // "7" legitimately appears twice (the Critical Alerts metric card
    // and the severity-distribution panel's own critical count) -- both
    // are real, correct renderings of the same overview.criticalAlerts/
    // severityDistribution data, not a bug.
    expect(screen.getAllByText('7').length).toBeGreaterThan(0)
    expect(screen.getByText('4')).toBeInTheDocument()
  })

  it('renders the recent alerts section with severity badges (items 8 and 12)', async () => {
    vi.spyOn(dashboardService, 'getDashboardOverview').mockResolvedValue(overview)
    renderWithProviders(<DashboardPage />)

    expect(await screen.findByText('Brute Force Authentication')).toBeInTheDocument()
    expect(screen.getAllByText('critical').length).toBeGreaterThan(0)
    expect(screen.getByText('brute_force_authentication')).toBeInTheDocument()
  })

  it('renders a polished empty state when there are no recent alerts (item 10)', async () => {
    vi.spyOn(dashboardService, 'getDashboardOverview').mockResolvedValue({ ...overview, recentAlerts: [] })
    renderWithProviders(<DashboardPage />)

    expect(await screen.findByText(/no active alerts/i)).toBeInTheDocument()
  })

  it('renders a safe error state and retries on failure (item 11 and item 15)', async () => {
    vi.spyOn(dashboardService, 'getDashboardOverview').mockRejectedValue(new Error('network down'))
    renderWithProviders(<DashboardPage />)

    expect(await screen.findByText(/unable to load security data/i)).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/network down/i)
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
  })
})
