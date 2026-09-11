import { describe, expect, it, vi, afterEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AlertsPage } from '@/pages/AlertsPage'
import { renderWithProviders } from './utils'
import * as alertsService from '@/services/alertsService'
import { ApiError } from '@/services/httpClient'
import type { AlertRead, AlertListResponse } from '@/types/api'

function makeAlert(overrides: Partial<AlertRead> = {}): AlertRead {
  const now = new Date().toISOString()
  return {
    id: `alert-${Math.random().toString(36).slice(2)}`,
    rule_id: 'brute_force_authentication',
    title: 'Brute force authentication detected',
    description: 'd',
    severity: 'critical',
    confidence: 'high',
    status: 'new',
    first_seen: now,
    last_seen: now,
    created_at: now,
    updated_at: now,
    evidence: {},
    alert_metadata: null,
    source_event_ids: ['evt-1', 'evt-2'],
    ...overrides,
  }
}
function resp(items: AlertRead[]): AlertListResponse {
  return { items, limit: 25, offset: 0 }
}

afterEach(() => vi.restoreAllMocks())

describe('AlertsPage', () => {
  it('renders REAL alert data with severity and status', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(resp([makeAlert({ severity: 'high', status: 'investigating' })]))
    renderWithProviders(<AlertsPage />, { route: '/alerts' })

    expect(await screen.findByText('Brute force authentication detected')).toBeInTheDocument()
    // "high"/"investigating" also appear as <option> text in the filter
    // toolbar's dropdowns, so scope to the alert row's own button.
    const row = screen.getByRole('button', { name: /Brute force authentication detected/i })
    expect(row).toHaveTextContent('high')
    expect(row).toHaveTextContent('investigating')
  })

  it('shows the loading skeleton before data resolves', () => {
    vi.spyOn(alertsService, 'listAlerts').mockReturnValue(new Promise(() => {}))
    const { container } = renderWithProviders(<AlertsPage />, { route: '/alerts' })
    expect(container.querySelectorAll('.animate-pulse').length).toBeGreaterThan(0)
  })

  it('shows a distinct empty state for a genuinely empty environment vs. an active filter', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(resp([]))
    renderWithProviders(<AlertsPage />, { route: '/alerts' })
    expect(await screen.findByText('No security events')).toBeInTheDocument()

    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(resp([]))
    renderWithProviders(<AlertsPage />, { route: '/alerts?severity=critical' })
    expect(await screen.findByText('No alerts match')).toBeInTheDocument()
  })

  it('shows a safe error state on failure, with retry', async () => {
    const mock = vi.spyOn(alertsService, 'listAlerts').mockRejectedValue(new ApiError(500, null, 'boom'))
    renderWithProviders(<AlertsPage />, { route: '/alerts' })
    expect(await screen.findByText(/unable to retrieve alerts/i)).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/ApiError|TypeError|traceback|boom/i)

    mock.mockResolvedValue(resp([]))
    await userEvent.setup().click(screen.getByRole('button', { name: /retry/i }))
    await waitFor(() => expect(screen.getByText('No security events')).toBeInTheDocument())
  })

  it('applies severity/status/rule_id filters as real backend query parameters', async () => {
    const mock = vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(resp([]))
    renderWithProviders(<AlertsPage />, { route: '/alerts' })
    await screen.findByText('No security events')

    const user = userEvent.setup()
    await user.selectOptions(screen.getByLabelText('Status'), 'investigating')
    await user.selectOptions(screen.getByLabelText('Severity'), 'high')
    await user.type(screen.getByLabelText('Rule ID'), 'suspicious_powershell_execution')
    await user.click(screen.getByRole('button', { name: /^apply$/i }))

    await waitFor(() => {
      const lastCall = mock.mock.calls.at(-1)?.[0]
      expect(lastCall).toMatchObject({ status: 'investigating', severity: 'high', rule_id: 'suspicious_powershell_execution' })
    })
  })

  it('paginates using limit/offset, never claiming a total', async () => {
    const fullPage = Array.from({ length: 25 }, () => makeAlert())
    const mock = vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(resp(fullPage))
    renderWithProviders(<AlertsPage />, { route: '/alerts' })
    await screen.findByText('Page 1')

    expect(screen.queryByText(/total/i)).not.toBeInTheDocument()
    await userEvent.setup().click(screen.getByRole('button', { name: /^next$/i }))

    await waitFor(() => {
      const lastCall = mock.mock.calls.at(-1)?.[0]
      expect(lastCall).toMatchObject({ offset: 25 })
    })
  })

  it('manual refresh re-fetches with the same filters', async () => {
    const mock = vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(resp([]))
    renderWithProviders(<AlertsPage />, { route: '/alerts' })
    await screen.findByText('No security events')
    expect(mock).toHaveBeenCalledTimes(1)

    await userEvent.setup().click(screen.getByRole('button', { name: /refresh dashboard data/i }))
    await waitFor(() => expect(mock).toHaveBeenCalledTimes(2))
  })

  it('handles a 401 from GET /alerts gracefully without crashing', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockRejectedValue(new ApiError(401, { detail: 'Could not validate credentials.' }, 'Could not validate credentials.'))
    renderWithProviders(<AlertsPage />, { route: '/alerts' })
    expect(await screen.findByText(/unable to retrieve alerts/i)).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: /^alerts$/i })).toBeInTheDocument()
  })

  it('never renders demo data (values match exactly what the mock returned)', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(resp([makeAlert({ title: 'Unique Marker Title 42' })]))
    renderWithProviders(<AlertsPage />, { route: '/alerts' })
    expect(await screen.findByText('Unique Marker Title 42')).toBeInTheDocument()
    expect(screen.queryByText(/128|3,842/)).not.toBeInTheDocument()
  })
})
