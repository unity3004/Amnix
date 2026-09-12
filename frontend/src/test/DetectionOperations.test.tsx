import { describe, expect, it, vi, afterEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { DetectionOperationsPage } from '@/pages/DetectionOperationsPage'
import { renderWithProviders } from './utils'
import * as alertsService from '@/services/alertsService'
import { ApiError } from '@/services/httpClient'
import { compareAlertPriority } from '@/features/alerts/priority'
import type { AlertRead, AlertListResponse } from '@/types/api'

afterEach(() => vi.restoreAllMocks())

function makeAlert(overrides: Partial<AlertRead> = {}): AlertRead {
  const now = new Date().toISOString()
  return {
    id: `alert-${Math.random().toString(36).slice(2)}`,
    rule_id: 'brute_force_authentication',
    title: 'Brute force authentication detected',
    description: 'd',
    severity: 'high',
    confidence: 'high',
    status: 'new',
    first_seen: now,
    last_seen: now,
    created_at: now,
    updated_at: now,
    evidence: {},
    alert_metadata: null,
    source_event_ids: ['evt-1'],
    ...overrides,
  }
}
function resp(items: AlertRead[]): AlertListResponse {
  return { items, limit: 100, offset: 0 }
}

function renderOperations(route = '/operations') {
  return renderWithProviders(
    <Routes>
      <Route path="/operations" element={<DetectionOperationsPage />} />
      <Route path="/rules/:ruleId" element={<div>RULE DETAIL MARKER</div>} />
      <Route path="/alerts/:alertId" element={<div>ALERT DETAIL MARKER</div>} />
    </Routes>,
    { route },
  )
}

describe('DetectionOperationsPage', () => {
  it('renders REAL alerts, severities, statuses, and rule IDs', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(
      resp([
        makeAlert({ title: 'Real critical alert', severity: 'critical', status: 'escalated', rule_id: 'brute_force_authentication' }),
        makeAlert({ title: 'Real medium alert', severity: 'medium', status: 'investigating', rule_id: 'suspicious_powershell_execution' }),
      ]),
    )
    renderOperations()

    expect(await screen.findByText('Real critical alert')).toBeInTheDocument()
    expect(screen.getByText('Real medium alert')).toBeInTheDocument()
    expect(screen.getAllByText(/^critical$/i).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/^medium$/i).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/^escalated$/i).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/^investigating$/i).length).toBeGreaterThan(0)
  })

  it('resolves a known rule_id through the existing Step 12H rule registry, without inventing a second registry', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(resp([makeAlert({ rule_id: 'brute_force_authentication' })]))
    renderOperations()

    expect(await screen.findByRole('link', { name: 'Brute Force Authentication' })).toHaveAttribute(
      'href',
      '/rules/brute_force_authentication',
    )
  })

  it('shows an unknown rule_id as backend-authoritative raw text, never a fabricated rule name', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(resp([makeAlert({ rule_id: 'future_unmapped_rule' })]))
    renderOperations()

    await screen.findByText('Detection Activity by Rule')
    expect(screen.getAllByText('future_unmapped_rule').length).toBeGreaterThan(0)
    expect(screen.queryByRole('link', { name: /future_unmapped_rule/i })).not.toBeInTheDocument()
  })

  it('uses bounded-observation wording, never a historical-total claim', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(resp([makeAlert()]))
    renderOperations()

    await screen.findByText('Alert Activity')
    expect(document.body.textContent).toMatch(/not a historical total/i)
    expect(document.body.textContent).not.toMatch(/total alerts:\s*\d+|total alerts today/i)
  })

  it('never displays a fake risk/threat/coverage score or trend percentage', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(resp([makeAlert({ severity: 'critical' })]))
    renderOperations()

    await screen.findByText('Alert Activity')
    expect(document.body.textContent).not.toMatch(
      /risk score|threat score|coverage score|detection effectiveness|\d+%\s*(increase|decrease|growth)|mttr|mttd/i,
    )
  })

  it('orders the Priority Queue using the exact Step 12G comparator (severity, then status, then recency)', async () => {
    const low = makeAlert({ id: 'low', title: 'Low priority alert', severity: 'low', status: 'new' })
    const critical = makeAlert({ id: 'critical', title: 'Critical escalated alert', severity: 'critical', status: 'escalated' })
    const high = makeAlert({ id: 'high', title: 'High new alert', severity: 'high', status: 'new' })
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(resp([low, high, critical]))
    renderOperations()

    await screen.findByText('Priority Queue')
    const expectedOrder = [low, high, critical].sort(compareAlertPriority).map((a) => a.title)
    expect(expectedOrder).toEqual(['Critical escalated alert', 'High new alert', 'Low priority alert'])

    const rows = screen.getAllByRole('button', { name: /priority alert|escalated alert|new alert/i })
    const renderedOrder = rows.map((r) => expectedOrder.find((title) => r.textContent?.includes(title))).filter(Boolean)
    expect(renderedOrder).toEqual(expectedOrder)
    expect(screen.getByText(/Critical severity · Escalated ·/)).toBeInTheDocument()
  })

  it('navigates from the Priority Queue to the real Alert Detail page using a real alert ID', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(resp([makeAlert({ id: 'real-alert-id', title: 'Click-through alert' })]))
    renderOperations()

    await userEvent.setup().click(await screen.findByRole('button', { name: /Click-through alert/i }))
    expect(await screen.findByText('ALERT DETAIL MARKER')).toBeInTheDocument()
  })

  it('does not fetch investigation, Copilot, or per-event data while rendering the overview', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(resp([makeAlert()]))
    const investigationSpy = vi.spyOn(alertsService, 'getAlertInvestigation')
    const copilotSpy = vi.spyOn(alertsService, 'askCopilot')
    renderOperations()

    await screen.findByText('Priority Queue')
    expect(investigationSpy).not.toHaveBeenCalled()
    expect(copilotSpy).not.toHaveBeenCalled()
  })

  it('does not issue a separate GET /alerts?rule_id=... request per rule on the overview page', async () => {
    const mock = vi
      .spyOn(alertsService, 'listAlerts')
      .mockResolvedValue(resp([makeAlert({ rule_id: 'brute_force_authentication' }), makeAlert({ rule_id: 'suspicious_powershell_execution' })]))
    renderOperations()

    await screen.findByText('Detection Activity by Rule')
    expect(mock).toHaveBeenCalledTimes(1)
    expect(mock.mock.calls[0][0]?.rule_id).toBeUndefined()
  })

  it('shows a page-level error state when GET /alerts fails, with retry, never substituting fake data', async () => {
    const mock = vi.spyOn(alertsService, 'listAlerts').mockRejectedValue(new ApiError(500, null, 'boom'))
    renderOperations()

    expect(await screen.findByText(/unable to retrieve recent alerts/i)).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/ApiError|TypeError|traceback|boom/i)

    mock.mockResolvedValue(resp([]))
    await userEvent.setup().click(screen.getByRole('button', { name: /retry/i }))
    await waitFor(() => expect(screen.getByText(/no recent alert activity/i)).toBeInTheDocument())
  })

  it('shows an honest empty state when no alerts are returned in the window', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(resp([]))
    renderOperations()

    expect(await screen.findByText(/no recent alert activity in the selected window\./i)).toBeInTheDocument()
    expect(screen.getByText(/detection activity may simply be outside the selected observation window/i)).toBeInTheDocument()
  })

  it('changing the observation window triggers exactly one new GET /alerts request', async () => {
    const mock = vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(resp([makeAlert()]))
    renderOperations()
    await screen.findByText('Priority Queue')
    const callsBefore = mock.mock.calls.length

    await userEvent.setup().selectOptions(screen.getByLabelText('Observation window'), '15')

    await waitFor(() => expect(mock.mock.calls.length).toBe(callsBefore + 1))
  })

  it('applies severity/status/rule_id filters as real backend query parameters, without a duplicate time-range control', async () => {
    const mock = vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(resp([]))
    renderOperations()
    await screen.findByText(/no recent alert activity/i)

    expect(screen.queryByLabelText('Time range')).not.toBeInTheDocument()

    const user = userEvent.setup()
    await user.selectOptions(screen.getByLabelText('Status'), 'investigating')
    await user.selectOptions(screen.getByLabelText('Severity'), 'high')
    await user.click(screen.getByRole('button', { name: /^apply$/i }))

    await waitFor(() => {
      const lastCall = mock.mock.calls.at(-1)?.[0]
      expect(lastCall).toMatchObject({ status: 'investigating', severity: 'high' })
    })
  })
})
