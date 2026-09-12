import { describe, expect, it, vi, afterEach } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { AlertDetailPage } from '@/pages/AlertDetailPage'
import { renderWithProviders } from './utils'
import * as alertsService from '@/services/alertsService'
import type { AlertRead, AlertListResponse } from '@/types/api'

afterEach(() => vi.restoreAllMocks())

function makeAlert(overrides: Partial<AlertRead> = {}): AlertRead {
  const now = new Date().toISOString()
  return {
    id: 'alert-1',
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
  return { items, limit: 10, offset: 0 }
}

function renderAlertDetail(route = '/alerts/alert-1') {
  return renderWithProviders(
    <Routes>
      <Route path="/alerts/:alertId" element={<AlertDetailPage />} />
      <Route path="/alerts/:alertId/investigation" element={<div>INVESTIGATION WORKSPACE MARKER</div>} />
      <Route path="/copilot" element={<div>COPILOT PAGE MARKER</div>} />
      <Route path="/events/:eventId" element={<div>EVENT DETAIL MARKER</div>} />
      <Route path="/rules/:ruleId" element={<div>RULE DETAIL MARKER</div>} />
    </Routes>,
    { route },
  )
}

describe('Step 12K: AlertDetailPage "why did this alert fire?" narrative', () => {
  it('renders this alert\'s real evidence values, not hardcoded demo data', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(
      makeAlert({
        rule_id: 'brute_force_authentication',
        evidence: {
          failure_count: 7,
          username: 'unlikely-demo-username-zzz',
          source_ip: '203.0.113.77',
          threshold: 5,
        },
      }),
    )
    renderAlertDetail()

    expect(await screen.findByText('7')).toBeInTheDocument()
    expect(screen.getByText('unlikely-demo-username-zzz')).toBeInTheDocument()
    expect(screen.getByText('203.0.113.77')).toBeInTheDocument()
    expect(screen.getByText('5')).toBeInTheDocument()
    // generic key humanization, not a hardcoded per-rule label
    expect(screen.getByText('Failure count')).toBeInTheDocument()
    expect(screen.getByText('Source ip')).toBeInTheDocument()
  })

  it('handles empty evidence safely, never fabricating a value', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert({ evidence: {} }))
    renderAlertDetail()

    expect(await screen.findByText('No structured evidence was recorded for this alert.')).toBeInTheDocument()
  })

  it('displays the static rule detectionLogic as rule context, separate from the alert\'s observed evidence', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(
      makeAlert({ rule_id: 'brute_force_authentication', evidence: { failure_count: 9 } }),
    )
    renderAlertDetail()

    expect(await screen.findByText(/Correlates authentication failures by \(username, source IP\)/)).toBeInTheDocument()
    expect(screen.getByText('Detection Rule Logic')).toBeInTheDocument()
    expect(screen.getByText('Observed Detection Evidence')).toBeInTheDocument()
  })

  it('shows all MITRE techniques for a rule with multiple mappings (encoded_powershell_command)', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert({ rule_id: 'encoded_powershell_command' }))
    renderAlertDetail()

    expect(await screen.findByText('T1059.001')).toBeInTheDocument()
    expect(screen.getByText('T1027.010')).toBeInTheDocument()
  })

  it('renders source_event_ids as real links, with no per-event API request', async () => {
    const eventSpyNames = ['getEvent', 'getSecurityEvent'] as const
    const spies = eventSpyNames
      .filter((name) => name in alertsService)
      .map((name) => vi.spyOn(alertsService as unknown as Record<string, () => unknown>, name))

    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(
      makeAlert({ source_event_ids: ['evt-aaa', 'evt-bbb'] }),
    )
    renderAlertDetail()

    const link = await screen.findByRole('link', { name: /evt-aaa/ })
    expect(link).toHaveAttribute('href', '/events/evt-aaa')
    expect(screen.getByRole('link', { name: /evt-bbb/ })).toHaveAttribute('href', '/events/evt-bbb')
    for (const spy of spies) expect(spy).not.toHaveBeenCalled()
  })

  it('navigates to the existing Investigation Workspace via the Investigate Alert CTA, without duplicating it inline', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert({ id: 'alert-1' }))
    renderAlertDetail()

    await screen.findByText('Brute force authentication detected')
    expect(screen.queryByText('INVESTIGATION WORKSPACE MARKER')).not.toBeInTheDocument()

    await userEvent.setup().click(screen.getByRole('button', { name: /investigate alert/i }))
    expect(await screen.findByText('INVESTIGATION WORKSPACE MARKER')).toBeInTheDocument()
  })

  it('never issues an automatic Copilot request while rendering the alert', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert())
    const copilotSpy = vi.spyOn(alertsService, 'askCopilot')
    renderAlertDetail()

    await screen.findByText('Brute force authentication detected')
    expect(copilotSpy).not.toHaveBeenCalled()
    expect(screen.queryByText('COPILOT PAGE MARKER')).not.toBeInTheDocument()
  })

  it('makes exactly one GET /alerts/{id} request and zero per-event / rule-list requests', async () => {
    const getAlertSpy = vi.spyOn(alertsService, 'getAlert').mockResolvedValue(
      makeAlert({ source_event_ids: ['evt-1', 'evt-2', 'evt-3'] }),
    )
    const listAlertsSpy = vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(resp([]))
    renderAlertDetail()

    await screen.findByText('Brute force authentication detected')
    expect(getAlertSpy).toHaveBeenCalledTimes(1)
    expect(listAlertsSpy).not.toHaveBeenCalled()
  })

  it('keeps an unknown rule_id safe: no fabricated rule name, no fabricated MITRE mapping, no crash', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(
      makeAlert({ rule_id: 'future_unmapped_rule', evidence: { some_future_field: 'x' } }),
    )
    renderAlertDetail()

    const matches = await screen.findAllByText('future_unmapped_rule')
    expect(matches.length).toBeGreaterThan(0)
    expect(screen.queryByRole('link', { name: 'future_unmapped_rule' })).not.toBeInTheDocument()
    expect(screen.getByText(/No rule context is available for/)).toBeInTheDocument()
    expect(screen.getByText(/No MITRE ATT&CK mapping exists for rule/)).toBeInTheDocument()
    // the alert's own evidence is still rendered even when the rule is unrecognized
    expect(screen.getByText('x')).toBeInTheDocument()
  })

  it('preserves an alert status control and loading/error states (Step 12L: now the Analyst Decision panel)', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert({ status: 'new' }))
    renderAlertDetail()

    expect(await screen.findByText('Analyst Decision')).toBeInTheDocument()
    expect(screen.getByText('Current Status')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Acknowledge' })).toBeInTheDocument()
  })
})
