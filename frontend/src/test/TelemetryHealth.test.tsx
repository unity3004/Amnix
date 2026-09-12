import { describe, expect, it, vi, afterEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { TelemetryHealthPage } from '@/pages/TelemetryHealthPage'
import { RuleDetailPage } from '@/pages/RuleDetailPage'
import { renderWithProviders } from './utils'
import * as eventsService from '@/services/eventsService'
import * as alertsService from '@/services/alertsService'
import { ApiError } from '@/services/httpClient'
import { DETECTION_RULES } from '@/features/rules/ruleRegistry'
import type { SecurityEventRead, SecurityEventListResponse, AlertRead, AlertListResponse } from '@/types/api'

afterEach(() => vi.restoreAllMocks())

function makeEvent(overrides: Partial<SecurityEventRead> = {}): SecurityEventRead {
  const now = new Date().toISOString()
  return {
    id: `event-${Math.random().toString(36).slice(2)}`,
    event_timestamp: now,
    event_type: 'authentication_failure',
    source: 'auth-log',
    raw_data: {},
    created_at: now,
    ...overrides,
  }
}
function eventsResp(items: SecurityEventRead[]): SecurityEventListResponse {
  return { items, limit: 100, offset: 0 }
}

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
function alertsResp(items: AlertRead[]): AlertListResponse {
  return { items, limit: 100, offset: 0 }
}

function renderTelemetry() {
  return renderWithProviders(
    <Routes>
      <Route path="/telemetry" element={<TelemetryHealthPage />} />
      <Route path="/rules/:ruleId" element={<RuleDetailPage />} />
      <Route path="/alerts/:alertId" element={<div>ALERT DETAIL MARKER</div>} />
    </Routes>,
    { route: '/telemetry' },
  )
}

describe('TelemetryHealthPage', () => {
  it('renders REAL observed event types from GET /events', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(
      eventsResp([makeEvent({ event_type: 'authentication_failure' }), makeEvent({ event_type: 'process_creation' })]),
    )
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([]))
    renderTelemetry()

    expect((await screen.findAllByText('authentication_failure')).length).toBeGreaterThan(0)
    expect(screen.getAllByText('process_creation').length).toBeGreaterThan(0)
  })

  it('renders REAL sources derived from SecurityEventRead.source', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([makeEvent({ source: 'sysmon-marker-source' })]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([]))
    renderTelemetry()

    expect((await screen.findAllByText('sysmon-marker-source')).length).toBeGreaterThan(0)
  })

  it('uses bounded-observation wording, never claiming a historical total', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([makeEvent()]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([]))
    renderTelemetry()

    await screen.findByText('Observed Telemetry')
    expect(document.body.textContent).toMatch(/not a historical total/i)
    expect(document.body.textContent).not.toMatch(/total events:\s*\d+|total alerts:\s*\d+/i)
  })

  it('never displays a fabricated coverage percentage or risk score', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([makeEvent()]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([makeAlert()]))
    renderTelemetry()

    await screen.findByText('Observed Telemetry')
    expect(document.body.textContent).not.toMatch(/coverage:\s*\d+%|risk score|threat score|detection score|\d+%\s*coverage/i)
  })

  it('derives rule -> event-type dependencies from the real static rule registry, not a second hardcoded mapping', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([makeEvent({ event_type: 'authentication_failure' })]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([]))
    renderTelemetry()

    for (const rule of DETECTION_RULES) {
      expect(await screen.findByText(rule.name)).toBeInTheDocument()
    }
    // brute_force_authentication depends on authentication_failure, which IS observed
    const bruteForceRow = screen.getByText('Brute Force Authentication').closest('tr')
    expect(bruteForceRow).toHaveTextContent('Telemetry observed recently')
  })

  it('shows "No recent telemetry observed" honestly for a rule whose event type was not observed -- never calls it broken', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([makeEvent({ event_type: 'authentication_failure' })]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([]))
    renderTelemetry()

    const psRow = (await screen.findByText('Suspicious PowerShell Execution')).closest('tr')
    expect(psRow).toHaveTextContent('No recent telemetry observed')
    expect(document.body.textContent).not.toMatch(/broken|does not work|failed detection/i)
  })

  it('derives Recent Detection Activity from real GET /alerts data, with no N+1 per-rule requests', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([makeEvent()]))
    const alertsMock = vi
      .spyOn(alertsService, 'listAlerts')
      .mockResolvedValue(alertsResp([makeAlert({ title: 'Real telemetry-linked alert' })]))
    renderTelemetry()

    expect(await screen.findByText('Real telemetry-linked alert')).toBeInTheDocument()
    expect(alertsMock).toHaveBeenCalledTimes(1)
    expect(alertsMock.mock.calls[0][0]).not.toHaveProperty('rule_id')
  })

  it('shows a safe error state when GET /events fails', async () => {
    vi.spyOn(eventsService, 'listEvents').mockRejectedValue(new ApiError(500, null, 'boom'))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([]))
    renderTelemetry()

    expect(await screen.findByText(/unable to retrieve telemetry/i)).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/ApiError|TypeError|traceback|boom/i)
  })

  it('shows a degraded state for detection activity when GET /alerts fails, while telemetry data remains visible', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([makeEvent({ event_type: 'authentication_failure' })]))
    vi.spyOn(alertsService, 'listAlerts').mockRejectedValue(new ApiError(500, null, 'boom'))
    renderTelemetry()

    expect((await screen.findAllByText('authentication_failure')).length).toBeGreaterThan(0)
    expect(await screen.findByText(/unable to retrieve recent alert activity/i)).toBeInTheDocument()
  })

  it('shows a clear page-level error when both events and alerts fail', async () => {
    vi.spyOn(eventsService, 'listEvents').mockRejectedValue(new ApiError(500, null, 'events boom'))
    vi.spyOn(alertsService, 'listAlerts').mockRejectedValue(new ApiError(500, null, 'alerts boom'))
    renderTelemetry()

    expect(await screen.findByText(/unable to retrieve telemetry or alert data/i)).toBeInTheDocument()
  })

  it('shows an honest empty telemetry state when no events are returned', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([]))
    renderTelemetry()

    // With zero events, no rule can show "telemetry observed" either, so
    // the empty-state message legitimately appears twice (the Observed
    // Telemetry section's own empty state, and every rule row's status
    // badge) -- assert at least one occurrence rather than a unique one.
    expect((await screen.findAllByText('No recent telemetry observed')).length).toBeGreaterThan(0)
  })

  it('shows an honest empty alert-activity state when no alerts are returned', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([makeEvent()]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([]))
    renderTelemetry()

    await screen.findByText('Observed Telemetry')
    // Legitimately appears once per rule's status badge plus the
    // Recent Detection Activity section's own empty-state heading.
    expect((await screen.findAllByText('No recent alert activity')).length).toBeGreaterThan(0)
  })

  it('surfaces a neutrally-worded potential visibility gap, never a "broken" claim', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([makeEvent({ event_type: 'authentication_failure' })]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([]))
    renderTelemetry()

    expect((await screen.findAllByText(/potential visibility gap/i)).length).toBeGreaterThan(0)
    expect(document.body.textContent).not.toMatch(/pipeline is broken|detection is broken|system failure/i)
  })

  it('navigates from the Detection Coverage Map to the real Rule Detail page', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([makeEvent({ event_type: 'authentication_failure' })]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([]))
    renderTelemetry()

    await userEvent.setup().click(await screen.findByRole('link', { name: 'Brute Force Authentication' }))
    expect(await screen.findByText('brute_force_authentication')).toBeInTheDocument()
  })

  it('navigates from Recent Detection Activity to the exact real alert', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([makeEvent()]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([makeAlert({ id: 'real-alert-id', title: 'Click-through alert' })]))
    renderTelemetry()

    await userEvent.setup().click(await screen.findByRole('button', { name: /Click-through alert/i }))
    expect(await screen.findByText('ALERT DETAIL MARKER')).toBeInTheDocument()
  })

  it('re-fetches both events and alerts exactly once when the observation window changes', async () => {
    const eventsMock = vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([makeEvent()]))
    const alertsMock = vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([]))
    renderTelemetry()
    await screen.findByText('Observed Telemetry')
    const eventsCallsBefore = eventsMock.mock.calls.length
    const alertsCallsBefore = alertsMock.mock.calls.length

    await userEvent.setup().selectOptions(screen.getByLabelText('Observation window'), '15')

    await waitFor(() => expect(eventsMock.mock.calls.length).toBe(eventsCallsBefore + 1))
    expect(alertsMock.mock.calls.length).toBe(alertsCallsBefore + 1)
  })
})
