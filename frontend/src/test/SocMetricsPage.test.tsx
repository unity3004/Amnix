import { describe, expect, it, vi, afterEach } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { SocMetricsPage } from '@/pages/SocMetricsPage'
import { renderWithProviders } from './utils'
import * as eventsService from '@/services/eventsService'
import * as alertsService from '@/services/alertsService'
import { ApiError } from '@/services/httpClient'
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

function renderMetrics(route = '/metrics') {
  return renderWithProviders(
    <Routes>
      <Route path="/metrics" element={<SocMetricsPage />} />
      <Route path="/alerts" element={<div>ALERT QUEUE MARKER</div>} />
    </Routes>,
    { route },
  )
}

describe('Step 12N: SOC Investigation Metrics & Workflow Insights', () => {
  it('1-2. real alerts produce summary metrics, explicitly bounded to the returned dataset', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(
      alertsResp([makeAlert({ severity: 'critical', status: 'escalated' })]),
    )
    renderMetrics()

    expect(await screen.findByText('Alerts Returned')).toBeInTheDocument()
    expect(screen.getByText(/Metrics reflect the alerts returned by the current query/i)).toBeInTheDocument()
  })

  it('3. never claims a fabricated total', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([makeAlert()]))
    renderMetrics()

    await screen.findByText('Alerts Returned')
    expect(document.body.textContent).not.toMatch(/total alerts:\s*\d+|total:\s*\d[\d,]*|total SOC backlog:\s*\d+/i)
  })

  it('4. status distribution reflects the real returned alerts', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(
      alertsResp([makeAlert({ status: 'investigating' }), makeAlert({ status: 'investigating' }), makeAlert({ status: 'new' })]),
    )
    renderMetrics()

    await screen.findByText('Current Alert Status Distribution')
    const investigatingCard = screen.getByText('investigating').closest('div')
    expect(investigatingCard).toHaveTextContent('2')
  })

  it('5. severity distribution reflects the real returned alerts', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(
      alertsResp([makeAlert({ severity: 'critical' }), makeAlert({ severity: 'critical' })]),
    )
    renderMetrics()

    const severityHeading = await screen.findByText('Severity Distribution')
    const severityCard = severityHeading.closest('.rounded-lg') as HTMLElement
    const criticalCard = within(severityCard).getByText('critical').closest('div')
    expect(criticalCard).toHaveTextContent('2')
  })

  it('6-7. rule activity is correct, and an unknown rule_id remains safe', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(
      alertsResp([
        makeAlert({ rule_id: 'brute_force_authentication' }),
        makeAlert({ rule_id: 'brute_force_authentication' }),
        makeAlert({ rule_id: 'future_unmapped_rule' }),
      ]),
    )
    renderMetrics()

    await screen.findByText('Alert Activity by Detection Rule')
    expect(screen.getByText('Brute Force Authentication')).toBeInTheDocument()
    expect(screen.getAllByText('future_unmapped_rule').length).toBeGreaterThan(0)
    expect(screen.queryByText('Most effective rule')).not.toBeInTheDocument()
  })

  it('8-10. evidence, supporting-event, and MITRE availability are correct', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(
      alertsResp([
        makeAlert({ rule_id: 'brute_force_authentication', evidence: { failure_count: 5 }, source_event_ids: ['e1'] }),
        makeAlert({ rule_id: 'future_unmapped_rule', evidence: {}, source_event_ids: [] }),
      ]),
    )
    renderMetrics()

    await screen.findByText('Evidence Availability')
    expect(screen.getByText('Structured Evidence Available')).toBeInTheDocument()
    const evidenceValue = screen.getByText('Structured Evidence Available').nextElementSibling
    expect(evidenceValue).toHaveTextContent('1 / 2')
    const eventsValue = screen.getByText('Supporting Events Available').nextElementSibling
    expect(eventsValue).toHaveTextContent('1 / 2')
    const mitreValue = screen.getByText('MITRE Mapping Available').nextElementSibling
    expect(mitreValue).toHaveTextContent('1 / 2')
  })

  it('11-12. the observation window is correct and recomputed fresh on every fetch (no staleness)', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([]))
    const alertsMock = vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([makeAlert()]))
    renderMetrics()
    await screen.findByText('Alerts Returned')

    const firstSince = alertsMock.mock.calls.at(-1)?.[0]?.since
    expect(firstSince).toBeTruthy()

    await userEvent.setup().selectOptions(screen.getByLabelText('Observation window'), '15')
    await waitFor(() => expect(alertsMock.mock.calls.length).toBeGreaterThan(1))
    const secondSince = alertsMock.mock.calls.at(-1)?.[0]?.since
    expect(secondSince).not.toBe(firstSince)
  })

  it('13. alert activity buckets are rendered from real first_seen timestamps', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([makeAlert()]))
    renderMetrics()

    expect(await screen.findByRole('img', { name: /recent alert activity/i })).toBeInTheDocument()
  })

  it('14. zero-value severity/status states are shown honestly, not omitted', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([makeAlert({ severity: 'high', status: 'new' })]))
    renderMetrics()

    await screen.findByText('Severity Distribution')
    expect(screen.getByText('No critical alerts returned in this view.')).toBeInTheDocument()
    expect(screen.getByText('No resolved alerts returned in this view.')).toBeInTheDocument()
  })

  it('15. a safe error state is shown on API failure, never a raw exception', async () => {
    vi.spyOn(eventsService, 'listEvents').mockRejectedValue(new ApiError(500, null, 'boom'))
    vi.spyOn(alertsService, 'listAlerts').mockRejectedValue(new ApiError(500, null, 'boom'))
    renderMetrics()

    expect(await screen.findByText('SOC metrics could not be loaded')).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/ApiError|TypeError|traceback|boom/i)
  })

  it('16. an honest empty state is shown when no alerts are returned', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([]))
    renderMetrics()

    expect(await screen.findByText('No alert activity is available for the selected view.')).toBeInTheDocument()
  })

  it('17-18. no investigation or Copilot fanout occurs while rendering metrics', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([makeEvent()]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([makeAlert()]))
    const investigationSpy = vi.spyOn(alertsService, 'getAlertInvestigation')
    const copilotSpy = vi.spyOn(alertsService, 'askCopilot')
    renderMetrics()

    await screen.findByText('Alerts Returned')
    expect(investigationSpy).not.toHaveBeenCalled()
    expect(copilotSpy).not.toHaveBeenCalled()
  })

  it('19-20. exactly one GET /alerts and one GET /events request occur, never per-alert or per-event', async () => {
    const alertsMock = vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(
      alertsResp([makeAlert(), makeAlert(), makeAlert()]),
    )
    const eventsMock = vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([makeEvent(), makeEvent()]))
    const getAlertSpy = vi.spyOn(alertsService, 'getAlert')
    const getEventSpy = vi.spyOn(eventsService, 'getEvent')
    renderMetrics()

    await screen.findByText('Alerts Returned')
    expect(alertsMock).toHaveBeenCalledTimes(1)
    expect(eventsMock).toHaveBeenCalledTimes(1)
    expect(getAlertSpy).not.toHaveBeenCalled()
    expect(getEventSpy).not.toHaveBeenCalled()
  })

  it('21. no fabricated MTTR/MTTD figure ever appears', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([makeAlert()]))
    renderMetrics()

    await screen.findByText('Alerts Returned')
    expect(document.body.textContent).not.toMatch(/mttr|mttd|mean time to (resolve|detect)/i)
    expect(screen.getByText(/Investigation completion cannot be measured globally/)).toBeInTheDocument()
  })

  it('22. no fabricated historical trend or growth percentage ever appears', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([makeAlert({ severity: 'critical' })]))
    renderMetrics()

    await screen.findByText('Alerts Returned')
    expect(document.body.textContent).not.toMatch(/\+\d+%|-\d+%\s*(from|vs\.?)|yesterday|last week/i)
  })

  it('24. existing navigation is unaffected -- the Alert Queue link from Investigation Insight works', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([makeAlert()]))
    renderMetrics()

    const link = await screen.findByRole('link', { name: /open the alert queue/i })
    expect(link).toHaveAttribute('href', '/alerts')
    await userEvent.setup().click(link)
    expect(await screen.findByText('ALERT QUEUE MARKER')).toBeInTheDocument()
  })

  it('never displays fabricated analyst productivity, SLA, or Copilot-usage metrics', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([makeAlert()]))
    renderMetrics()

    await screen.findByText('Alerts Returned')
    expect(document.body.textContent).not.toMatch(/sla compliance|analyst productivity|response time score|copilot usage:\s*\d+/i)
    expect(screen.getByText(/Copilot usage cannot be measured here/)).toBeInTheDocument()
  })
})
