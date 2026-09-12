import { describe, expect, it, vi, afterEach } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { DetectionHealthPage } from '@/pages/DetectionHealthPage'
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

function renderHealth(route = '/detection-health') {
  return renderWithProviders(
    <Routes>
      <Route path="/detection-health" element={<DetectionHealthPage />} />
      <Route path="/rules/:ruleId" element={<div>RULE DETAIL MARKER</div>} />
    </Routes>,
    { route },
  )
}

describe('Step 12O: Detection Health & Rule Observability', () => {
  it('1. every real registry rule renders in the observability table', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([]))
    renderHealth()

    await screen.findByText('Detection Rule Observability')
    for (const rule of DETECTION_RULES) {
      expect(screen.getByText(rule.name)).toBeInTheDocument()
    }
  })

  it('2. real observed event types render', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([makeEvent({ event_type: 'process_creation' })]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([]))
    renderHealth()

    const coverageHeading = await screen.findByText('Event Type Coverage')
    const coverageCard = coverageHeading.closest('.rounded-lg') as HTMLElement
    expect(within(coverageCard).getByText('process_creation')).toBeInTheDocument()
  })

  it('3. telemetry-to-rule mapping is correct', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([makeEvent({ event_type: 'process_creation' })]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([]))
    renderHealth()

    const coverageHeading = await screen.findByText('Event Type Coverage')
    const coverageCard = coverageHeading.closest('.rounded-lg') as HTMLElement
    const row = within(coverageCard).getByText('process_creation').closest('li') as HTMLElement
    expect(within(row).getByText('Suspicious PowerShell Execution')).toBeInTheDocument()
    expect(within(row).getByText('Encoded PowerShell Command')).toBeInTheDocument()
  })

  it('4-5. a rule with telemetry and alerts shows both, with the correct combined observation', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([makeEvent({ event_type: 'authentication_failure' })]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(
      alertsResp([makeAlert({ rule_id: 'brute_force_authentication' })]),
    )
    renderHealth()

    const obsHeading = await screen.findByText('Detection Rule Observability')
    const obsCard = obsHeading.closest('.rounded-lg') as HTMLElement
    const nameLink = within(obsCard).getByRole('link', { name: 'Brute Force Authentication' })
    const row = nameLink.closest('tr') as HTMLElement
    expect(within(row).getByText('Observed')).toBeInTheDocument()
    expect(within(row).getByText('1')).toBeInTheDocument()
    expect(within(row).getByText('Telemetry observed; recent alert activity observed.')).toBeInTheDocument()
  })

  it('6. a rule with telemetry but no alerts shows the correct neutral observation', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([makeEvent({ event_type: 'authentication_failure' })]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([]))
    renderHealth()

    const obsHeading = await screen.findByText('Detection Rule Observability')
    const obsCard = obsHeading.closest('.rounded-lg') as HTMLElement
    const nameLink = within(obsCard).getByRole('link', { name: 'Brute Force Authentication' })
    const row = nameLink.closest('tr') as HTMLElement
    expect(within(row).getByText('Telemetry observed; no recent alert activity returned.')).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/rule is broken|detection failed|missed an attack/i)
  })

  it('7. a rule with no observed telemetry shows the correct neutral observation', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([]))
    renderHealth()

    const nameLink = await screen.findByRole('link', { name: 'Brute Force Authentication' })
    const row = nameLink.closest('tr') as HTMLElement
    expect(within(row).getByText('No dependent telemetry observed in this view.')).toBeInTheDocument()
  })

  it('8. an unknown rule_id present on real alerts is handled safely', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([makeAlert({ rule_id: 'future_unmapped_rule' })]))
    renderHealth()

    expect(await screen.findAllByText('future_unmapped_rule')).not.toHaveLength(0)
    expect(screen.getByText('No registry metadata available')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'future_unmapped_rule' })).not.toBeInTheDocument()
  })

  it('9-10. evidence and supporting-event availability are correct', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(
      alertsResp([
        makeAlert({ rule_id: 'brute_force_authentication', evidence: { failure_count: 5 }, source_event_ids: ['e1'] }),
        makeAlert({ rule_id: 'brute_force_authentication', evidence: {}, source_event_ids: [] }),
      ]),
    )
    renderHealth()

    const nameLink = await screen.findByRole('link', { name: 'Brute Force Authentication' })
    const row = nameLink.closest('tr') as HTMLElement
    expect(within(row).getByText('1 / 2')).toBeInTheDocument()
  })

  it('11-12. MITRE mapping is correct, including a multi-technique rule', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([]))
    renderHealth()

    const bfLink = await screen.findByRole('link', { name: 'Brute Force Authentication' })
    expect((bfLink.closest('tr') as HTMLElement)).toHaveTextContent('T1110')

    const encLink = screen.getByRole('link', { name: 'Encoded PowerShell Command' })
    const encRow = encLink.closest('tr') as HTMLElement
    expect(encRow).toHaveTextContent('T1059.001')
    expect(encRow).toHaveTextContent('T1027.010')
  })

  it('13-15. no effectiveness/accuracy/false-positive/true-positive metric ever appears (disclaimer negations like "not a measure of rule effectiveness" are expected and excluded)', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([makeEvent()]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([makeAlert()]))
    renderHealth()

    await screen.findByText('Detection Rule Observability')
    expect(document.body.textContent).not.toMatch(
      /\beffectiveness:\s*\d|\baccuracy:\s*\d|\bprecision:\s*\d|\brecall:\s*\d|true.?positive rate|false.?positive rate|detection quality:\s*\d|coverage percentage:\s*\d/i,
    )
    expect(document.body.textContent).not.toMatch(/\b(good|bad|effective|ineffective) rule\b/i)
    expect(document.body.textContent).not.toMatch(/\bworking\b|\bbroken\b/i)
  })

  it('17. no fabricated historical total appears anywhere (the honest "does not represent historical totals" disclaimer is expected and excluded)', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([makeEvent()]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([makeAlert()]))
    renderHealth()

    await screen.findByText('Detection Rule Observability')
    expect(document.body.textContent).not.toMatch(/total alerts:\s*\d+|total events:\s*\d+|historical total:\s*\d+/i)
    expect(screen.getByText(/this view does not represent historical totals/i)).toBeInTheDocument()
  })

  it('18. the observation window is recomputed fresh on every fetch (no staleness)', async () => {
    const alertsMock = vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([makeAlert()]))
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([]))
    renderHealth()
    await screen.findByText('Detection Rule Observability')

    const firstSince = alertsMock.mock.calls.at(-1)?.[0]?.since
    expect(firstSince).toBeTruthy()

    await userEvent.setup().selectOptions(screen.getByLabelText('Observation window'), '15')
    await screen.findByText('Detection Rule Observability')
    const secondSince = alertsMock.mock.calls.at(-1)?.[0]?.since
    expect(secondSince).not.toBe(firstSince)
  })

  it('19. a loading state is shown before data resolves', () => {
    vi.spyOn(eventsService, 'listEvents').mockReturnValue(new Promise(() => {}))
    vi.spyOn(alertsService, 'listAlerts').mockReturnValue(new Promise(() => {}))
    const { container } = renderHealth()
    expect(container.querySelectorAll('.animate-pulse').length).toBeGreaterThan(0)
  })

  it('20. a full failure of both sources shows a safe error state, never a raw exception', async () => {
    vi.spyOn(eventsService, 'listEvents').mockRejectedValue(new ApiError(500, null, 'boom'))
    vi.spyOn(alertsService, 'listAlerts').mockRejectedValue(new ApiError(500, null, 'boom'))
    renderHealth()

    expect(await screen.findByText('Detection health data could not be loaded')).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/ApiError|TypeError|traceback|boom/i)
  })

  it('21. a partial failure (alerts down, telemetry up) marks alert-dependent columns Unavailable, never a misleading zero', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([makeEvent({ event_type: 'authentication_failure' })]))
    vi.spyOn(alertsService, 'listAlerts').mockRejectedValue(new ApiError(500, null, 'boom'))
    renderHealth()

    const obsHeading = await screen.findByText('Detection Rule Observability')
    const obsCard = obsHeading.closest('.rounded-lg') as HTMLElement
    const nameLink = within(obsCard).getByRole('link', { name: 'Brute Force Authentication' })
    const row = nameLink.closest('tr') as HTMLElement
    expect(within(row).getAllByText('Unavailable').length).toBeGreaterThan(0)
    expect(within(row).queryByText('0')).not.toBeInTheDocument()
    expect(screen.getByText(/Alert activity could not be retrieved for this refresh/)).toBeInTheDocument()
  })

  it('22. an honest empty state is shown when no telemetry or alerts are returned', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([]))
    renderHealth()

    expect(await screen.findByText('No detection activity is available for the selected view.')).toBeInTheDocument()
  })

  it('23-24. exactly one GET /alerts and one GET /events request occur on load', async () => {
    const alertsMock = vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([makeAlert()]))
    const eventsMock = vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([makeEvent()]))
    renderHealth()

    await screen.findByText('Detection Rule Observability')
    expect(alertsMock).toHaveBeenCalledTimes(1)
    expect(eventsMock).toHaveBeenCalledTimes(1)
  })

  it('25-28. zero per-rule, per-alert, per-event, investigation, or Copilot requests occur', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([makeAlert(), makeAlert()]))
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([makeEvent(), makeEvent()]))
    const getAlertSpy = vi.spyOn(alertsService, 'getAlert')
    const getEventSpy = vi.spyOn(eventsService, 'getEvent')
    const investigationSpy = vi.spyOn(alertsService, 'getAlertInvestigation')
    const copilotSpy = vi.spyOn(alertsService, 'askCopilot')
    renderHealth()

    await screen.findByText('Detection Rule Observability')
    expect(getAlertSpy).not.toHaveBeenCalled()
    expect(getEventSpy).not.toHaveBeenCalled()
    expect(investigationSpy).not.toHaveBeenCalled()
    expect(copilotSpy).not.toHaveBeenCalled()
  })

  it('30. existing navigation remains intact -- rule links navigate to the real Rule Detail page', async () => {
    vi.spyOn(eventsService, 'listEvents').mockResolvedValue(eventsResp([]))
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(alertsResp([]))
    renderHealth()

    const link = await screen.findByRole('link', { name: 'Brute Force Authentication' })
    expect(link).toHaveAttribute('href', '/rules/brute_force_authentication')
    await userEvent.setup().click(link)
    expect(await screen.findByText('RULE DETAIL MARKER')).toBeInTheDocument()
  })
})
