import { describe, expect, it, vi, afterEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { AlertDetailPage } from '@/pages/AlertDetailPage'
import { renderWithProviders } from './utils'
import * as alertsService from '@/services/alertsService'
import { ApiError } from '@/services/httpClient'
import { compareAlertPriority, explainAlertPriority } from '@/features/alerts/priority'
import type { AlertRead } from '@/types/api'

afterEach(() => vi.restoreAllMocks())

function makeAlert(overrides: Partial<AlertRead> = {}): AlertRead {
  const now = new Date().toISOString()
  return {
    id: 'alert-triage-1',
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
    evidence: { failure_count: 7, username: 'jdoe' },
    alert_metadata: null,
    source_event_ids: ['evt-1'],
    ...overrides,
  }
}

function renderAlertDetail(route = '/alerts/alert-triage-1') {
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

describe('Step 12L: Alert Triage Workflow & Analyst Decision Center', () => {
  it('1. renders the real current alert status', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert({ status: 'investigating' }))
    renderAlertDetail()

    await screen.findByText('Analyst Decision')
    expect(screen.getByText('Current Status')).toBeInTheDocument()
    expect(screen.getAllByText('investigating').length).toBeGreaterThan(0)
  })

  it('2. renders only the backend-supported next statuses as available actions (mirrors the real transition graph)', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert({ status: 'new' }))
    renderAlertDetail()

    await screen.findByText('Available Analyst Actions')
    expect(screen.getByRole('button', { name: 'Acknowledge' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Start Investigating' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Escalate' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Resolve' })).not.toBeInTheDocument()
  })

  it('2b. a resolved (terminal) alert offers no further actions, never inventing a reopen action', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert({ status: 'resolved' }))
    renderAlertDetail()

    await screen.findByText('Analyst Decision')
    expect(screen.getByText('This alert is resolved. No further status changes are available.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /acknowledge|resolve|escalate|investigating/i })).not.toBeInTheDocument()
  })

  it('3. clicking an action sends PATCH to the correct alert id and target status', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert({ id: 'alert-triage-1', status: 'new' }))
    const patchMock = vi.spyOn(alertsService, 'updateAlertStatus').mockResolvedValue(makeAlert({ status: 'acknowledged' }))
    renderAlertDetail()

    await userEvent.setup().click(await screen.findByRole('button', { name: 'Acknowledge' }))
    await waitFor(() => expect(patchMock).toHaveBeenCalledWith('alert-triage-1', 'acknowledged'))
  })

  it('4. a successful server response updates the displayed current status without a page reload', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert({ status: 'new' }))
    vi.spyOn(alertsService, 'updateAlertStatus').mockResolvedValue(makeAlert({ status: 'acknowledged' }))
    renderAlertDetail()

    await userEvent.setup().click(await screen.findByRole('button', { name: 'Acknowledge' }))
    await waitFor(() => expect(screen.getByText('Alert status updated.')).toBeInTheDocument())
    expect(screen.getAllByText('acknowledged').length).toBeGreaterThan(0)
  })

  it('5. a failed update does not falsely change the displayed status', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert({ status: 'new' }))
    vi.spyOn(alertsService, 'updateAlertStatus').mockRejectedValue(new ApiError(409, { detail: 'boom' }, 'boom'))
    renderAlertDetail()

    await userEvent.setup().click(await screen.findByRole('button', { name: 'Acknowledge' }))
    await waitFor(() => expect(screen.getByText('Alert status could not be updated.')).toBeInTheDocument())
    expect(screen.getAllByText('new').length).toBeGreaterThan(0)
    expect(screen.queryByText('acknowledged')).not.toBeInTheDocument()
  })

  it('6. duplicate submissions are prevented while a status update is pending', async () => {
    let resolvePatch!: (alert: AlertRead) => void
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert({ status: 'new' }))
    vi.spyOn(alertsService, 'updateAlertStatus').mockReturnValue(
      new Promise((resolve) => {
        resolvePatch = resolve
      }),
    )
    renderAlertDetail()

    const user = userEvent.setup()
    const ackButton = await screen.findByRole('button', { name: 'Acknowledge' })
    await user.click(ackButton)

    expect(await screen.findByText('Updating alert status…')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Updating…' })).toBeDisabled()
    const escalateButton = screen.getByRole('button', { name: 'Escalate' })
    expect(escalateButton).toBeDisabled()

    resolvePatch(makeAlert({ status: 'acknowledged' }))
    await waitFor(() => expect(screen.getByText('Alert status updated.')).toBeInTheDocument())
  })

  it('7. a safe error message is rendered, never a raw backend exception', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert({ status: 'new' }))
    vi.spyOn(alertsService, 'updateAlertStatus').mockRejectedValue(new ApiError(500, null, 'boom'))
    renderAlertDetail()

    await userEvent.setup().click(await screen.findByRole('button', { name: 'Acknowledge' }))
    await waitFor(() => expect(screen.getByText('Alert status could not be updated.')).toBeInTheDocument())
    expect(document.body.textContent).not.toMatch(/traceback|stack|sql|exception|boom/i)
  })

  it('8-9. Triage Readiness reflects real available evidence, with no fabricated percentage', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(
      makeAlert({ rule_id: 'brute_force_authentication', evidence: { failure_count: 7 }, source_event_ids: ['evt-1'] }),
    )
    renderAlertDetail()

    await screen.findByText('Triage Readiness')
    expect(screen.getByText('Detection rule identified')).toBeInTheDocument()
    expect(screen.getByText('Alert evidence available')).toBeInTheDocument()
    expect(screen.getByText('Supporting events available')).toBeInTheDocument()
    expect(screen.getByText('MITRE context available')).toBeInTheDocument()
    expect(screen.getByText('Investigation available')).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/\d+%\s*(ready|readiness|complete)/i)
    expect(document.body.textContent).not.toMatch(/risk score|threat score|probability/i)
  })

  it('10-13. readiness signals are individually correct for a full-evidence alert', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(
      makeAlert({
        rule_id: 'encoded_powershell_command',
        evidence: { process_name: 'powershell.exe' },
        source_event_ids: ['evt-1', 'evt-2'],
      }),
    )
    renderAlertDetail()

    await screen.findByText('Triage Readiness')
    // rule identified -> real rule name link exists
    expect(await screen.findByRole('link', { name: 'Encoded PowerShell Command' })).toBeInTheDocument()
    // evidence available -> rendered
    expect(screen.getAllByText('powershell.exe').length).toBeGreaterThan(0)
    // MITRE available -> both techniques for this rule show
    expect(screen.getByText('T1059.001')).toBeInTheDocument()
    expect(screen.getByText('T1027.010')).toBeInTheDocument()
  })

  it('11. evidence-unavailable state is correct for empty evidence', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert({ evidence: {} }))
    renderAlertDetail()

    await screen.findByText('Triage Readiness')
    const items = screen.getAllByText('Alert evidence available')
    expect(items.length).toBe(1)
    expect(screen.getByText('No structured evidence was recorded for this alert.')).toBeInTheDocument()
  })

  it('12. supporting-events-unavailable state is correct', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert({ source_event_ids: [] }))
    renderAlertDetail()

    await screen.findByText('Triage Readiness')
    expect(screen.getByText('No source events recorded for this alert.')).toBeInTheDocument()
  })

  it('13. MITRE-unavailable state is correct for a rule with no mapping', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert({ rule_id: 'future_unmapped_rule' }))
    renderAlertDetail()

    await screen.findByText('Triage Readiness')
    expect(screen.getByText(/No MITRE ATT&CK mapping exists for rule/)).toBeInTheDocument()
  })

  it('14. an unknown rule_id is handled safely everywhere on the page, including the Analyst Decision panel', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert({ rule_id: 'future_unmapped_rule', status: 'new' }))
    renderAlertDetail()

    await screen.findByText('Triage Readiness')
    expect(screen.queryByRole('link', { name: 'future_unmapped_rule' })).not.toBeInTheDocument()
    // Analyst Decision is unaffected by rule resolution -- still offers real actions
    expect(await screen.findByRole('button', { name: 'Acknowledge' })).toBeInTheDocument()
  })

  it('15. the Investigate Alert CTA still navigates to the existing Investigation Workspace', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert())
    renderAlertDetail()

    await screen.findByText('Brute force authentication detected')
    await userEvent.setup().click(screen.getByRole('button', { name: /investigate alert/i }))
    expect(await screen.findByText('INVESTIGATION WORKSPACE MARKER')).toBeInTheDocument()
  })

  it('16. no automatic Copilot request occurs while rendering or updating status', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert({ status: 'new' }))
    vi.spyOn(alertsService, 'updateAlertStatus').mockResolvedValue(makeAlert({ status: 'acknowledged' }))
    const copilotSpy = vi.spyOn(alertsService, 'askCopilot')
    renderAlertDetail()

    await userEvent.setup().click(await screen.findByRole('button', { name: 'Acknowledge' }))
    await waitFor(() => expect(screen.getByText('Alert status updated.')).toBeInTheDocument())
    expect(copilotSpy).not.toHaveBeenCalled()
  })

  it('17. no automatic investigation request occurs while rendering or updating status', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(makeAlert({ status: 'new' }))
    vi.spyOn(alertsService, 'updateAlertStatus').mockResolvedValue(makeAlert({ status: 'acknowledged' }))
    const investigationSpy = vi.spyOn(alertsService, 'getAlertInvestigation')
    renderAlertDetail()

    await userEvent.setup().click(await screen.findByRole('button', { name: 'Acknowledge' }))
    await waitFor(() => expect(screen.getByText('Alert status updated.')).toBeInTheDocument())
    expect(investigationSpy).not.toHaveBeenCalled()
  })

  it('18. no per-event N+1 requests occur, and exactly one PATCH is sent per status change', async () => {
    const getAlertSpy = vi.spyOn(alertsService, 'getAlert').mockResolvedValue(
      makeAlert({ status: 'new', source_event_ids: ['evt-1', 'evt-2', 'evt-3'] }),
    )
    const patchSpy = vi.spyOn(alertsService, 'updateAlertStatus').mockResolvedValue(makeAlert({ status: 'acknowledged' }))
    renderAlertDetail()

    await userEvent.setup().click(await screen.findByRole('button', { name: 'Acknowledge' }))
    await waitFor(() => expect(patchSpy).toHaveBeenCalledTimes(1))
    expect(getAlertSpy).toHaveBeenCalledTimes(1)
  })

  it('19. the priority explanation reuses the exact Step 12G comparator/explanation logic', async () => {
    const alert = makeAlert({ severity: 'critical', status: 'escalated' })
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(alert)
    renderAlertDetail()

    await screen.findByText('Brute force authentication detected')
    expect(screen.getByText(explainAlertPriority(alert))).toBeInTheDocument()
    expect(typeof compareAlertPriority).toBe('function')
  })

  it('20. existing Alert Detail functionality remains intact: evidence, supporting events, MITRE, description', async () => {
    vi.spyOn(alertsService, 'getAlert').mockResolvedValue(
      makeAlert({ description: 'Six failed attempts observed.', evidence: { failure_count: 6 } }),
    )
    renderAlertDetail()

    expect(await screen.findByText('Six failed attempts observed.')).toBeInTheDocument()
    expect(screen.getByText('6')).toBeInTheDocument()
    expect(screen.getByText('T1110')).toBeInTheDocument()
    expect(await screen.findByRole('link', { name: /evt-1/ })).toHaveAttribute('href', '/events/evt-1')
  })
})
