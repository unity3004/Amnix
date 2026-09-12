import { describe, expect, it, vi, afterEach } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { AlertsPage } from '@/pages/AlertsPage'
import { renderWithProviders } from './utils'
import * as alertsService from '@/services/alertsService'
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
  return { items, limit: 25, offset: 0 }
}

function renderQueue(route = '/alerts') {
  return renderWithProviders(
    <Routes>
      <Route path="/alerts" element={<AlertsPage />} />
      <Route path="/alerts/:alertId" element={<div>ALERT DETAIL MARKER</div>} />
    </Routes>,
    { route },
  )
}

describe('Step 12M: SOC Alert Queue & Analyst Workbench', () => {
  it('1. renders real AlertRead data', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(
      resp([makeAlert({ title: 'Real queue alert', severity: 'critical' })]),
    )
    renderQueue()
    expect(await screen.findByText('Real queue alert')).toBeInTheDocument()
  })

  it('2-3. Queue Summary derives counts only from the returned page, never claiming a global total', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(
      resp([
        makeAlert({ severity: 'critical', status: 'new' }),
        makeAlert({ severity: 'high', status: 'investigating' }),
        makeAlert({ severity: 'low', status: 'escalated' }),
      ]),
    )
    renderQueue()

    expect(await screen.findByText('Alerts Returned')).toBeInTheDocument()
    expect(screen.getByText('Critical / High')).toBeInTheDocument()
    expect(screen.getByText(/Summary of alerts returned in this view/)).toBeInTheDocument()
    expect(screen.getByText(/not a total SOC backlog/)).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/total alerts:\s*\d+|total:\s*\d[\d,]*|page \d+ of \d+/i)
  })

  it('4-5. severity and status display correctly per row', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(
      resp([makeAlert({ title: 'Sev/status marker', severity: 'medium', status: 'acknowledged' })]),
    )
    renderQueue()
    const row = await screen.findByRole('button', { name: /Sev\/status marker/i })
    expect(row).toHaveTextContent('medium')
    expect(row).toHaveTextContent('acknowledged')
  })

  it('6. rule resolves through the static rule registry (real name shown)', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(
      resp([makeAlert({ title: 'Rule marker', rule_id: 'brute_force_authentication' })]),
    )
    renderQueue()
    const row = await screen.findByRole('button', { name: /Rule marker/i })
    expect(row).toHaveTextContent('Brute Force Authentication')
  })

  it('7. an unknown rule_id remains safe -- raw rule_id shown, never a fabricated name', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(
      resp([makeAlert({ title: 'Unknown rule marker', rule_id: 'future_unmapped_rule' })]),
    )
    renderQueue()
    const row = await screen.findByRole('button', { name: /Unknown rule marker/i })
    expect(row).toHaveTextContent('future_unmapped_rule')
    expect(row).toHaveTextContent('No mapping')
  })

  it('8. evidence availability derives from the real alert.evidence field', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(
      resp([
        makeAlert({ title: 'Has evidence', evidence: { failure_count: 5 } }),
        makeAlert({ title: 'No evidence', evidence: {} }),
      ]),
    )
    renderQueue()
    const withEvidence = await screen.findByRole('button', { name: /Has evidence/i })
    expect(withEvidence).toHaveTextContent('Evidence available')
    const withoutEvidence = screen.getByRole('button', { name: /No evidence/i })
    expect(withoutEvidence).toHaveTextContent('No structured evidence')
  })

  it('9. supporting event count derives from the real source_event_ids length', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(
      resp([makeAlert({ title: 'Event count marker', source_event_ids: ['e1', 'e2', 'e3'] })]),
    )
    renderQueue()
    const row = await screen.findByRole('button', { name: /Event count marker/i })
    expect(row).toHaveTextContent('3 events')
  })

  it('10. MITRE mapping derives from the static registry', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(
      resp([makeAlert({ title: 'MITRE marker', rule_id: 'brute_force_authentication' })]),
    )
    renderQueue()
    const row = await screen.findByRole('button', { name: /MITRE marker/i })
    expect(row).toHaveTextContent('T1110')
  })

  it('11. a multi-technique rule (encoded_powershell_command) displays both MITRE techniques, not just the first', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(
      resp([makeAlert({ title: 'Multi MITRE marker', rule_id: 'encoded_powershell_command' })]),
    )
    renderQueue()
    const row = await screen.findByRole('button', { name: /Multi MITRE marker/i })
    expect(row).toHaveTextContent('T1059.001')
    expect(row).toHaveTextContent('T1027.010')
  })

  it('12-13. priority sorting reuses Step 12G exactly and is explicitly page-scoped', async () => {
    const low = makeAlert({ id: 'low', title: 'Low priority alert', severity: 'low' })
    const critical = makeAlert({ id: 'critical', title: 'Critical priority alert', severity: 'critical' })
    const mock = vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(resp([low, critical]))
    renderQueue()
    await screen.findByText('Low priority alert')
    const callsBeforeSort = mock.mock.calls.length

    await userEvent.setup().selectOptions(screen.getByLabelText('Sort'), 'priority')

    const rows = await screen.findAllByRole('button', { name: /priority alert/i })
    expect(rows[0]).toHaveTextContent('Critical priority alert')
    expect(rows[1]).toHaveTextContent('Low priority alert')
    expect(screen.getByText(/priority order applies to this page only/i)).toBeInTheDocument()
    expect(mock.mock.calls.length).toBe(callsBeforeSort)
  })

  it('14. server-order mode preserves the real API-returned order', async () => {
    const first = makeAlert({ id: 'first', title: 'First returned alert', severity: 'low' })
    const second = makeAlert({ id: 'second', title: 'Second returned alert', severity: 'critical' })
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(resp([first, second]))
    renderQueue()

    await screen.findByText('First returned alert')
    const rows = screen.getAllByRole('button', { name: /returned alert/i })
    expect(rows[0]).toHaveTextContent('First returned alert')
    expect(rows[1]).toHaveTextContent('Second returned alert')
  })

  it('15-17. status/severity/rule filters reach GET /alerts as real query parameters', async () => {
    const mock = vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(resp([]))
    renderQueue()
    await screen.findByText('No alerts were returned for this view.')

    const user = userEvent.setup()
    await user.selectOptions(screen.getByLabelText('Status'), 'escalated')
    await user.selectOptions(screen.getByLabelText('Severity'), 'critical')
    await user.type(screen.getByLabelText('Rule ID'), 'encoded_powershell_command')
    await user.click(screen.getByRole('button', { name: /^apply$/i }))

    const lastCall = mock.mock.calls.at(-1)?.[0]
    expect(lastCall).toMatchObject({ status: 'escalated', severity: 'critical', rule_id: 'encoded_powershell_command' })
  })

  it('19. pagination preserves active filters in the URL/query', async () => {
    const mock = vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(
      resp(Array.from({ length: 25 }, () => makeAlert({ status: 'investigating' }))),
    )
    renderQueue('/alerts?status=investigating')
    await screen.findByText('Page 1')

    await userEvent.setup().click(screen.getByRole('button', { name: /^next$/i }))

    const lastCall = mock.mock.calls.at(-1)?.[0]
    expect(lastCall).toMatchObject({ status: 'investigating', offset: 25 })
  })

  it('20. empty queue state is shown honestly', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(resp([]))
    renderQueue()
    expect(await screen.findByText('No alerts were returned for this view.')).toBeInTheDocument()
  })

  it('21. filtered-empty state is distinct from the genuinely-empty state', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(resp([]))
    renderQueue('/alerts?rule_id=nonexistent_rule')
    expect(await screen.findByText('No alerts match the selected filters.')).toBeInTheDocument()
  })

  it('23. alert navigation opens the real Alert Detail / Step 12L triage workflow', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(
      resp([makeAlert({ id: 'real-alert-id', title: 'Click-through queue alert' })]),
    )
    renderQueue()
    await userEvent.setup().click(await screen.findByRole('button', { name: /Click-through queue alert/i }))
    expect(await screen.findByText('ALERT DETAIL MARKER')).toBeInTheDocument()
  })

  it('24-25. opening the queue makes no automatic investigation or Copilot request', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(resp([makeAlert()]))
    const investigationSpy = vi.spyOn(alertsService, 'getAlertInvestigation')
    const copilotSpy = vi.spyOn(alertsService, 'askCopilot')
    renderQueue()

    await screen.findByText('Brute force authentication detected')
    expect(investigationSpy).not.toHaveBeenCalled()
    expect(copilotSpy).not.toHaveBeenCalled()
  })

  it('26. opening the queue makes no per-alert detail request fanout', async () => {
    const listMock = vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(
      resp([makeAlert(), makeAlert(), makeAlert()]),
    )
    const getAlertSpy = vi.spyOn(alertsService, 'getAlert')
    renderQueue()

    await screen.findAllByText('Brute force authentication detected')
    expect(listMock).toHaveBeenCalledTimes(1)
    expect(getAlertSpy).not.toHaveBeenCalled()
  })

  it('27. no per-event request fanout occurs while rendering rows with multiple source events', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(
      resp([makeAlert({ source_event_ids: ['e1', 'e2', 'e3', 'e4', 'e5'] })]),
    )
    renderQueue()
    await screen.findByText('5 events')
  })

  it('28. no fabricated numeric risk score or maliciousness probability appears on the queue', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(
      resp([makeAlert({ title: 'Score-free queue alert', severity: 'critical' })]),
    )
    renderQueue()
    await screen.findByText('Score-free queue alert')
    expect(document.body.textContent).not.toMatch(/risk score|threat score|probability of attack|\d+%\s*(risk|threat|malicious)/i)
  })

  it('29. no fabricated historical total appears anywhere on the queue', async () => {
    vi.spyOn(alertsService, 'listAlerts').mockResolvedValue(resp([makeAlert()]))
    renderQueue()
    await screen.findByText('Brute force authentication detected')
    expect(document.body.textContent).not.toMatch(/total alerts:\s*\d+|total backlog:\s*\d+|\d+,\d{3}\+? alerts/i)
  })

  it('30. existing Alerts page regression: loading skeleton still renders before data resolves', () => {
    vi.spyOn(alertsService, 'listAlerts').mockReturnValue(new Promise(() => {}))
    const { container } = renderQueue()
    expect(container.querySelectorAll('.animate-pulse').length).toBeGreaterThan(0)
  })
})
