import { describe, expect, it, vi, afterEach } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { IncidentConsolePage } from '@/pages/IncidentConsolePage'
import { renderWithProviders } from './utils'
import * as casesService from '@/services/casesService'
import * as alertsService from '@/services/alertsService'
import * as healthService from '@/services/healthService'
import type {
  AlertListResponse,
  AlertRead,
  CaseAuditListResponse,
  CaseAuditResponse,
  CaseNoteListResponse,
  CaseNoteResponse,
  CaseRead,
  CopilotAuditListResponse,
  InvestigationContext,
} from '@/types/api'

afterEach(() => vi.restoreAllMocks())

function makeCase(overrides: Partial<CaseRead> = {}): CaseRead {
  const now = new Date().toISOString()
  return {
    id: 'case-1',
    case_number: 42,
    title: 'Coordinated credential abuse',
    description: 'd',
    status: 'INVESTIGATING',
    priority: 'high',
    severity: 'critical',
    created_at: now,
    updated_at: now,
    created_by: 'user-1',
    owner_id: 'analyst-1',
    closed_at: null,
    closure_reason: null,
    ...overrides,
  }
}

function makeAlert(overrides: Partial<AlertRead> = {}): AlertRead {
  const now = new Date().toISOString()
  return {
    id: `alert-${Math.random().toString(36).slice(2)}`,
    rule_id: 'brute_force_authentication',
    title: 'Brute force detected',
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
    source_event_ids: [],
    ...overrides,
  }
}

function makeAudit(overrides: Partial<CaseAuditResponse> = {}): CaseAuditResponse {
  return {
    id: `audit-${Math.random().toString(36).slice(2)}`,
    case_id: 'case-1',
    actor_user_id: 'user-1',
    action: 'CASE_CREATED',
    related_alert_id: null,
    previous_value: null,
    new_value: null,
    created_at: new Date().toISOString(),
    ...overrides,
  }
}

function makeNote(overrides: Partial<CaseNoteResponse> = {}): CaseNoteResponse {
  return {
    id: `note-${Math.random().toString(36).slice(2)}`,
    case_id: 'case-1',
    author_id: 'user-1',
    body: 'A note.',
    created_at: new Date().toISOString(),
    ...overrides,
  }
}

function alertsResp(items: AlertRead[]): AlertListResponse {
  return { items, limit: 50, offset: 0 }
}
function auditResp(items: CaseAuditResponse[]): CaseAuditListResponse {
  return { items, limit: 200, offset: 0 }
}
function notesResp(items: CaseNoteResponse[]): CaseNoteListResponse {
  return { items, limit: 200, offset: 0 }
}
function copilotResp(): CopilotAuditListResponse {
  return { items: [], limit: 50, offset: 0 }
}
function makeInvestigation(overrides: Partial<InvestigationContext> = {}): InvestigationContext {
  const now = new Date().toISOString()
  return {
    alert: makeAlert(),
    timeline: [],
    entities: { hostnames: [], usernames: [], source_ips: [], destination_ips: [], process_names: [], file_hashes: [] },
    summary: { text: '', event_count: 0, unique_host_count: 0, unique_user_count: 0, timespan_seconds: null, first_event_at: null, last_event_at: null },
    generated_at: now,
    ...overrides,
  }
}

/** Base mocks every test needs -- keeps individual tests focused on
 * what they're actually verifying.
 */
function mockConsoleFixtures(overrides: {
  caseItem?: CaseRead
  alerts?: AlertRead[]
  notes?: CaseNoteResponse[]
  audits?: CaseAuditResponse[]
  investigation?: InvestigationContext
} = {}) {
  const caseItem = overrides.caseItem ?? makeCase()
  vi.spyOn(casesService, 'getCase').mockResolvedValue(caseItem)
  vi.spyOn(casesService, 'listCaseAlerts').mockResolvedValue(alertsResp(overrides.alerts ?? []))
  vi.spyOn(casesService, 'listCaseNotes').mockResolvedValue(notesResp(overrides.notes ?? []))
  vi.spyOn(casesService, 'listCaseAudit').mockResolvedValue(auditResp(overrides.audits ?? [makeAudit()]))
  vi.spyOn(alertsService, 'getAlertInvestigation').mockResolvedValue(overrides.investigation ?? makeInvestigation())
  vi.spyOn(alertsService, 'getCopilotAudits').mockResolvedValue(copilotResp())
  vi.spyOn(healthService, 'getHealth').mockResolvedValue({ status: 'ok', service: 'amnix' })
  return caseItem
}

function renderConsole(route = '/cases/case-1/console') {
  return renderWithProviders(
    <Routes>
      <Route path="/cases/:caseId/console" element={<IncidentConsolePage />} />
      <Route path="/cases/:caseId" element={<div>CASE DETAIL MARKER</div>} />
      <Route path="/alerts/:alertId" element={<div>ALERT DETAIL MARKER</div>} />
      <Route path="/alerts/:alertId/investigation" element={<div>INVESTIGATION MARKER</div>} />
      <Route path="/rules/:ruleId" element={<div>RULE DETAIL MARKER</div>} />
      <Route path="/operations" element={<div>DETECTION OPERATIONS MARKER</div>} />
      <Route path="/detection-health" element={<div>DETECTION HEALTH MARKER</div>} />
    </Routes>,
    { route },
  )
}

describe('IncidentConsolePage: Incident Summary', () => {
  it('renders REAL case header data', async () => {
    mockConsoleFixtures()
    renderConsole()

    expect(await screen.findByText('Coordinated credential abuse')).toBeInTheDocument()
    expect(screen.getByText('Case #42')).toBeInTheDocument()
    expect(screen.getAllByText('INVESTIGATING').length).toBeGreaterThan(0)
    expect(screen.getAllByText('high priority').length).toBeGreaterThan(0)
  })
})

describe('IncidentConsolePage: Timeline merge and filters', () => {
  it('merges real audit and note entries into the timeline', async () => {
    mockConsoleFixtures({
      audits: [makeAudit({ action: 'CASE_CREATED' })],
      notes: [makeNote({ body: 'Escalated to on-call.' })],
    })
    renderConsole()

    await screen.findByText('Coordinated credential abuse')
    // "Case created"/"Note added" each appear in both the Timeline panel
    // and their own dedicated panel (Audit Trail / Notes) -- both real,
    // both expected.
    expect((await screen.findAllByText('Case created')).length).toBeGreaterThan(0)
    expect(screen.getAllByText('Note added').length).toBeGreaterThan(0)
  })

  it('filters the timeline client-side with zero additional requests', async () => {
    mockConsoleFixtures({
      audits: [makeAudit({ action: 'CASE_CREATED' })],
      notes: [makeNote({ body: 'Escalated to on-call.' })],
    })
    const auditSpy = vi.spyOn(casesService, 'listCaseAudit')
    renderConsole()

    await screen.findByText('Note added')
    const callsBeforeFilter = auditSpy.mock.calls.length
    const timelinePanel = document.getElementById('console-timeline') as HTMLElement

    await userEvent.setup().click(within(timelinePanel).getByRole('button', { name: /^notes\s*1$/i }))

    expect(within(timelinePanel).getByText('Note added')).toBeInTheDocument()
    expect(within(timelinePanel).queryByText('Case created')).not.toBeInTheDocument()
    expect(auditSpy.mock.calls.length).toBe(callsBeforeFilter)
  })
})

describe('IncidentConsolePage: Evidence grouping', () => {
  it('groups the focused alert\'s real telemetry by event_type', async () => {
    const alert = makeAlert({ id: 'alert-focus' })
    mockConsoleFixtures({
      alerts: [alert],
      investigation: makeInvestigation({
        alert,
        timeline: [
          { event_id: 'e1', event_timestamp: new Date().toISOString(), event_type: 'authentication_failure', source: 's', hostname: 'host-1', username: null, source_ip: null, destination_ip: null, process_name: null, command_line: null },
          { event_id: 'e2', event_timestamp: new Date().toISOString(), event_type: 'process_creation', source: 's', hostname: null, username: null, source_ip: null, destination_ip: null, process_name: 'powershell.exe', command_line: null },
        ],
      }),
    })
    renderConsole()

    expect(await screen.findByText('Authentication')).toBeInTheDocument()
    expect(screen.getByText('Process Creation')).toBeInTheDocument()
    expect(screen.queryByText('Network')).not.toBeInTheDocument()
  })
})

describe('IncidentConsolePage: Alert grouping', () => {
  it('groups linked alerts by real severity', async () => {
    mockConsoleFixtures({
      alerts: [makeAlert({ title: 'Critical one', severity: 'critical' }), makeAlert({ title: 'Low one', severity: 'low' })],
    })
    renderConsole()

    expect(await screen.findByText('Critical one')).toBeInTheDocument()
    expect(screen.getByText('Low one')).toBeInTheDocument()
    // Both the "critical" and "low" groups have exactly one alert each.
    expect(screen.getAllByText('1 alert').length).toBe(2)
  })
})

describe('IncidentConsolePage: Investigation Progress', () => {
  it('reflects real case/alert state, never a fabricated percentage', async () => {
    mockConsoleFixtures({ caseItem: makeCase({ owner_id: null }), alerts: [] })
    renderConsole()

    await screen.findByText('Coordinated credential abuse')
    expect(screen.getByText('Investigation Progress')).toBeInTheDocument()
    expect(screen.getByText('Detection linked')).toBeInTheDocument()
    expect(screen.getByText('Analyst assigned')).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/\d+%\s*complete/i)
  })
})

describe('IncidentConsolePage: Recommendations', () => {
  it('recommends a real, navigable action when the case has no owner', async () => {
    mockConsoleFixtures({ caseItem: makeCase({ id: 'case-1', owner_id: null, status: 'OPEN' }), notes: [makeNote()] })
    renderConsole()

    const link = await screen.findByRole('link', { name: /No owner assigned to this case\./ })
    expect(link).toHaveAttribute('href', '/cases/case-1')
    await userEvent.setup().click(link)
    expect(await screen.findByText('CASE DETAIL MARKER')).toBeInTheDocument()
  })

  it('shows no fabricated recommendation when the case is fully staffed and healthy', async () => {
    mockConsoleFixtures({
      caseItem: makeCase({ owner_id: 'analyst-1', status: 'INVESTIGATING' }),
      notes: [makeNote()],
      alerts: [makeAlert({ severity: 'low', status: 'resolved' })],
    })
    renderConsole()

    await screen.findByText('Coordinated credential abuse')
    expect(await screen.findByText('No outstanding recommendations.')).toBeInTheDocument()
  })
})

describe('IncidentConsolePage: Notes update the timeline', () => {
  it('adding a note refreshes both the Notes panel and the merged timeline', async () => {
    const caseItem = mockConsoleFixtures({ notes: [] })
    const newNote = makeNote({ body: 'Escalated now.' })
    // After the mutation succeeds, the shared ['case-notes', caseId]
    // query (used by BOTH CaseNotesPanel and useIncidentConsole's own
    // timeline merge) is invalidated and refetched -- the second call
    // returns the real new note, proving the cache is genuinely shared,
    // not two independent copies of the same data.
    vi.spyOn(casesService, 'listCaseNotes').mockResolvedValueOnce(notesResp([])).mockResolvedValue(notesResp([newNote]))
    const createMock = vi.spyOn(casesService, 'createCaseNote').mockResolvedValue(newNote)
    renderConsole()

    await screen.findByText('No notes have been added to this case yet.')
    const user = userEvent.setup()
    await user.type(screen.getByLabelText('Add a Note'), 'Escalated now.')
    await user.click(screen.getByRole('button', { name: /add note/i }))

    await waitFor(() => expect(createMock).toHaveBeenCalledWith(caseItem.id, 'Escalated now.'))
    await waitFor(() => expect(screen.getAllByText('Note added').length).toBeGreaterThan(0))
  })
})

describe('IncidentConsolePage: manual refresh', () => {
  it('re-fetches case, alerts, notes, and audit on demand', async () => {
    const getCaseSpy = vi.spyOn(casesService, 'getCase').mockResolvedValue(makeCase())
    vi.spyOn(casesService, 'listCaseAlerts').mockResolvedValue(alertsResp([]))
    const notesSpy = vi.spyOn(casesService, 'listCaseNotes').mockResolvedValue(notesResp([]))
    const auditSpy = vi.spyOn(casesService, 'listCaseAudit').mockResolvedValue(auditResp([makeAudit()]))
    vi.spyOn(healthService, 'getHealth').mockResolvedValue({ status: 'ok', service: 'amnix' })
    renderConsole()

    await screen.findByText('Coordinated credential abuse')
    const callsBefore = { case: getCaseSpy.mock.calls.length, notes: notesSpy.mock.calls.length, audit: auditSpy.mock.calls.length }

    await userEvent.setup().click(screen.getByRole('button', { name: /refresh dashboard data/i }))

    await waitFor(() => {
      expect(getCaseSpy.mock.calls.length).toBeGreaterThan(callsBefore.case)
      expect(notesSpy.mock.calls.length).toBeGreaterThan(callsBefore.notes)
      expect(auditSpy.mock.calls.length).toBeGreaterThan(callsBefore.audit)
    })
  })
})

describe('IncidentConsolePage: no N+1', () => {
  it('fetches investigation for the focused alert exactly once, never looped across every linked alert', async () => {
    const alerts = [
      makeAlert({ id: 'a1', severity: 'low' }),
      makeAlert({ id: 'a2', severity: 'critical' }),
      makeAlert({ id: 'a3', severity: 'medium' }),
    ]
    mockConsoleFixtures({ alerts })
    const investigationSpy = vi.spyOn(alertsService, 'getAlertInvestigation').mockResolvedValue(makeInvestigation())
    renderConsole()

    await screen.findByText('Coordinated credential abuse')
    await waitFor(() => expect(investigationSpy).toHaveBeenCalledTimes(1))
    // Focuses the highest-priority (critical) alert, not the first in the array.
    expect(investigationSpy).toHaveBeenCalledWith('a2')
  })
})
