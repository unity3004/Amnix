import { describe, expect, it } from 'vitest'
import {
  buildIncidentTimeline,
  classifyEventType,
  deriveDetectionSnapshot,
  deriveIncidentHealth,
  deriveInvestigationProgress,
  deriveParticipatingRules,
  deriveRecommendations,
  groupAlertsBySeverity,
  groupAuditsByDay,
  groupEvidenceByType,
  groupMitreByTactic,
} from '@/features/console/logic'
import type { AlertRead, CaseAuditResponse, CaseNoteResponse, CaseRead, CopilotAuditResponse, TimelineEntry } from '@/types/api'

function makeAlert(overrides: Partial<AlertRead> = {}): AlertRead {
  const now = new Date().toISOString()
  return {
    id: `alert-${Math.random().toString(36).slice(2)}`,
    rule_id: 'brute_force_authentication',
    title: 'Test alert',
    description: 'd',
    severity: 'medium',
    confidence: 'medium',
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

function makeCase(overrides: Partial<CaseRead> = {}): CaseRead {
  const now = new Date().toISOString()
  return {
    id: 'case-1',
    case_number: 1,
    title: 'Test case',
    description: 'd',
    status: 'OPEN',
    priority: 'medium',
    severity: null,
    created_at: now,
    updated_at: now,
    created_by: 'user-1',
    owner_id: null,
    closed_at: null,
    closure_reason: null,
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

function makeTimelineEntry(overrides: Partial<TimelineEntry> = {}): TimelineEntry {
  return {
    event_id: `evt-${Math.random().toString(36).slice(2)}`,
    event_timestamp: new Date().toISOString(),
    event_type: 'authentication_failure',
    source: 'test',
    hostname: null,
    username: null,
    source_ip: null,
    destination_ip: null,
    process_name: null,
    command_line: null,
    ...overrides,
  }
}

function makeCopilotAudit(overrides: Partial<CopilotAuditResponse> = {}): CopilotAuditResponse {
  return {
    id: `ca-${Math.random().toString(36).slice(2)}`,
    alert_id: 'alert-1',
    request_type: 'ask',
    provider_name: 'mock',
    model_name: 'mock-model',
    outcome: 'success',
    validation_status: 'passed',
    http_status: 200,
    question_fingerprint: 'fp',
    question_length: 10,
    history_turn_count: null,
    duration_ms: 100,
    created_at: new Date().toISOString(),
    ...overrides,
  }
}

describe('classifyEventType (no rule-specific logic)', () => {
  it('classifies by event_type substring only', () => {
    expect(classifyEventType('authentication_failure')).toBe('Authentication')
    expect(classifyEventType('powershell_execution')).toBe('PowerShell')
    expect(classifyEventType('process_creation')).toBe('Process Creation')
    expect(classifyEventType('network_connection')).toBe('Network')
    expect(classifyEventType('registry_modification')).toBe('Other')
  })
})

describe('groupEvidenceByType', () => {
  it('groups real timeline entries, never inventing a group with no data', () => {
    const timeline = [makeTimelineEntry({ event_type: 'authentication_failure' }), makeTimelineEntry({ event_type: 'process_creation' })]
    const groups = groupEvidenceByType(timeline)
    expect(groups.get('Authentication')).toHaveLength(1)
    expect(groups.get('Process Creation')).toHaveLength(1)
    expect(groups.has('Network')).toBe(false)
  })
})

describe('deriveDetectionSnapshot', () => {
  it('returns all-zero/null for no linked alerts, never a fabricated non-zero value', () => {
    expect(deriveDetectionSnapshot([])).toEqual({ linkedAlertCount: 0, highestSeverity: null, distinctRuleCount: 0, distinctEventCount: 0 })
  })

  it('derives real counts from real alerts', () => {
    const alerts = [
      makeAlert({ severity: 'low', rule_id: 'a', source_event_ids: ['e1'] }),
      makeAlert({ severity: 'critical', rule_id: 'b', source_event_ids: ['e2', 'e1'] }),
    ]
    const snapshot = deriveDetectionSnapshot(alerts)
    expect(snapshot.linkedAlertCount).toBe(2)
    expect(snapshot.highestSeverity).toBe('critical')
    expect(snapshot.distinctRuleCount).toBe(2)
    expect(snapshot.distinctEventCount).toBe(2) // e1 deduplicated
  })
})

describe('groupAlertsBySeverity', () => {
  it('places each alert in its own real severity bucket', () => {
    const alerts = [makeAlert({ severity: 'critical' }), makeAlert({ severity: 'low' }), makeAlert({ severity: 'critical' })]
    const groups = groupAlertsBySeverity(alerts)
    expect(groups.critical).toHaveLength(2)
    expect(groups.low).toHaveLength(1)
    expect(groups.high).toHaveLength(0)
    expect(groups.medium).toHaveLength(0)
  })
})

describe('groupMitreByTactic', () => {
  it('deduplicates techniques and groups by real tactic from the registry', () => {
    const alerts = [makeAlert({ rule_id: 'encoded_powershell_command' }), makeAlert({ rule_id: 'encoded_powershell_command' })]
    const byTactic = groupMitreByTactic(alerts)
    // encoded_powershell_command maps to T1059.001 (Execution) and T1027.010 (Stealth)
    expect(byTactic.get('Execution')?.map((t) => t.techniqueId)).toEqual(['T1059.001'])
    expect(byTactic.get('Stealth')?.map((t) => t.techniqueId)).toEqual(['T1027.010'])
  })

  it('returns an empty map for an unrecognized rule -- never a fabricated technique', () => {
    const byTactic = groupMitreByTactic([makeAlert({ rule_id: 'totally_unknown_rule' })])
    expect(byTactic.size).toBe(0)
  })
})

describe('deriveParticipatingRules', () => {
  it('groups real alerts by rule_id and detects observed evidence honestly', () => {
    const rules = deriveParticipatingRules([
      makeAlert({ rule_id: 'a', evidence: { x: 1 } }),
      makeAlert({ rule_id: 'a', evidence: {} }),
      makeAlert({ rule_id: 'b', evidence: {} }),
    ])
    const ruleA = rules.find((r) => r.ruleId === 'a')
    const ruleB = rules.find((r) => r.ruleId === 'b')
    expect(ruleA?.alerts).toHaveLength(2)
    expect(ruleA?.hasObservedEvidence).toBe(true)
    expect(ruleB?.hasObservedEvidence).toBe(false)
  })
})

describe('deriveIncidentHealth', () => {
  it('counts by real AlertStatus values, never a score/percentage', () => {
    const alerts = [
      makeAlert({ status: 'new' }),
      makeAlert({ status: 'acknowledged' }),
      makeAlert({ status: 'investigating' }),
      makeAlert({ status: 'resolved' }),
      makeAlert({ status: 'escalated' }),
    ]
    const health = deriveIncidentHealth({ alerts, notes: [makeNote()], focusedAlertCopilotAudits: [makeCopilotAudit()], timelineEventCount: 3 })
    expect(health.openAlerts).toBe(2) // new + acknowledged
    expect(health.investigatingAlerts).toBe(1)
    expect(health.resolvedAlerts).toBe(1)
    expect(health.escalatedAlerts).toBe(1)
    expect(health.notesAdded).toBe(1)
    expect(health.focusedAlertCopilotConversations).toBe(1)
    expect(health.timelineEvents).toBe(3)
    expect(health).not.toHaveProperty('score')
    expect(health).not.toHaveProperty('percentage')
  })

  it('reports zero Copilot conversations when no alert is focused, never assuming data exists', () => {
    const health = deriveIncidentHealth({ alerts: [], notes: [], focusedAlertCopilotAudits: undefined, timelineEventCount: 0 })
    expect(health.focusedAlertCopilotConversations).toBe(0)
  })
})

describe('deriveInvestigationProgress', () => {
  it('marks items complete only when real data exists', () => {
    const items = deriveInvestigationProgress({
      caseItem: makeCase({ owner_id: null }),
      alerts: [],
      notes: [],
      audits: [],
      focusedAlertTimeline: undefined,
      focusedAlertCopilotAudits: undefined,
    })
    for (const item of items) expect(item.complete).toBe(false)
  })

  it('marks items complete when the corresponding real data is present', () => {
    const items = deriveInvestigationProgress({
      caseItem: makeCase({ owner_id: 'user-1' }),
      alerts: [makeAlert({ rule_id: 'brute_force_authentication', source_event_ids: ['e1'] })],
      notes: [makeNote()],
      audits: [makeAudit()],
      focusedAlertTimeline: [makeTimelineEntry()],
      focusedAlertCopilotAudits: [makeCopilotAudit()],
    })
    const byKey = Object.fromEntries(items.map((i) => [i.key, i.complete]))
    expect(byKey['detection-linked']).toBe(true)
    expect(byKey['evidence-available']).toBe(true)
    expect(byKey['timeline-available']).toBe(true)
    expect(byKey['mitre-mapped']).toBe(true)
    expect(byKey['analyst-assigned']).toBe(true)
    expect(byKey['copilot-consulted']).toBe(true)
    expect(byKey['notes-recorded']).toBe(true)
    expect(byKey['audit-history-present']).toBe(true)
  })

  it('only shows the closure-reason item when the case is actually CLOSED', () => {
    const openItems = deriveInvestigationProgress({
      caseItem: makeCase({ status: 'OPEN' }),
      alerts: [],
      notes: [],
      audits: [],
      focusedAlertTimeline: undefined,
      focusedAlertCopilotAudits: undefined,
    })
    expect(openItems.some((i) => i.key === 'closure-reason-present')).toBe(false)

    const closedItems = deriveInvestigationProgress({
      caseItem: makeCase({ status: 'CLOSED', closure_reason: 'Confirmed benign.' }),
      alerts: [],
      notes: [],
      audits: [],
      focusedAlertTimeline: undefined,
      focusedAlertCopilotAudits: undefined,
    })
    const closureItem = closedItems.find((i) => i.key === 'closure-reason-present')
    expect(closureItem?.complete).toBe(true)
  })
})

describe('deriveRecommendations (deterministic only)', () => {
  it('recommends nothing for a fully-staffed, closed-out case with no critical unresolved alerts', () => {
    const recs = deriveRecommendations({
      caseItem: makeCase({ owner_id: 'user-1', status: 'INVESTIGATING' }),
      alerts: [makeAlert({ severity: 'low', status: 'resolved' })],
      notes: [makeNote()],
    })
    expect(recs.find((r) => r.key === 'no-owner')).toBeUndefined()
    expect(recs.find((r) => r.key === 'no-notes')).toBeUndefined()
    expect(recs.find((r) => r.key === 'still-open')).toBeUndefined()
    expect(recs.find((r) => r.key === 'critical-unresolved')).toBeUndefined()
  })

  it('flags every real gap with a real navigation target', () => {
    const criticalAlert = makeAlert({ id: 'alert-crit', severity: 'critical', status: 'new', title: 'Critical thing' })
    const recs = deriveRecommendations({
      caseItem: makeCase({ id: 'case-9', owner_id: null, status: 'OPEN' }),
      alerts: [criticalAlert],
      notes: [],
    })
    expect(recs.find((r) => r.key === 'no-owner')?.href).toBe('/cases/case-9')
    expect(recs.find((r) => r.key === 'no-notes')?.scrollToId).toBe('console-notes')
    expect(recs.find((r) => r.key === 'still-open')?.href).toBe('/cases/case-9')
    expect(recs.find((r) => r.key === 'critical-unresolved')?.href).toBe('/alerts/alert-crit')
  })
})

describe('groupAuditsByDay', () => {
  it('groups by real created_at relative to an injected "now"', () => {
    const now = new Date('2026-09-14T12:00:00Z')
    const today = makeAudit({ created_at: '2026-09-14T08:00:00Z' })
    const yesterday = makeAudit({ created_at: '2026-09-13T08:00:00Z' })
    const older = makeAudit({ created_at: '2026-09-01T08:00:00Z' })
    const groups = groupAuditsByDay([today, yesterday, older], now)
    expect(groups.map((g) => g.label)).toEqual(['Today', 'Yesterday', 'Older'])
    expect(groups[0].items).toEqual([today])
    expect(groups[1].items).toEqual([yesterday])
    expect(groups[2].items).toEqual([older])
  })

  it('omits an empty group entirely rather than showing an empty section', () => {
    const now = new Date('2026-09-14T12:00:00Z')
    const groups = groupAuditsByDay([makeAudit({ created_at: '2026-09-14T08:00:00Z' })], now)
    expect(groups).toHaveLength(1)
    expect(groups[0].label).toBe('Today')
  })
})

describe('buildIncidentTimeline (the centerpiece merge -- no fake entries)', () => {
  it('merges audits and notes with correct categories, sorted newest-first', () => {
    const older = makeAudit({ id: 'a1', action: 'CASE_CREATED', created_at: '2026-01-01T00:00:00Z' })
    const middle = makeAudit({ id: 'a2', action: 'CASE_STATUS_CHANGED', created_at: '2026-01-02T00:00:00Z' })
    const newest = makeNote({ id: 'n1', created_at: '2026-01-03T00:00:00Z', body: 'Escalated.' })

    const timeline = buildIncidentTimeline({ audits: [older, middle], notes: [newest] })

    expect(timeline.map((e) => e.id)).toEqual(['note-n1', 'audit-a2', 'audit-a1'])
    expect(timeline[0].category).toBe('Notes')
    expect(timeline[0].actor).toBe('user-1')
    expect(timeline[1].category).toBe('Status') // CASE_STATUS_CHANGED
    expect(timeline[2].category).toBe('Audit') // CASE_CREATED
  })

  it('never fabricates an "Investigation Started" entry -- investigation entries only appear from real focusedAlertTimeline data', () => {
    const timeline = buildIncidentTimeline({ audits: [], notes: [] })
    expect(timeline).toHaveLength(0)

    const withInvestigation = buildIncidentTimeline({
      audits: [],
      notes: [],
      focusedAlertTimeline: [makeTimelineEntry({ event_id: 'evt-1', event_type: 'authentication_failure' })],
    })
    expect(withInvestigation).toHaveLength(1)
    expect(withInvestigation[0].category).toBe('Investigation')
    expect(withInvestigation[0].title).toBe('authentication_failure')
    expect(withInvestigation[0].actor).toBeNull() // system-observed telemetry has no actor
  })

  it('never shows a fabricated Copilot verdict -- only real audit metadata', () => {
    const audit = makeCopilotAudit({ request_type: 'ask', outcome: 'success', provider_name: 'mock', model_name: 'mock-model' })
    const timeline = buildIncidentTimeline({ audits: [], notes: [], focusedAlertCopilotAudits: [audit] })
    expect(timeline[0].category).toBe('Copilot')
    expect(timeline[0].title).toBe('Copilot asked')
    expect(timeline[0].description).toContain('success')
    expect(timeline[0].actor).toBeNull() // CopilotAuditResponse has no actor field
    expect(timeline[0].description).not.toMatch(/verdict|confidence/i)
  })

  it('maps CASE_OWNER_CHANGED to the Owner category and CASE_ALERT_LINKED to the Alerts category', () => {
    const timeline = buildIncidentTimeline({
      audits: [makeAudit({ id: 'a1', action: 'CASE_OWNER_CHANGED' }), makeAudit({ id: 'a2', action: 'CASE_ALERT_LINKED' })],
      notes: [],
    })
    expect(timeline.find((e) => e.id === 'audit-a1')?.category).toBe('Owner')
    expect(timeline.find((e) => e.id === 'audit-a2')?.category).toBe('Alerts')
  })
})
