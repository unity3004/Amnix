import { describe, expect, it } from 'vitest'
import { deriveIncidentNarrative, deriveOpenItems, deriveTemporalSummary } from '@/features/cases/caseSummary'
import type { AlertRead, CaseNoteResponse, CaseRead } from '@/types/api'

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

describe('deriveTemporalSummary', () => {
  it('returns null/null for a case with no linked alerts', () => {
    expect(deriveTemporalSummary([])).toEqual({ earliest: null, latest: null })
  })

  it('returns the real min(first_seen)/max(last_seen) across all linked alerts', () => {
    const alerts = [
      makeAlert({ first_seen: '2026-01-02T00:00:00Z', last_seen: '2026-01-02T01:00:00Z' }),
      makeAlert({ first_seen: '2026-01-01T00:00:00Z', last_seen: '2026-01-03T00:00:00Z' }),
      makeAlert({ first_seen: '2026-01-05T00:00:00Z', last_seen: '2026-01-05T00:30:00Z' }),
    ]
    expect(deriveTemporalSummary(alerts)).toEqual({ earliest: '2026-01-01T00:00:00Z', latest: '2026-01-05T00:30:00Z' })
  })
})

describe('deriveIncidentNarrative', () => {
  it('states plainly when no alerts are linked -- never a fabricated conclusion', () => {
    const lines = deriveIncidentNarrative({ caseItem: makeCase(), alerts: [], notes: [] })
    expect(lines[0]).toBe('No alerts are currently linked to this case.')
    expect(lines.join(' ')).not.toMatch(/attacker|compromise|malicious|confirmed/i)
  })

  it('reports real alert/event/evidence counts, never inventing causality', () => {
    const alerts = [
      makeAlert({ id: 'a1', rule_id: 'brute_force_authentication', source_event_ids: ['e1', 'e2'], evidence: { failure_count: 5 } }),
      makeAlert({ id: 'a2', rule_id: 'suspicious_powershell_execution', source_event_ids: ['e2', 'e3'], evidence: {} }),
    ]
    const lines = deriveIncidentNarrative({ caseItem: makeCase(), alerts, notes: [] })
    expect(lines[0]).toContain('2 linked alerts')
    // Distinct union (e1, e2, e3) -- e2 shared by both alerts must not be double-counted.
    expect(lines[1]).toContain('3 distinct security events')
    expect(lines[2]).toContain('2 of 2 linked alerts')
    expect(lines.join(' ')).not.toMatch(/the attacker|system was compromised|threat is contained/i)
  })

  it('reports a real note count and case state, using the case\'s own real status/priority/owner', () => {
    const lines = deriveIncidentNarrative({
      caseItem: makeCase({ status: 'INVESTIGATING', priority: 'high', owner_id: 'user-9' }),
      alerts: [],
      notes: [makeNote(), makeNote()],
    })
    expect(lines.find((l) => l.includes('2 analyst notes'))).toBeDefined()
    expect(lines.at(-1)).toBe('The case is currently INVESTIGATING with high priority and an assigned owner.')
  })
})

describe('deriveOpenItems', () => {
  it('flags no linked alerts and no notes, and states the real OPEN status', () => {
    const items = deriveOpenItems({ caseItem: makeCase({ status: 'OPEN' }), alerts: [], notes: [] })
    expect(items).toContain('No alerts are linked to this case.')
    expect(items).toContain('Case investigation is still open.')
  })

  it('does not flag missing notes once real alerts exist but no notes are recorded', () => {
    const items = deriveOpenItems({ caseItem: makeCase(), alerts: [makeAlert()], notes: [] })
    expect(items).toContain('No analyst notes have been recorded.')
    expect(items).not.toContain('No alerts are linked to this case.')
  })

  it('never claims an attack is confirmed, a threat contained, or a system safe -- for any real status', () => {
    for (const status of ['OPEN', 'INVESTIGATING', 'RESOLVED', 'CLOSED'] as const) {
      const items = deriveOpenItems({ caseItem: makeCase({ status }), alerts: [makeAlert()], notes: [makeNote()] })
      expect(items.join(' ')).not.toMatch(/attack is confirmed|threat is contained|system is safe/i)
    }
  })

  it('maps each real Case status to its own distinct, honest workflow message', () => {
    expect(deriveOpenItems({ caseItem: makeCase({ status: 'RESOLVED' }), alerts: [], notes: [] })).toContain('Case is resolved but not yet closed.')
    expect(deriveOpenItems({ caseItem: makeCase({ status: 'CLOSED' }), alerts: [], notes: [] })).toContain('Case is closed.')
  })
})
