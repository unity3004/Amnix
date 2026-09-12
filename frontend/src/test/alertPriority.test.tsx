import { describe, expect, it } from 'vitest'
import { compareAlertPriority, explainAlertPriority } from '@/features/alerts/priority'
import type { AlertRead } from '@/types/api'

function makeAlert(overrides: Partial<AlertRead> = {}): AlertRead {
  const now = new Date().toISOString()
  return {
    id: 'alert-1',
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

describe('compareAlertPriority', () => {
  it('orders critical before high before medium before low, using the real DetectionSeverity values', () => {
    const critical = makeAlert({ id: 'c', severity: 'critical' })
    const high = makeAlert({ id: 'h', severity: 'high' })
    const medium = makeAlert({ id: 'm', severity: 'medium' })
    const low = makeAlert({ id: 'l', severity: 'low' })

    const sorted = [low, medium, critical, high].sort(compareAlertPriority)
    expect(sorted.map((a) => a.id)).toEqual(['c', 'h', 'm', 'l'])
  })

  it('within the same severity, orders escalated, then new, then acknowledged, then investigating, then resolved', () => {
    const severity = 'high' as const
    const escalated = makeAlert({ id: 'escalated', severity, status: 'escalated' })
    const isNew = makeAlert({ id: 'new', severity, status: 'new' })
    const acknowledged = makeAlert({ id: 'acknowledged', severity, status: 'acknowledged' })
    const investigating = makeAlert({ id: 'investigating', severity, status: 'investigating' })
    const resolved = makeAlert({ id: 'resolved', severity, status: 'resolved' })

    const sorted = [resolved, investigating, acknowledged, isNew, escalated].sort(compareAlertPriority)
    expect(sorted.map((a) => a.id)).toEqual(['escalated', 'new', 'acknowledged', 'investigating', 'resolved'])
  })

  it('within the same severity and status, orders newer first_seen before older', () => {
    const older = makeAlert({ id: 'older', first_seen: new Date(Date.now() - 60 * 60 * 1000).toISOString() })
    const newer = makeAlert({ id: 'newer', first_seen: new Date().toISOString() })

    const sorted = [older, newer].sort(compareAlertPriority)
    expect(sorted.map((a) => a.id)).toEqual(['newer', 'older'])
  })

  it('severity always outranks status and recency, even for an old critical alert vs. a brand-new low one', () => {
    const oldCritical = makeAlert({
      id: 'old-critical',
      severity: 'critical',
      status: 'resolved',
      first_seen: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
    })
    const newLow = makeAlert({ id: 'new-low', severity: 'low', status: 'escalated', first_seen: new Date().toISOString() })

    const sorted = [newLow, oldCritical].sort(compareAlertPriority)
    expect(sorted.map((a) => a.id)).toEqual(['old-critical', 'new-low'])
  })
})

describe('explainAlertPriority', () => {
  it('produces a concise, human-readable explanation built only from severity/status/recency -- never a numeric score', () => {
    const alert = makeAlert({ severity: 'critical', status: 'escalated', first_seen: new Date().toISOString() })
    const explanation = explainAlertPriority(alert)

    expect(explanation).toMatch(/^Critical severity · Escalated · /)
    expect(explanation).not.toMatch(/%|score|\bprobability\b/i)
  })

  it('labels every real AlertStatus value with an honest, non-alarming phrase', () => {
    expect(explainAlertPriority(makeAlert({ status: 'new' }))).toContain('Needs triage')
    expect(explainAlertPriority(makeAlert({ status: 'acknowledged' }))).toContain('Acknowledged')
    expect(explainAlertPriority(makeAlert({ status: 'investigating' }))).toContain('Investigating')
    expect(explainAlertPriority(makeAlert({ status: 'resolved' }))).toContain('Resolved')
    expect(explainAlertPriority(makeAlert({ status: 'escalated' }))).toContain('Escalated')
  })
})
