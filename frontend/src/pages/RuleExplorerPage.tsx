import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { Search, ShieldCheck } from 'lucide-react'
import { PageHeader } from '@/components/layout/PageHeader'
import { Card } from '@/components/ui/Card'
import { Badge, SeverityBadge } from '@/components/ui/Badge'
import { EmptyState } from '@/components/ui/EmptyState'
import { DETECTION_RULES } from '@/features/rules/ruleRegistry'
import { getMitreTechniquesForRule } from '@/features/dashboard/mitreRegistry'
import { ALERT_SEVERITY_VALUES } from '@/features/alerts/types'

const selectClass =
  'h-8 rounded-md border border-border bg-surface px-2 text-xs text-fg-muted transition-colors duration-fast hover:border-border-strong focus:border-accent/50 focus:outline-none'

/** Detection Rule Explorer (Step 12H). AMNIX's detection rules are
 * static, application-controlled Python code with no backend API of
 * their own (see ruleRegistry.ts's own docstring for the full
 * discovery). Search and severity filtering below are entirely
 * client-side over that fixed, 3-entry static array -- there is no
 * server-side rule query to perform, and with only 3 rules that scope
 * is intentional, not a limitation to grow out of later without
 * reconsidering the approach.
 */
export function RuleExplorerPage() {
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('')

  const filteredRules = useMemo(() => {
    const query = search.trim().toLowerCase()
    return DETECTION_RULES.filter((rule) => {
      if (severity && rule.severity !== severity) return false
      if (!query) return true
      return (
        rule.ruleId.toLowerCase().includes(query) ||
        rule.name.toLowerCase().includes(query) ||
        rule.description.toLowerCase().includes(query)
      )
    })
  }, [search, severity])

  return (
    <div className="mx-auto max-w-[1400px] px-6 py-6">
      <PageHeader title="Detection Rules" description="Application-controlled detection logic AMNIX evaluates against ingested telemetry" />

      <Card className="overflow-hidden">
        <div className="flex flex-wrap items-center gap-2 border-b border-border px-5 py-3">
          <Search className="size-3.5 shrink-0 text-fg-subtle" strokeWidth={1.75} aria-hidden="true" />
          <label className="sr-only" htmlFor="rules-search">
            Search rules
          </label>
          <input
            id="rules-search"
            type="text"
            placeholder="Search by rule ID, name, or description"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="h-8 w-72 rounded-md border border-border bg-surface px-2 text-xs text-fg placeholder:text-fg-subtle transition-colors duration-fast hover:border-border-strong focus:border-accent/50 focus:outline-none"
          />
          <label className="sr-only" htmlFor="rules-severity-filter">
            Severity
          </label>
          <select id="rules-severity-filter" className={selectClass} value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">Severity: Any</option>
            {ALERT_SEVERITY_VALUES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <span className="text-[11px] text-fg-subtle">
            {filteredRules.length} of {DETECTION_RULES.length} rule{DETECTION_RULES.length === 1 ? '' : 's'}
          </span>
        </div>

        {filteredRules.length === 0 ? (
          <EmptyState icon={ShieldCheck} title="No rules match" description="No detection rules match the current search/severity filter." />
        ) : (
          <ul className="divide-y divide-border-faint">
            {filteredRules.map((rule) => {
              const techniques = getMitreTechniquesForRule(rule.ruleId)
              return (
                <li key={rule.ruleId}>
                  <Link
                    to={`/rules/${rule.ruleId}`}
                    className="flex flex-col gap-2 px-5 py-4 transition-colors duration-fast hover:bg-surface-hover sm:flex-row sm:items-start sm:gap-4"
                  >
                    <div className="flex items-center gap-3 sm:w-56 sm:shrink-0">
                      <SeverityBadge severity={rule.severity} />
                      <div className="min-w-0">
                        <p className="truncate text-sm font-medium text-fg">{rule.name}</p>
                        <p className="truncate font-mono text-[11px] text-fg-subtle">{rule.ruleId}</p>
                      </div>
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="text-xs text-fg-muted">{rule.description}</p>
                      <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                        {rule.eventTypes.map((eventType) => (
                          <Badge key={eventType} tone="neutral">
                            {eventType}
                          </Badge>
                        ))}
                        {techniques.map((t) => (
                          <Badge key={t.techniqueId} tone="accent">
                            {t.techniqueId}
                          </Badge>
                        ))}
                      </div>
                    </div>
                    <Badge tone="success" className="shrink-0">
                      Active · Application-controlled
                    </Badge>
                  </Link>
                </li>
              )
            })}
          </ul>
        )}
      </Card>
    </div>
  )
}
