/**
 * Static MITRE ATT&CK mapping, copied verbatim from the real backend
 * registry (backend/app/mitre/registry.py) -- these are the only
 * rule_id -> technique mappings that actually exist in AMNIX today.
 * Nothing here is invented; if the backend registry gains a new
 * mapping, this is the one place to add it (deliberately not fetched
 * over the network -- the existing instruction is to reuse the
 * existing frontend/static mapping, not to duplicate it via a new
 * endpoint).
 *
 * Step 12E: `encoded_powershell_command` maps to TWO techniques in the
 * real backend registry (T1059.001 AND T1027.010 -- see
 * app.mitre.registry's own docstring for why both are genuinely
 * supported by that rule). The single-technique `MITRE_REGISTRY` map
 * below could only ever represent one, silently dropping T1059.001 for
 * that rule -- a real fidelity gap, fixed here by moving to a
 * multi-technique map and a plural lookup. `lookupMitreTechnique`
 * (singular) is kept unchanged for its existing callers (AlertRow,
 * AlertDetailPage, dashboard derive functions), returning the first
 * mapped technique.
 */

export interface MitreTechnique {
  techniqueId: string
  name: string
  tactic: string
}

export const MITRE_REGISTRY: Record<string, MitreTechnique[]> = {
  brute_force_authentication: [{ techniqueId: 'T1110', name: 'Brute Force', tactic: 'Credential Access' }],
  suspicious_powershell_execution: [
    { techniqueId: 'T1059.001', name: 'Command and Scripting Interpreter: PowerShell', tactic: 'Execution' },
  ],
  encoded_powershell_command: [
    { techniqueId: 'T1059.001', name: 'Command and Scripting Interpreter: PowerShell', tactic: 'Execution' },
    { techniqueId: 'T1027.010', name: 'Obfuscated Files or Information: Command Obfuscation', tactic: 'Stealth' },
  ],
}

export function getMitreTechniquesForRule(ruleId: string): MitreTechnique[] {
  return MITRE_REGISTRY[ruleId] ?? []
}

export function lookupMitreTechnique(ruleId: string): MitreTechnique | null {
  return getMitreTechniquesForRule(ruleId)[0] ?? null
}
