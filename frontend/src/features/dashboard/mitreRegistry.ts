/**
 * Static MITRE ATT&CK mapping, copied verbatim from the real backend
 * registry (backend/app/mitre/registry.py) during Step 12A/12C
 * discovery -- these are the only three rule_id -> technique mappings
 * that actually exist in AMNIX today. Nothing here is invented; if the
 * backend registry gains a new mapping, this is the one place to add
 * it (deliberately not fetched over the network -- the brief's own
 * instruction is to reuse the existing frontend/static mapping, not to
 * duplicate it via a new endpoint).
 */

export interface MitreTechnique {
  techniqueId: string
  name: string
  tactic: string
}

export const MITRE_REGISTRY: Record<string, MitreTechnique> = {
  brute_force_authentication: { techniqueId: 'T1110', name: 'Brute Force', tactic: 'Credential Access' },
  suspicious_powershell_execution: {
    techniqueId: 'T1059.001',
    name: 'Command and Scripting Interpreter: PowerShell',
    tactic: 'Execution',
  },
  encoded_powershell_command: {
    techniqueId: 'T1027.010',
    name: 'Obfuscated Files or Information: Command Obfuscation',
    tactic: 'Stealth',
  },
}

export function lookupMitreTechnique(ruleId: string): MitreTechnique | null {
  return MITRE_REGISTRY[ruleId] ?? null
}
