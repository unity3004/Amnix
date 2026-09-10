/** AMNIX brand mark — geometric, technical, minimal. A hexagonal
 * aperture built from three overlapping strokes suggesting layered
 * observation/detection (concentric "watching" rings), rendered purely
 * in CSS/SVG with no external asset. Deliberately small in scope, per
 * the brief's §11 instruction not to spend the step building a logo
 * system.
 */
export function Logo({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" fill="none" className={className} aria-hidden="true">
      <path
        d="M16 2 L28.4 9 V23 L16 30 L3.6 23 V9 Z"
        stroke="var(--color-accent)"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      <path
        d="M16 9 L22.2 12.5 V19.5 L16 23 L9.8 19.5 V12.5 Z"
        stroke="var(--color-accent-strong)"
        strokeWidth="1.4"
        strokeLinejoin="round"
        opacity="0.85"
      />
      <circle cx="16" cy="16" r="2.1" fill="var(--color-accent)" />
    </svg>
  )
}
