/**
 * In-memory-only token storage.
 *
 * WHY NOT localStorage/sessionStorage/cookies — decided by inspecting
 * the real backend contract (backend/app/api/dependencies.py,
 * backend/app/api/auth.py, backend/app/core/tokens.py), not invented:
 *
 *   - AMNIX authenticates exclusively via an `Authorization: Bearer
 *     <token>` header (fastapi.security.HTTPBearer). There is no
 *     cookie-reading code anywhere in the backend at all.
 *   - The backend's CORSMiddleware is configured with
 *     `allow_credentials=False` (see app/main.py) — a deliberate Step
 *     11L decision, since AMNIX never uses cookie-based auth. Even if
 *     the frontend tried to rely on cookies, the browser would not send
 *     them cross-origin under this configuration.
 *   - The refresh token (7-day lifetime by default, see
 *     Settings.refresh_token_expire_days) is a long-lived bearer-
 *     equivalent secret. Persisting it in localStorage/sessionStorage
 *     would leave it readable by any successful XSS for its entire
 *     lifetime.
 *
 * Given those two hard constraints (no cookie mechanism exists; the
 * long-lived refresh token should not sit in persistent browser
 * storage), both tokens are kept in a plain module-level variable only
 * — never written to Web Storage. The real, honest cost: a full page
 * reload loses the session and the user must log in again. That
 * trade-off is intentional and documented (see the Step 12A final
 * report's Known Limitations) rather than silently accepting a less
 * safe default for convenience.
 */

export interface TokenPair {
  accessToken: string
  refreshToken: string
}

let current: TokenPair | null = null
const listeners = new Set<(tokens: TokenPair | null) => void>()

export function getTokens(): TokenPair | null {
  return current
}

export function setTokens(tokens: TokenPair | null): void {
  current = tokens
  for (const listener of listeners) listener(current)
}

export function subscribeTokens(listener: (tokens: TokenPair | null) => void): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}
