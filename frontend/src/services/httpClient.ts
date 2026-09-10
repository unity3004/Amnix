import type { ApiErrorBody } from '@/types/api'
import { getTokens, setTokens } from './tokenStore'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL as string

if (!API_BASE_URL) {
  // Fail loud in dev rather than silently calling a relative path that
  // would hit the Vite dev server itself and produce a confusing 404.
  // eslint-disable-next-line no-console
  console.error('VITE_API_BASE_URL is not configured — see .env.example')
}

/** Thrown for every non-2xx API response. Carries only what the backend
 * itself already decided is safe to expose (see AMNIX's Step 11O API
 * contract review — every error body is already a safe, generic
 * message) — this class never adds anything the backend didn't return.
 */
export class ApiError extends Error {
  readonly status: number
  readonly body: ApiErrorBody | null

  constructor(status: number, body: ApiErrorBody | null, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.body = body
  }
}

function detailToMessage(body: ApiErrorBody | null, fallback: string): string {
  if (!body) return fallback
  if (typeof body.detail === 'string') return body.detail
  if (Array.isArray(body.detail) && body.detail.length > 0) return body.detail[0].msg
  return fallback
}

interface RequestOptions {
  method?: 'GET' | 'POST' | 'PATCH' | 'DELETE'
  body?: unknown
  auth?: boolean
  /** Internal — prevents the refresh-token call itself from recursing. */
  skipAuthRetry?: boolean
}

let refreshInFlight: Promise<boolean> | null = null

async function attemptRefresh(): Promise<boolean> {
  const tokens = getTokens()
  if (!tokens) return false

  if (!refreshInFlight) {
    refreshInFlight = (async () => {
      try {
        const response = await rawRequest('/auth/refresh', {
          method: 'POST',
          body: { refresh_token: tokens.refreshToken },
          skipAuthRetry: true,
        })
        const data = (await response.json()) as { access_token: string; refresh_token: string }
        setTokens({ accessToken: data.access_token, refreshToken: data.refresh_token })
        return true
      } catch {
        setTokens(null)
        return false
      } finally {
        refreshInFlight = null
      }
    })()
  }
  return refreshInFlight
}

async function rawRequest(path: string, options: RequestOptions): Promise<Response> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (options.auth) {
    const tokens = getTokens()
    if (tokens) headers.Authorization = `Bearer ${tokens.accessToken}`
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: options.method ?? 'GET',
    headers,
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
  })

  if (!response.ok) {
    let body: ApiErrorBody | null = null
    try {
      body = (await response.json()) as ApiErrorBody
    } catch {
      body = null
    }
    throw new ApiError(response.status, body, detailToMessage(body, `Request failed (${response.status}).`))
  }

  return response
}

/** The one function every service module calls. Handles the
 * access-token-expired -> refresh-once -> retry-once flow transparently
 * for any `auth: true` request, matching TokenService's real rotation
 * contract (see backend/app/services/token_service.py) — a refresh
 * failure clears the session rather than looping.
 */
export async function apiRequest<T>(path: string, options: RequestOptions = {}): Promise<T> {
  try {
    const response = await rawRequest(path, options)
    if (response.status === 204) return undefined as T
    return (await response.json()) as T
  } catch (error) {
    const isAuthFailure = error instanceof ApiError && error.status === 401
    if (isAuthFailure && options.auth && !options.skipAuthRetry) {
      const refreshed = await attemptRefresh()
      if (refreshed) {
        const retryResponse = await rawRequest(path, options)
        if (retryResponse.status === 204) return undefined as T
        return (await retryResponse.json()) as T
      }
    }
    if (error instanceof ApiError) throw error
    // A genuinely unreachable backend / network failure — never surface
    // the raw TypeError/fetch message (it can vary by browser and is
    // not meaningful to an analyst); the UI layer decides how to
    // present this via ErrorState.
    throw new ApiError(0, null, 'Unable to reach the AMNIX backend.')
  }
}
