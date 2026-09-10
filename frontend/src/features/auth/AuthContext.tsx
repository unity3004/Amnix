import { createContext, useCallback, useEffect, useState, type ReactNode } from 'react'
import type { UserRead } from '@/types/api'
import * as authService from '@/services/authService'
import { getTokens, setTokens, subscribeTokens } from '@/services/tokenStore'
import { ApiError } from '@/services/httpClient'

export interface AuthContextValue {
  user: UserRead | null
  isAuthenticated: boolean
  isAuthenticating: boolean
  login: (email: string, password: string) => Promise<void>
  logout: () => void
}

export const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserRead | null>(null)
  const [isAuthenticated, setIsAuthenticated] = useState(() => getTokens() !== null)
  const [isAuthenticating, setIsAuthenticating] = useState(false)

  useEffect(() => {
    return subscribeTokens((tokens) => {
      setIsAuthenticated(tokens !== null)
      if (tokens === null) setUser(null)
    })
  }, [])

  const login = useCallback(async (email: string, password: string) => {
    setIsAuthenticating(true)
    try {
      const result = await authService.login({ email, password })
      setTokens({ accessToken: result.access_token, refreshToken: result.refresh_token })
      setUser(result.user)
    } catch (error) {
      if (error instanceof ApiError) throw error
      throw new ApiError(0, null, 'Unable to reach the AMNIX backend.')
    } finally {
      setIsAuthenticating(false)
    }
  }, [])

  const logout = useCallback(() => {
    setTokens(null)
    setUser(null)
  }, [])

  return <AuthContext value={{ user, isAuthenticated, isAuthenticating, login, logout }}>{children}</AuthContext>
}
