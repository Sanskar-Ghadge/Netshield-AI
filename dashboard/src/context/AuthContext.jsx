/**
 * NetShield AI — Authentication Context.
 *
 * Provides global state for user authentication, login/signup handlers,
 * session persistence via localStorage, and API Key management.
 *
 * @module context/AuthContext
 */

import { createContext, useContext, useState, useEffect } from 'react'
import { loginUser, registerUser, fetchCurrentUser, regenerateApiKey } from '../api/client.js'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [token, setToken] = useState(() => {
    try {
      // Proactively clear any stale legacy token in localStorage so old accounts never auto-load
      localStorage.removeItem('netshield_auth_token')
      return sessionStorage.getItem('netshield_auth_token')
    } catch {
      return null
    }
  })
  const [loading, setLoading] = useState(true)

  // Verify saved session token on app mount (only if active in current browser session)
  useEffect(() => {
    // Ensure any legacy localStorage token is purged
    try {
      localStorage.removeItem('netshield_auth_token')
    } catch {
      // Ignore
    }

    async function restoreSession() {
      const savedToken = sessionStorage.getItem('netshield_auth_token')
      if (!savedToken) {
        setUser(null)
        setToken(null)
        setLoading(false)
        return
      }

      try {
        const { user: profile } = await fetchCurrentUser()
        setUser(profile)
        setToken(savedToken)
      } catch (err) {
        console.warn('[AuthContext] Session expired or server unavailable:', err)
        sessionStorage.removeItem('netshield_auth_token')
        setUser(null)
        setToken(null)
      } finally {
        setLoading(false)
      }
    }

    restoreSession()
  }, [])

  // Login handler
  const login = async (identifier, password) => {
    const data = await loginUser(identifier, password)
    sessionStorage.setItem('netshield_auth_token', data.token)
    setToken(data.token)
    setUser(data.user)
    return data
  }

  // Register handler
  const register = async (username, email, password) => {
    const data = await registerUser(username, email, password)
    sessionStorage.setItem('netshield_auth_token', data.token)
    setToken(data.token)
    setUser(data.user)
    return data
  }

  // Logout handler
  const logout = () => {
    try {
      localStorage.removeItem('netshield_auth_token')
      sessionStorage.removeItem('netshield_auth_token')
    } catch {
      // Ignore
    }
    setToken(null)
    setUser(null)
  }

  // Regenerate API Key handler
  const rotateApiKey = async () => {
    const data = await regenerateApiKey()
    setUser(prev => prev ? { ...prev, apiKey: data.apiKey } : null)
    return data.apiKey
  }

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        loading,
        isAuthenticated: !!user,
        login,
        register,
        logout,
        rotateApiKey,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}
