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
  const [token, setToken] = useState(() => localStorage.getItem('netshield_auth_token'))
  const [loading, setLoading] = useState(true)

  // Verify saved token on app mount
  useEffect(() => {
    async function restoreSession() {
      const savedToken = localStorage.getItem('netshield_auth_token')
      if (!savedToken) {
        setLoading(false)
        return
      }

      try {
        const { user: profile } = await fetchCurrentUser()
        setUser(profile)
        setToken(savedToken)
      } catch (err) {
        console.warn('[AuthContext] Session expired or server unavailable:', err)
        localStorage.removeItem('netshield_auth_token')
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
    localStorage.setItem('netshield_auth_token', data.token)
    setToken(data.token)
    setUser(data.user)
    return data
  }

  // Register handler
  const register = async (username, email, password) => {
    const data = await registerUser(username, email, password)
    localStorage.setItem('netshield_auth_token', data.token)
    setToken(data.token)
    setUser(data.user)
    return data
  }

  // Logout handler
  const logout = () => {
    localStorage.removeItem('netshield_auth_token')
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
