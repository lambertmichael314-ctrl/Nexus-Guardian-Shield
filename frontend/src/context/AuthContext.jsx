import React, { createContext, useContext, useEffect, useState } from 'react'
import { login as apiLogin, getMe } from '../services/api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  // Restore session on mount
  useEffect(() => {
    const token = localStorage.getItem('access_token')
    if (!token) {
      setLoading(false)
      return
    }
    getMe()
      .then((res) => setUser(res.data))
      .catch(() => localStorage.clear())
      .finally(() => setLoading(false))
  }, [])

  const login = async (username, password) => {
    const { data } = await apiLogin(username, password)
    localStorage.setItem('access_token', data.access_token)
    localStorage.setItem('refresh_token', data.refresh_token)
    const me = await getMe()
    setUser(me.data)
    return me.data
  }

  const logout = () => {
    localStorage.removeItem('access_token')
    localStorage.removeItem('refresh_token')
    setUser(null)
    window.location.href = '/login'
  }

  const isAdmin = user?.role === 'admin'

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, isAdmin, isAuthenticated: !!user }}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => useContext(AuthContext)
