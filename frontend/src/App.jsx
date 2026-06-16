import React from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './context/AuthContext'
import Layout from './components/Layout'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Intelligence from './pages/Intelligence'
import Analysis from './pages/Analysis'
import UsersPage from './pages/UsersPage'

function RequireAuth({ children }) {
  const { isAuthenticated, loading } = useAuth()
  if (loading) {
    return (
      <div className="h-screen flex items-center justify-center bg-slate-950">
        <div className="w-10 h-10 border-4 border-cyber-blue/30 border-t-cyber-blue rounded-full animate-spin" />
      </div>
    )
  }
  return isAuthenticated ? children : <Navigate to="/login" replace />
}

function RequireAdmin({ children }) {
  const { isAdmin, loading } = useAuth()
  if (loading) {
    return (
      <div className="h-screen flex items-center justify-center bg-slate-950">
        <div className="w-10 h-10 border-4 border-cyber-blue/30 border-t-cyber-blue rounded-full animate-spin" />
      </div>
    )
  }
  return isAdmin ? children : <Navigate to="/dashboard" replace />
}

function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="/"
          element={
            <RequireAuth>
              <Layout />
            </RequireAuth>
          }
        >
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="intelligence" element={<Intelligence />} />
          <Route path="analysis" element={<Analysis />} />
          <Route
            path="users"
            element={
              <RequireAdmin>
                <UsersPage />
              </RequireAdmin>
            }
          />
        </Route>
      </Routes>
    </AuthProvider>
  )
}

export default App
