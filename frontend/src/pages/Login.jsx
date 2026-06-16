import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { Shield, Eye, EyeOff } from 'lucide-react'
import { register as apiRegister } from '../services/api'

export default function Login() {
  const navigate = useNavigate()
  const { login } = useAuth()
  const [isRegister, setIsRegister] = useState(false)
  const [showPass, setShowPass] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [form, setForm] = useState({
    username: '',
    email: '',
    password: '',
    full_name: '',
  })

  const handleChange = (e) =>
    setForm((f) => ({ ...f, [e.target.name]: e.target.value }))

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      if (isRegister) {
        await apiRegister({
          username: form.username,
          email: form.email,
          password: form.password,
          full_name: form.full_name || undefined,
          role: 'analyst',
        })
        await login(form.username, form.password)
      } else {
        await login(form.username, form.password)
      }
      navigate('/dashboard')
    } catch (err) {
      const msg = err.response?.data?.error?.message || err.response?.data?.detail || 'Authentication failed'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950 px-4">
      <div className="w-full max-w-sm">
        <div className="flex flex-col items-center mb-8">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-cyber-blue to-cyber-cyan flex items-center justify-center mb-3 shadow-lg shadow-cyber-blue/20">
            <Shield className="w-7 h-7 text-slate-900" />
          </div>
          <h1 className="text-2xl font-bold text-slate-100">CTI Platform</h1>
          <p className="text-sm text-slate-500 mt-1">Guardian Shield Enterprise</p>
        </div>

        <div className="glass-panel p-6">
          {error && (
            <div className="mb-4 px-3 py-2 rounded-lg bg-red-400/10 border border-red-400/20 text-red-400 text-sm">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">Username</label>
              <input
                name="username"
                type="text"
                required
                autoFocus
                value={form.username}
                onChange={handleChange}
                className="input-dark"
                placeholder="analyst1"
              />
            </div>

            {isRegister && (
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Email</label>
                <input
                  name="email"
                  type="email"
                  required
                  value={form.email}
                  onChange={handleChange}
                  className="input-dark"
                  placeholder="analyst@org.com"
                />
              </div>
            )}

            {isRegister && (
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Full Name</label>
                <input
                  name="full_name"
                  type="text"
                  value={form.full_name}
                  onChange={handleChange}
                  className="input-dark"
                  placeholder="Optional"
                />
              </div>
            )}

            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">Password</label>
              <div className="relative">
                <input
                  name="password"
                  type={showPass ? 'text' : 'password'}
                  required
                  minLength={12}
                  value={form.password}
                  onChange={handleChange}
                  className="input-dark pr-10"
                  placeholder="••••••••••••"
                />
                <button
                  type="button"
                  onClick={() => setShowPass((s) => !s)}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                >
                  {showPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-primary w-full disabled:opacity-50"
            >
              {loading ? (
                <span className="inline-flex items-center gap-2">
                  <span className="w-4 h-4 border-2 border-slate-900/30 border-t-slate-900 rounded-full animate-spin" />
                  {isRegister ? 'Creating account…' : 'Signing in…'}
                </span>
              ) : isRegister ? (
                'Create Account'
              ) : (
                'Sign In'
              )}
            </button>
          </form>

          <div className="mt-4 text-center">
            <button
              onClick={() => {
                setIsRegister((r) => !r)
                setError('')
              }}
              className="text-xs text-slate-500 hover:text-cyber-blue transition-colors"
            >
              {isRegister ? 'Already have an account? Sign in' : "Need an account? Register"}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
