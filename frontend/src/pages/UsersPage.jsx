import React, { useEffect, useState } from 'react'
import {
  Users,
  Plus,
  Edit3,
  UserX,
  X,
  Shield,
  Search,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react'
import { listUsers, createUser, updateUser, deleteUser } from '../services/api'

const ROLES = ['analyst', 'admin']

export default function UsersPage() {
  const [users, setUsers] = useState([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [limit] = useState(15)
  const [search, setSearch] = useState('')
  const [loading, setLoading] = useState(false)
  const [modalOpen, setModalOpen] = useState(false)
  const [editing, setEditing] = useState(null)
  const [form, setForm] = useState({
    username: '',
    email: '',
    password: '',
    full_name: '',
    role: 'analyst',
    is_active: true,
  })

  async function load() {
    setLoading(true)
    try {
      const { data } = await listUsers({ limit, offset })
      setUsers(data.items || [])
      setTotal(data.total || 0)
    } catch (e) {
      console.error('User fetch error', e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [offset])

  const resetForm = () => {
    setForm({ username: '', email: '', password: '', full_name: '', role: 'analyst', is_active: true })
    setEditing(null)
  }

  const openCreate = () => {
    resetForm()
    setModalOpen(true)
  }

  const openEdit = (user) => {
    setForm({
      username: user.username,
      email: user.email,
      password: '',
      full_name: user.full_name || '',
      role: user.role,
      is_active: user.is_active,
    })
    setEditing(user.id)
    setModalOpen(true)
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    try {
      const payload = { ...form }
      if (editing && !payload.password) delete payload.password
      if (editing) {
        await updateUser(editing, payload)
      } else {
        await createUser(payload)
      }
      setModalOpen(false)
      resetForm()
      load()
    } catch (err) {
      const msg = err.response?.data?.error?.message || err.response?.data?.detail || 'Save failed'
      alert(msg)
    }
  }

  const handleDeactivate = async (id) => {
    if (!confirm('Deactivate this user account?')) return
    try {
      await deleteUser(id)
      load()
    } catch (e) {
      alert('Deactivation failed')
    }
  }

  const filtered = users.filter((u) =>
    u.username.toLowerCase().includes(search.toLowerCase()) ||
    u.email.toLowerCase().includes(search.toLowerCase())
  )

  const pages = Math.ceil(total / limit)
  const currentPage = Math.floor(offset / limit) + 1

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <Users className="w-5 h-5 text-cyber-blue" />
          User Management
        </h1>
        <button onClick={openCreate} className="btn-primary text-sm">
          <Plus className="w-4 h-4" />
          Create User
        </button>
      </div>

      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search users…"
            className="input-dark pl-9"
          />
        </div>
      </div>

      <div className="glass-panel overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-slate-900/50 text-slate-500 text-xs uppercase">
              <tr>
                <th className="px-4 py-3 text-left">User</th>
                <th className="px-4 py-3 text-left">Email</th>
                <th className="px-4 py-3 text-left">Role</th>
                <th className="px-4 py-3 text-left">Status</th>
                <th className="px-4 py-3 text-left">Created</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {loading ? (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center">
                    <div className="w-6 h-6 border-2 border-cyber-blue/30 border-t-cyber-blue rounded-full animate-spin mx-auto" />
                  </td>
                </tr>
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-slate-500">
                    No users found.
                  </td>
                </tr>
              ) : (
                filtered.map((user) => (
                  <tr key={user.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-xs font-bold text-slate-400">
                          {user.username.charAt(0).toUpperCase()}
                        </div>
                        <div>
                          <p className="text-slate-200 font-medium">{user.username}</p>
                          {user.full_name && (
                            <p className="text-xs text-slate-500">{user.full_name}</p>
                          )}
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-slate-400">{user.email}</td>
                    <td className="px-4 py-3">
                      {user.role === 'admin' ? (
                        <span className="badge-red flex items-center gap-1">
                          <Shield className="w-3 h-3" />
                          admin
                        </span>
                      ) : (
                        <span className="badge-blue">analyst</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {user.is_active ? (
                        <span className="badge-green">Active</span>
                      ) : (
                        <span className="badge-amber">Inactive</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-slate-500 text-xs">
                      {user.created_at ? new Date(user.created_at).toLocaleDateString() : '—'}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => openEdit(user)}
                          className="p-1.5 rounded-md text-slate-400 hover:text-cyber-blue hover:bg-cyber-blue/10 transition-colors"
                          title="Edit"
                        >
                          <Edit3 className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleDeactivate(user.id)}
                          disabled={!user.is_active}
                          className="p-1.5 rounded-md text-slate-400 hover:text-cyber-red hover:bg-cyber-red/10 transition-colors disabled:opacity-30"
                          title="Deactivate"
                        >
                          <UserX className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div className="px-4 py-3 border-t border-slate-800 flex items-center justify-between">
          <span className="text-xs text-slate-500">
            Showing {filtered.length} of {total} results
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setOffset((o) => Math.max(0, o - limit))}
              disabled={offset === 0}
              className="p-1.5 rounded-md text-slate-400 hover:text-slate-100 hover:bg-slate-800 disabled:opacity-30 transition-colors"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="text-xs text-slate-400">
              Page {currentPage} of {pages || 1}
            </span>
            <button
              onClick={() => setOffset((o) => o + limit)}
              disabled={offset + limit >= total}
              className="p-1.5 rounded-md text-slate-400 hover:text-slate-100 hover:bg-slate-800 disabled:opacity-30 transition-colors"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Modal */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <div className="glass-panel w-full max-w-lg">
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
              <h3 className="text-base font-semibold text-slate-100">
                {editing ? 'Edit User' : 'Create User'}
              </h3>
              <button
                onClick={() => { setModalOpen(false); resetForm() }}
                className="p-1 rounded-md text-slate-500 hover:text-slate-200 hover:bg-slate-800 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleSubmit} className="px-6 py-4 space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">Username</label>
                  <input
                    type="text"
                    required
                    disabled={!!editing}
                    value={form.username}
                    onChange={(e) => setForm((f) => ({ ...f, username: e.target.value }))}
                    className="input-dark disabled:opacity-50"
                    placeholder="analyst42"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">Role</label>
                  <select
                    value={form.role}
                    onChange={(e) => setForm((f) => ({ ...f, role: e.target.value }))}
                    className="input-dark"
                  >
                    {ROLES.map((r) => (
                      <option key={r} value={r}>{r}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Email</label>
                <input
                  type="email"
                  required
                  value={form.email}
                  onChange={(e) => setForm((f) => ({ ...f, email: e.target.value }))}
                  className="input-dark"
                  placeholder="user@org.com"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">
                  Password {editing && <span className="text-slate-600">(leave blank to keep current)</span>}
                </label>
                <input
                  type="password"
                  required={!editing}
                  value={form.password}
                  onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))}
                  className="input-dark"
                  placeholder={editing ? '••••••••' : 'Min 12 characters'}
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Full Name</label>
                <input
                  type="text"
                  value={form.full_name}
                  onChange={(e) => setForm((f) => ({ ...f, full_name: e.target.value }))}
                  className="input-dark"
                  placeholder="Optional"
                />
              </div>

              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={form.is_active}
                  onChange={(e) => setForm((f) => ({ ...f, is_active: e.target.checked }))}
                  className="w-4 h-4 rounded border-slate-600 bg-slate-800 text-cyber-blue"
                />
                <span className="text-sm text-slate-300">Account active</span>
              </div>

              <div className="flex items-center justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => { setModalOpen(false); resetForm() }}
                  className="px-4 py-2 rounded-lg text-sm text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
                >
                  Cancel
                </button>
                <button type="submit" className="btn-primary text-sm">
                  {editing ? 'Update User' : 'Create User'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
