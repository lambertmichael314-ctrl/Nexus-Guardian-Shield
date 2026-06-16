import React from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import {
  LayoutDashboard,
  Shield,
  FileSearch,
  Users,
  LogOut,
  Menu,
  X,
} from 'lucide-react'

const navItems = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/intelligence', label: 'Intelligence', icon: Shield },
  { to: '/analysis', label: 'Analysis', icon: FileSearch },
]

const adminNav = { to: '/users', label: 'Users', icon: Users }

export default function Layout() {
  const { user, logout, isAdmin } = useAuth()
  const [sidebarOpen, setSidebarOpen] = React.useState(false)

  return (
    <div className="min-h-screen flex bg-slate-950">
      {/* Mobile sidebar overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/60 z-30 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={`
          fixed lg:static inset-y-0 left-0 z-40 w-60
          bg-slate-900 border-r border-slate-800
          flex flex-col transition-transform duration-200
          ${sidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
        `}
      >
        <div className="h-14 flex items-center px-4 border-b border-slate-800">
          <Shield className="w-6 h-6 text-cyber-blue mr-2" />
          <span className="font-bold text-slate-100 tracking-tight">CTI Platform</span>
        </div>

        <nav className="flex-1 px-2 py-4 space-y-1">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              onClick={() => setSidebarOpen(false)}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-cyber-blue/10 text-cyber-blue border border-cyber-blue/20'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800'
                }`
              }
            >
              <item.icon className="w-4 h-4" />
              {item.label}
            </NavLink>
          ))}

          {isAdmin && (
            <NavLink
              to={adminNav.to}
              onClick={() => setSidebarOpen(false)}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-cyber-blue/10 text-cyber-blue border border-cyber-blue/20'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800'
                }`
              }
            >
              <Users className="w-4 h-4" />
              {adminNav.label}
            </NavLink>
          )}
        </nav>

        <div className="p-3 border-t border-slate-800">
          <div className="px-3 py-2 mb-2">
            <p className="text-xs text-slate-500">Signed in as</p>
            <p className="text-sm font-medium text-slate-200 truncate">{user?.username}</p>
            <p className="text-xs text-slate-500">{user?.role}</p>
          </div>
          <button
            onClick={logout}
            className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm text-red-400 hover:bg-red-400/10 hover:text-red-300 transition-colors"
          >
            <LogOut className="w-4 h-4" />
            Logout
          </button>
        </div>
      </aside>

      {/* Main area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top header */}
        <header className="h-14 flex items-center justify-between px-4 border-b border-slate-800 bg-slate-900/80 backdrop-blur">
          <div className="flex items-center gap-3">
            <button
              className="lg:hidden p-1 text-slate-400 hover:text-slate-100"
              onClick={() => setSidebarOpen(true)}
            >
              <Menu className="w-5 h-5" />
            </button>
          </div>
          <div className="flex items-center gap-3">
            <span className="badge-blue">v1.0.0</span>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 p-4 lg:p-6 overflow-y-auto">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
