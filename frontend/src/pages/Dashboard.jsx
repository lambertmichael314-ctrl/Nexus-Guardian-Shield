import React, { useEffect, useState } from 'react'
import {
  Shield,
  AlertTriangle,
  FileSearch,
  Users,
  Activity,
  TrendingUp,
  TrendingDown,
} from 'lucide-react'
import { listIOCs, listScans } from '../services/api'

function StatCard({ title, value, icon: Icon, color, trend }) {
  const colorMap = {
    blue:  'bg-cyber-blue/10 text-cyber-blue border-cyber-blue/20',
    green: 'bg-cyber-green/10 text-cyber-green border-cyber-green/20',
    amber: 'bg-cyber-amber/10 text-cyber-amber border-cyber-amber/20',
    red:   'bg-cyber-red/10 text-cyber-red border-cyber-red/20',
  }
  return (
    <div className="glass-panel p-4 flex items-start justify-between">
      <div>
        <p className="text-xs text-slate-500 mb-1">{title}</p>
        <p className="text-2xl font-bold text-slate-100">{value}</p>
        {trend && (
          <p className={`text-xs mt-1 flex items-center gap-1 ${trend.up ? 'text-cyber-green' : 'text-cyber-red'}`}>
            {trend.up ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
            {trend.label}
          </p>
        )}
      </div>
      <div className={`w-10 h-10 rounded-lg border flex items-center justify-center ${colorMap[color]}`}>
        <Icon className="w-5 h-5" />
      </div>
    </div>
  )
}

export default function Dashboard() {
  const [stats, setStats] = useState({ iocs: 0, scans: 0, alerts: 0 })
  const [recentIOCs, setRecentIOCs] = useState([])
  const [recentScans, setRecentScans] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    async function load() {
      try {
        const [iocRes, scanRes] = await Promise.all([
          listIOCs({ limit: 5 }),
          listScans({ limit: 5 }),
        ])
        setRecentIOCs(iocRes.data.items || [])
        setRecentScans(scanRes.data.items || [])
        setStats({
          iocs: iocRes.data.total || 0,
          scans: scanRes.data.total || 0,
          alerts: (scanRes.data.items || []).filter(s => s.is_malware).length,
        })
      } catch (e) {
        console.error('Dashboard fetch failed', e)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [])

  const severityBadge = (sev) => {
    const map = {
      critical: 'badge-red',
      high: 'badge-red',
      medium: 'badge-amber',
      low: 'badge-blue',
      info: 'badge-blue',
    }
    return map[sev] || 'badge-blue'
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-8 h-8 border-4 border-cyber-blue/30 border-t-cyber-blue rounded-full animate-spin" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-slate-100">Dashboard</h1>
        <span className="text-xs text-slate-500 flex items-center gap-1">
          <Activity className="w-3 h-3 text-cyber-green animate-pulse" />
          System Online
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard title="Total IOCs" value={stats.iocs} icon={Shield} color="blue" />
        <StatCard title="Total Scans" value={stats.scans} icon={FileSearch} color="green" />
        <StatCard
          title="Active Alerts"
          value={stats.alerts}
          icon={AlertTriangle}
          color={stats.alerts > 0 ? 'red' : 'amber'}
        />
        <StatCard title="Platform Status" value="Healthy" icon={Activity} color="green" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent IOCs */}
        <div className="glass-panel overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-200">Recent Indicators</h2>
            <a href="/intelligence" className="text-xs text-cyber-blue hover:underline">View all</a>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-900/50 text-slate-500 text-xs">
                <tr>
                  <th className="px-4 py-2 text-left font-medium">Type</th>
                  <th className="px-4 py-2 text-left font-medium">Value</th>
                  <th className="px-4 py-2 text-left font-medium">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {recentIOCs.length === 0 && (
                  <tr>
                    <td colSpan={3} className="px-4 py-6 text-center text-slate-500">
                      No indicators found
                    </td>
                  </tr>
                )}
                {recentIOCs.map((ioc) => (
                  <tr key={ioc.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-4 py-2.5">
                      <span className="badge-blue">{ioc.ioc_type}</span>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-slate-300 truncate max-w-[200px]">
                      {ioc.value}
                    </td>
                    <td className="px-4 py-2.5">
                      {ioc.is_active ? (
                        <span className="badge-green">Active</span>
                      ) : (
                        <span className="badge-amber">Inactive</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Recent Scans */}
        <div className="glass-panel overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-200">Recent Analyses</h2>
            <a href="/analysis" className="text-xs text-cyber-blue hover:underline">View all</a>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-900/50 text-slate-500 text-xs">
                <tr>
                  <th className="px-4 py-2 text-left font-medium">Filename</th>
                  <th className="px-4 py-2 text-left font-medium">Status</th>
                  <th className="px-4 py-2 text-left font-medium">Result</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {recentScans.length === 0 && (
                  <tr>
                    <td colSpan={3} className="px-4 py-6 text-center text-slate-500">
                      No scans found
                    </td>
                  </tr>
                )}
                {recentScans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-4 py-2.5 text-slate-300 truncate max-w-[200px]">
                      {scan.filename}
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={`badge-${scan.status === 'completed' ? 'green' : scan.status === 'failed' ? 'red' : 'amber'}`}>
                        {scan.status}
                      </span>
                    </td>
                    <td className="px-4 py-2.5">
                      {scan.is_malware ? (
                        <span className="badge-red">Malicious</span>
                      ) : (
                        <span className="badge-blue">Clean</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  )
}
