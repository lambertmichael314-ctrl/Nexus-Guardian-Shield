import React, { useEffect, useRef, useState } from 'react'
import {
  Upload,
  FileSearch,
  AlertTriangle,
  CheckCircle,
  XCircle,
  RefreshCw,
  ChevronRight,
  Activity,
} from 'lucide-react'
import { uploadSample, listScans, getScan } from '../services/api'
import useScanProgress from '../hooks/useScanProgress'

function SeverityBadge({ severity }) {
  const map = {
    critical: 'badge-red',
    high: 'badge-red',
    medium: 'badge-amber',
    low: 'badge-blue',
    info: 'badge-blue',
  }
  return <span className={`${map[severity] || 'badge-blue'} capitalize`}>{severity || '—'}</span>
}

function LiveProgress({ scanId, onComplete }) {
  const { events, connected, done } = useScanProgress(scanId)

  useEffect(() => {
    if (done && onComplete) onComplete()
  }, [done, onComplete])

  if (!scanId) return null

  const analyzers = events.filter((e) => e.type === 'analyzer')
  const total = events.find((e) => e.type === 'status' && e.total_analyzers)?.total_analyzers || 11
  const completed = analyzers.filter((e) => e.status === 'complete' || e.status === 'error' || e.status === 'skipped').length
  const pct = total ? Math.round((completed / total) * 100) : 0

  return (
    <div className="glass-panel p-4 space-y-3 animate-pulse">
      <div className="flex items-center justify-between text-sm">
        <span className="text-slate-300 flex items-center gap-2">
          {done ? (
            <CheckCircle className="w-4 h-4 text-cyber-green" />
          ) : (
            <Activity className="w-4 h-4 text-cyber-amber animate-spin" />
          )}
          {done ? 'Analysis complete' : 'Analyzing in real-time…'}
        </span>
        <span className="text-xs text-slate-500">
          {connected ? <span className="badge-green">Live</span> : <span className="badge-amber">Reconnecting</span>}
        </span>
      </div>
      <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
        <div className="h-full bg-gradient-to-r from-cyber-blue to-cyber-cyan transition-all duration-500" style={{ width: `${pct}%` }} />
      </div>
      <div className="flex flex-wrap gap-2">
        {analyzers.map((ev, i) => (
          <span
            key={i}
            className={`text-[10px] px-2 py-0.5 rounded border ${
              ev.status === 'complete' && ev.detected
                ? 'border-cyber-red/30 text-cyber-red bg-cyber-red/10'
                : ev.status === 'complete'
                ? 'border-cyber-green/30 text-cyber-green bg-cyber-green/10'
                : ev.status === 'error'
                ? 'border-cyber-amber/30 text-cyber-amber bg-cyber-amber/10'
                : 'border-slate-700 text-slate-500 bg-slate-900'
            }`}
          >
            {ev.name} ({ev.status})
          </span>
        ))}
      </div>
    </div>
  )
}

export default function Analysis() {
  const [file, setFile] = useState(null)
  const [notes, setNotes] = useState('')
  const [dragging, setDragging] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [uploadResult, setUploadResult] = useState(null)
  const [activeScanId, setActiveScanId] = useState(null)
  const [scans, setScans] = useState([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [limit] = useState(10)
  const [selectedScan, setSelectedScan] = useState(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const fileRef = useRef()

  async function loadScans() {
    try {
      const { data } = await listScans({ limit, offset })
      setScans(data.items || [])
      setTotal(data.total || 0)
    } catch (e) { console.error(e) }
  }

  useEffect(() => { loadScans() }, [offset])

  const handleDrop = (e) => {
    e.preventDefault()
    setDragging(false)
    const f = e.dataTransfer.files[0]
    if (f) setFile(f)
  }

  const handleUpload = async () => {
    if (!file) return
    setUploading(true)
    setUploadResult(null)
    setActiveScanId(null)
    try {
      const { data } = await uploadSample(file, notes)
      setUploadResult(data)
      setActiveScanId(data.id)
      loadScans()
    } catch (err) {
      const msg = err.response?.data?.error?.message || 'Upload failed'
      setUploadResult({ error: msg })
    } finally {
      setUploading(false)
      setFile(null)
      setNotes('')
      if (fileRef.current) fileRef.current.value = ''
    }
  }

  const viewScanDetail = async (id) => {
    setDetailLoading(true)
    try {
      const { data } = await getScan(id)
      setSelectedScan(data)
    } catch (e) { console.error(e) }
    finally { setDetailLoading(false) }
  }

  const pages = Math.ceil(total / limit)
  const currentPage = Math.floor(offset / limit) + 1

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <FileSearch className="w-5 h-5 text-cyber-blue" /> Malware Analysis
        </h1>
      </div>

      <div className="glass-panel p-6 space-y-4">
        <h2 className="text-sm font-semibold text-slate-200">Upload Sample</h2>
        <div
          onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
          onDragLeave={() => setDragging(false)}
          onDrop={handleDrop}
          onClick={() => fileRef.current?.click()}
          className={`
            border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all
            ${dragging ? 'border-cyber-blue bg-cyber-blue/5' : 'border-slate-700 hover:border-slate-600 hover:bg-slate-800/30'}
          `}
        >
          <Upload className="w-8 h-8 text-slate-500 mx-auto mb-3" />
          <p className="text-sm text-slate-400">
            {file ? <span className="text-cyber-blue font-medium">{file.name}</span> : <>Drag & drop a file here, or <span className="text-cyber-blue">click to browse</span></>}
          </p>
          <p className="text-xs text-slate-600 mt-1">Max 50 MB</p>
          <input ref={fileRef} type="file" className="hidden" onChange={(e) => e.target.files?.[0] && setFile(e.target.files[0])} />
        </div>

        {file && (
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
            <input type="text" value={notes} onChange={(e) => setNotes(e.target.value)} className="input-dark flex-1" placeholder="Optional notes for this sample…" />
            <button onClick={handleUpload} disabled={uploading} className="btn-primary text-sm whitespace-nowrap disabled:opacity-50">
              {uploading ? <span className="inline-flex items-center gap-2"><RefreshCw className="w-4 h-4 animate-spin" /> Analyzing…</span> : <><Upload className="w-4 h-4" /> Analyze</>}
            </button>
          </div>
        )}

        {uploadResult && uploadResult.error && (
          <div className="p-3 rounded-lg bg-cyber-red/10 border border-cyber-red/20 text-cyber-red text-sm">
            {uploadResult.error}
          </div>
        )}
      </div>

      {activeScanId && !uploadResult?.error && (
        <LiveProgress scanId={activeScanId} onComplete={loadScans} />
      )}

      <div className="glass-panel overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-200">Scan History</h2>
          <button onClick={loadScans} className="p-1.5 rounded-md text-slate-500 hover:text-cyber-blue hover:bg-cyber-blue/10 transition-colors"><RefreshCw className="w-4 h-4" /></button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-slate-900/50 text-slate-500 text-xs uppercase">
              <tr>
                <th className="px-4 py-3 text-left">ID</th>
                <th className="px-4 py-3 text-left">Filename</th>
                <th className="px-4 py-3 text-left">Hash</th>
                <th className="px-4 py-3 text-left">Status</th>
                <th className="px-4 py-3 text-left">Severity</th>
                <th className="px-4 py-3 text-left">Result</th>
                <th className="px-4 py-3 text-right"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {scans.length === 0 && <tr><td colSpan={7} className="px-4 py-6 text-center text-slate-500">No scans yet.</td></tr>}
              {scans.map((scan) => (
                <tr key={scan.id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="px-4 py-3 text-slate-400">#{scan.id}</td>
                  <td className="px-4 py-3 text-slate-300">{scan.filename}</td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-500 truncate max-w-[140px]">{scan.file_hash}</td>
                  <td className="px-4 py-3">
                    {scan.status === 'completed' ? <span className="badge-green">Completed</span>
                     : scan.status === 'failed' ? <span className="badge-red">Failed</span>
                     : <span className="badge-amber capitalize">{scan.status}</span>}
                  </td>
                  <td className="px-4 py-3"><SeverityBadge severity={scan.severity} /></td>
                  <td className="px-4 py-3">
                    {scan.is_malware ? <span className="badge-red flex items-center gap-1"><AlertTriangle className="w-3 h-3" /> Malicious</span>
                     : <span className="badge-blue flex items-center gap-1"><CheckCircle className="w-3 h-3" /> Clean</span>}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button onClick={() => viewScanDetail(scan.id)} className="p-1.5 rounded-md text-slate-400 hover:text-cyber-blue hover:bg-cyber-blue/10 transition-colors"><ChevronRight className="w-4 h-4" /></button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="px-4 py-3 border-t border-slate-800 flex items-center justify-between">
          <span className="text-xs text-slate-500">Page {currentPage} of {pages || 1} — {total} total</span>
          <div className="flex items-center gap-2">
            <button onClick={() => setOffset((o) => Math.max(0, o - limit))} disabled={offset === 0} className="px-3 py-1 rounded-md text-xs text-slate-400 hover:text-slate-100 hover:bg-slate-800 disabled:opacity-30 transition-colors">Previous</button>
            <button onClick={() => setOffset((o) => o + limit)} disabled={offset + limit >= total} className="px-3 py-1 rounded-md text-xs text-slate-400 hover:text-slate-100 hover:bg-slate-800 disabled:opacity-30 transition-colors">Next</button>
          </div>
        </div>
      </div>

      {selectedScan && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <div className="glass-panel w-full max-w-2xl max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
              <h3 className="text-base font-semibold text-slate-100">Scan #{selectedScan.id}</h3>
              <button onClick={() => setSelectedScan(null)} className="p-1 rounded-md text-slate-500 hover:text-slate-200 hover:bg-slate-800 transition-colors"><XCircle className="w-5 h-5" /></button>
            </div>
            <div className="px-6 py-4 space-y-4">
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div><p className="text-xs text-slate-500">Filename</p><p className="text-slate-200">{selectedScan.filename}</p></div>
                <div><p className="text-xs text-slate-500">Size</p><p className="text-slate-200">{(selectedScan.file_size / 1024).toFixed(1)} KB</p></div>
                <div><p className="text-xs text-slate-500">SHA-256</p><p className="font-mono text-xs text-slate-400 break-all">{selectedScan.file_hash}</p></div>
                <div><p className="text-xs text-slate-500">Status</p><p className="capitalize text-slate-200">{selectedScan.status}</p></div>
                <div><p className="text-xs text-slate-500">Severity</p><p><SeverityBadge severity={selectedScan.severity} /></p></div>
                <div><p className="text-xs text-slate-500">Confidence</p><p className="text-slate-200">{selectedScan.confidence ? `${Math.round(selectedScan.confidence * 100)}%` : '—'}</p></div>
              </div>

              {selectedScan.detector_hits?.length > 0 && (
                <div>
                  <p className="text-xs font-medium text-slate-400 mb-2">Detector Results</p>
                  <div className="space-y-2">
                    {selectedScan.detector_hits.map((hit) => (
                      <div key={hit.name} className={`p-2.5 rounded-lg border text-sm ${hit.detected ? 'bg-cyber-red/10 border-cyber-red/20 text-red-400' : 'bg-slate-800/50 border-slate-700 text-slate-400'}`}>
                        <div className="flex items-center justify-between">
                          <span className="font-medium">{hit.name}</span>
                          <span className="text-xs">{hit.detected ? 'Detected' : 'Clean'} {hit.confidence ? `(${Math.round(hit.confidence * 100)}%)` : ''}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {selectedScan.analysis_summary && (
                <div>
                  <p className="text-xs font-medium text-slate-400 mb-1">Summary</p>
                  <pre className="p-3 rounded-lg bg-slate-900/50 border border-slate-800 text-xs text-slate-300 whitespace-pre-wrap font-mono leading-relaxed">{selectedScan.analysis_summary}</pre>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {detailLoading && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="w-8 h-8 border-4 border-cyber-blue/30 border-t-cyber-blue rounded-full animate-spin" />
        </div>
      )}
    </div>
  )
}
