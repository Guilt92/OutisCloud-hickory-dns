import React from 'react'
import { motion } from 'framer-motion'
import api from '../../api/client'
import { ClipboardList, Search, Download } from 'lucide-react'

const PAGE = 50

export default function AuditLogs(){
  const [logs, setLogs] = React.useState([])
  const [total, setTotal] = React.useState(0)
  const [page, setPage] = React.useState(0)
  const [action, setAction] = React.useState('')
  const [resource, setResource] = React.useState('')
  const [q, setQ] = React.useState('')
  const [error, setError] = React.useState('')

  const load = async ()=>{
    try {
      const params = { limit: PAGE, offset: page * PAGE }
      if (action) params.action = action
      if (resource) params.resource_type = resource
      const r = await api.get('/api/v1/audit/logs', { params })
      setLogs(r.data || [])
      setTotal(parseInt(r.headers?.['x-total-count'] || '0', 10))
      setError('')
    } catch(e){ setError(e.response?.data?.error || e.message) }
  }
  React.useEffect(()=>{ const t=localStorage.getItem('token'); if(t) api.setToken(t); load() }, [page, action, resource])

  const exportCSV = ()=>{
    const hdrs = ['time','user','action','resource','resource_id','ip','details']
    const rows = logs.map(l => [l.createdAt, l.userId, l.action, l.resourceType, l.resourceId, l.ipAddress, l.details])
    const csv = [hdrs.join(','), ...rows.map(r=> r.map(c=>`"${String(c ?? '').replace(/"/g,'""')}"`).join(','))].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = 'audit_logs.csv'; a.click(); URL.revokeObjectURL(url)
  }

  const filtered = logs.filter(l=> JSON.stringify(l).toLowerCase().includes(q.toLowerCase()))
  const pages = Math.max(1, Math.ceil(total / PAGE))

  return (
    <div className="page space-y-6">
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        className="section-header"
      >
        <div className="flex items-center gap-3">
          <div className="icon-box bg-gradient-to-br from-amber-500 to-amber-600">
            <ClipboardList className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="section-title">Audit Logs</h1>
            <p className="section-desc">Track all administrative actions and system events</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
            <input className="input pl-9" placeholder="Filter this page..." value={q} onChange={e=>setQ(e.target.value)} />
          </div>
          <input className="input w-36" placeholder="action" value={action} onChange={e=>{setPage(0); setAction(e.target.value.trim())}} />
          <select className="select w-36" value={resource} onChange={e=>{setPage(0); setResource(e.target.value)}}>
            <option value="">all resources</option>
            {['user','zone','record','georule','nameserver','agent'].map(r => <option key={r} value={r}>{r}</option>)}
          </select>
          <button className="btn-secondary btn-sm" onClick={exportCSV}>
            <Download className="w-4 h-4" />
            Export CSV
          </button>
        </div>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        className="card overflow-hidden"
      >
        {filtered.length === 0 ? (
          <div className="p-12 text-center">
            <ClipboardList className="w-14 h-14 text-gray-300 dark:text-gray-600 mx-auto mb-3" />
            <p className="text-gray-500 dark:text-gray-400">No audit logs found</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>User</th>
                  <th>Action</th>
                  <th>Resource</th>
                  <th>Address</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((l,i) => (
                  <motion.tr
                    key={i}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: i * 0.01 }}
                  >
                    <td className="text-gray-500 dark:text-gray-400 whitespace-nowrap">{l.createdAt ? new Date(l.createdAt).toLocaleString() : ''}</td>
                    <td className="font-mono text-xs text-gray-900 dark:text-white">{l.userId ? l.userId.slice(0, 8) : '-'}</td>
                    <td><span className="badge badge-info">{l.action}</span></td>
                    <td className="text-xs">{l.resourceType}{l.resourceId ? ` ${String(l.resourceId).slice(0, 8)}` : ''}</td>
                    <td className="text-xs text-gray-500">{l.ipAddress || '-'}</td>
                    <td className="text-gray-600 dark:text-gray-300 max-w-xs truncate font-mono text-xs" title={l.details}>{l.details}</td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {error && <p className="p-3 text-sm text-red-600">{error}</p>}
        <div className="flex items-center justify-between px-5 py-3 border-t border-gray-100 dark:border-gray-700 text-sm">
          <span className="text-gray-500">{total} event(s)</span>
          <div className="flex items-center gap-2">
            <button className="btn-sm btn-ghost" disabled={page === 0} onClick={()=>setPage(page-1)}>Previous</button>
            <span>Page {page + 1} / {pages}</span>
            <button className="btn-sm btn-ghost" disabled={page + 1 >= pages} onClick={()=>setPage(page+1)}>Next</button>
          </div>
        </div>
      </motion.div>
    </div>
  )
}
