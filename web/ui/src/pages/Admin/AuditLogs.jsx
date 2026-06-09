import React from 'react'
import { motion } from 'framer-motion'
import api from '../../api/client'
import { ClipboardList, Search, Download } from 'lucide-react'

export default function AuditLogs(){
  const [logs, setLogs] = React.useState([])
  const [q, setQ] = React.useState('')

  const load = async ()=>{ try { const r = await api.get('/api/v1/audit/logs'); setLogs(r.data||[]) } catch(e){ console.error(e) } }
  React.useEffect(()=>{ const t=localStorage.getItem('token'); if(t) api.setToken(t); load() }, [])

  const exportCSV = ()=>{
    const hdrs = ['time','actor','action','details']
    const rows = logs.map(l => [l.time, l.actor, l.action, JSON.stringify(l.details)])
    const csv = [hdrs.join(','), ...rows.map(r=> r.map(c=>`"${String(c).replace(/"/g,'""')}"`).join(','))].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = 'audit_logs.csv'; a.click(); URL.revokeObjectURL(url)
  }

  const filtered = logs.filter(l=> JSON.stringify(l).toLowerCase().includes(q.toLowerCase()))

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
            <input className="input pl-9" placeholder="Filter logs..." value={q} onChange={e=>setQ(e.target.value)} />
          </div>
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
                  <th>Actor</th>
                  <th>Action</th>
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
                    <td className="text-gray-500 dark:text-gray-400 whitespace-nowrap">{l.time}</td>
                    <td className="font-medium text-gray-900 dark:text-white">{l.actor}</td>
                    <td><span className="badge badge-info">{l.action}</span></td>
                    <td className="text-gray-600 dark:text-gray-300 max-w-xs truncate font-mono text-xs">{JSON.stringify(l.details)}</td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </motion.div>
    </div>
  )
}
