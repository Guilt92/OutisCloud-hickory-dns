import React from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import api from '../api/client'
import { validators } from '../hooks/useFormValidation'
import BulkImport from '../components/BulkImport'
import Notifications from '../components/Notifications'
import { useParams } from 'react-router-dom'
import { FileText, Plus, Trash2, Download, RefreshCw, Edit3, X } from 'lucide-react'

export default function Records(){
  const { id } = useParams()
  const zoneId = id
  const [records, setRecords] = React.useState([])
  const [name, setName] = React.useState('')
  const [type, setType] = React.useState('A')
  const [value, setValue] = React.useState('')
  const [ttl, setTtl] = React.useState(3600)
  const [priority, setPriority] = React.useState(0)
  const [editing, setEditing] = React.useState(null)
  const [error, setError] = React.useState('')
  const [loading, setLoading] = React.useState(false)
  const notify = React.useContext(Notifications)

  const load = async () => { 
    setLoading(true)
    try { 
      const r = await api.get(`/api/v1/zones/${zoneId}/records`); 
      setRecords(r.data || []) 
    } catch (e) { 
      console.error('load records', e)
      notify?.error('Failed to load records: ' + (e.response?.data?.error || e.message))
    }
    setLoading(false)
  }
  React.useEffect(()=>{ 
    const token = localStorage.getItem('token')
    if (token) api.setToken(token)
    load() 
  }, [zoneId])

  const resetForm = () => {
    setName(''); setType('A'); setValue(''); setTtl(3600); setPriority(0); setEditing(null); setError('');
  }

  const validateRecord = () => {
    if (!type) { setError('Type is required'); return false }
    if (!value) { setError('Value is required'); return false }
    if (ttl <= 0) { setError('TTL must be positive'); return false }
    // type-specific checks
    switch(type) {
      case 'A':
        // ipAddress returns '' if valid, error message if invalid
        if (!validators.ipAddress(value)) break
        setError('Invalid IPv4 address'); return false
      case 'AAAA':
        // Same validator works for IPv6 as well
        if (!validators.ipAddress(value)) break
        setError('Invalid IPv6 address'); return false
      case 'CNAME': case 'NS': case 'MX': case 'SRV':
        if (!value.endsWith('.')) { setError('Target must be a fully qualified domain name ending with a dot'); return false }
        break
      case 'TXT':
        // TXT records can be any text, no validation needed
        break
      default:
        break
    }
    if ((type === 'MX' || type === 'SRV') && priority < 0) { setError('Priority must be non‑negative'); return false }
    return true
  }

  const create = async () => {
    setError('')
    if (!validateRecord()) return
    try {
      const payload = { name, record_type: type, value, ttl, priority: (type === 'MX' || type === 'SRV' ? priority : undefined) }
      if (editing) {
        await api.put(`/api/v1/zones/${zoneId}/records/${editing.id}`, payload)
        notify?.success('Record updated successfully')
      } else {
        await api.post(`/api/v1/zones/${zoneId}/records`, payload)
        notify?.success('Record created successfully')
      }
      resetForm()
      load();
    } catch (e) { 
      const errMsg = e.response?.data?.error || e.message || (editing ? 'update failed' : 'create failed');
      setError(errMsg)
      notify?.error(errMsg)
    }
  }
  
  const remove = async (rid) => { 
    try { 
      await api.delete(`/api/v1/zones/${zoneId}/records/${rid}`); 
      if (editing && editing.id === rid) resetForm()
      load() 
      notify?.success('Record deleted')
    } catch (e) { 
      const errMsg = e.response?.data?.error || e.message || 'delete failed';
      notify?.error(errMsg)
    } 
  }
  
  const onBulkComplete = ()=> {
    load()
    notify?.success('Records imported successfully')
  }

  const downloadTemplate = () => {
    const sample = 'name,record_type,value,ttl,priority\nwww,A,192.0.2.1,3600,\nmail,A,192.0.2.2,3600,\n@,MX,mail.example.com.,3600,10\n'
    const blob = new Blob([sample], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'records_template.csv'
    a.click()
    URL.revokeObjectURL(url)
  }

  const recordTypes = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV', 'NS', 'PTR', 'SOA', 'CAA']

  return (
    <div className="page space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        className="section-header"
      >
        <div className="flex items-center gap-3">
          <div className="icon-box bg-gradient-to-br from-orange-500 to-orange-600">
            <FileText className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="section-title">DNS Records</h1>
            <p className="section-desc">Zone: {zoneId?.substring(0,8)}...</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button className="btn-secondary btn-sm" onClick={load} disabled={loading}>
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </motion.div>

      {/* Form card */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        className="card"
      >
        <div className="p-5">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-4">
            <div>
              <label className="form-label">Name</label>
              <input className="input" placeholder="e.g., www" value={name} onChange={e=>setName(e.target.value)} />
            </div>
            <div>
              <label className="form-label">Type</label>
              <select className="select" value={type} onChange={e=>setType(e.target.value)}>
                {recordTypes.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>
            <div>
              <label className="form-label">Value</label>
              <input className="input" placeholder="e.g., 192.0.2.1" value={value} onChange={e=>setValue(e.target.value)} />
            </div>
            <div>
              <label className="form-label">TTL</label>
              <input type="number" className="input" placeholder="3600" value={ttl} onChange={e=>setTtl(Number(e.target.value))} />
            </div>
            <div>
              <label className="form-label">Priority</label>
              <input type="number" className="input" value={priority} onChange={e => setPriority(Number(e.target.value))} />
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">Only used for MX/SRV</p>
            </div>
            <div className="flex items-end gap-2">
              <button className="btn-primary flex-1" onClick={create}>
                <Plus className="w-4 h-4" />
                {editing ? 'Save' : 'Add'} Record
              </button>
              {editing && (
                <button onClick={resetForm} className="btn-sm btn-ghost"><X className="w-4 h-4" /></button>
              )}
            </div>
          </div>

          <AnimatePresence>
            {error && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="mt-4"
              >
                <div className="bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400 px-4 py-2 rounded-lg text-sm border border-red-200 dark:border-red-800">{error}</div>
              </motion.div>
            )}
          </AnimatePresence>

          <div className="flex items-center gap-3 mt-4 pt-4 border-t border-gray-100 dark:border-gray-700">
            <BulkImport endpoint={`/api/v1/zones/${zoneId}/records/bulk`} onComplete={onBulkComplete} />
            <button onClick={downloadTemplate} className="btn-sm btn-ghost">
              <Download className="w-4 h-4" />
              Template
            </button>
          </div>
        </div>
      </motion.div>

      {/* Table */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="card overflow-hidden"
      >
        {records.length === 0 ? (
          <div className="p-12 text-center">
            <FileText className="w-14 h-14 text-gray-300 dark:text-gray-600 mx-auto mb-3" />
            <p className="text-gray-500 dark:text-gray-400">No records in this zone yet</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Type</th>
                  <th>Value</th>
                  <th>TTL</th>
                  <th>Priority</th>
                  <th className="text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {records.map((r, i) => (
                  <motion.tr
                    key={r.id}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: i * 0.02 }}
                  >
                    <td className="font-medium text-gray-900 dark:text-white">{r.name || '@'}</td>
                    <td>
                      <span className={`badge ${
                        ['A','AAAA'].includes(r.record_type) ? 'badge-info' :
                        ['CNAME'].includes(r.record_type) ? 'badge-warning' :
                        ['MX'].includes(r.record_type) ? 'badge-danger' :
                        ['TXT'].includes(r.record_type) ? 'badge-success' :
                        'badge-default'
                      }`}>
                        {r.record_type}
                      </span>
                    </td>
                    <td className="font-mono text-gray-600 dark:text-gray-300 max-w-xs truncate">{r.value}</td>
                    <td className="text-gray-500 dark:text-gray-400">{r.ttl}</td>
                    <td className="text-gray-500 dark:text-gray-400">{r.priority || ''}</td>
                    <td className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => {
                            setEditing(r);
                            setName(r.name);
                            setType(r.record_type);
                            setValue(r.value);
                            setTtl(r.ttl);
                            setPriority(r.priority);
                          }}
                          className="btn-sm btn-ghost"
                        >
                          <Edit3 className="w-3.5 h-3.5" />
                        </button>
                        <button onClick={() => remove(r.id)} className="btn-sm text-red-600 hover:bg-red-50 dark:text-red-400 dark:hover:bg-red-900/20 rounded-lg transition-colors">
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
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
