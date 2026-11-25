import React from 'react'
import { apiErrorMessage } from '../api/errors'
import { motion, AnimatePresence } from 'framer-motion'
import api from '../api/client'
import { validators } from '../hooks/useFormValidation'
import BulkImport from '../components/BulkImport'
import Notifications from '../components/Notifications'
import { useParams } from 'react-router-dom'
import { useAuthStore } from '../store'
import { useServerPagination, PaginationControls } from '../hooks/useAdvancedUI'
import { FileText, Plus, Trash2, Download, RefreshCw, Edit3, X, Tag } from 'lucide-react'
import { useConfirm } from '../components/ui'

export default function Records(){
  const askConfirm = useConfirm()
  const { id } = useParams()
  const zoneId = id
  const paged = useServerPagination(api, `/api/v1/zones/${zoneId}/records`, { pageSize: 25 })
  const records = paged.items
  const [name, setName] = React.useState('')
  const [type, setType] = React.useState('A')
  const [value, setValue] = React.useState('')
  const [ttl, setTtl] = React.useState(3600)
  const [priority, setPriority] = React.useState(0)
  const [editing, setEditing] = React.useState(null)
  const [error, setError] = React.useState('')
  const [metaRecord, setMetaRecord] = React.useState(null)
  const [metaComment, setMetaComment] = React.useState('')
  const [metaTags, setMetaTags] = React.useState('')
  const loading = paged.loading
  const notify = React.useContext(Notifications)
  const notifyRef = React.useRef(notify)
  notifyRef.current = notify
  const { user } = useAuthStore()
  const [access, setAccess] = React.useState('')
  // read-only for viewer accounts and for zones shared as viewer
  const readOnly = user?.role === 'viewer' || access === 'viewer'
  React.useEffect(() => { api.get(`/api/v1/zones/${zoneId}`).then(r => setAccess(r.data?.access || '')).catch(() => {}) }, [zoneId])

  const load = paged.reload
  React.useEffect(()=>{
    const token = localStorage.getItem('token')
    if (token) api.setToken(token)
  }, [zoneId])
  React.useEffect(() => { if (paged.error) notifyRef.current?.error('Failed to load records: ' + (paged.error.response?.data?.error || paged.error.message)) }, [paged.error])

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
      const errMsg = apiErrorMessage(e, editing ? 'update failed' : 'create failed');
      setError(errMsg)
      notify?.error(errMsg)
    }
  }
  
  const startMetadata = (record) => {
    setMetaRecord(record)
    setMetaComment(record.comment || '')
    setMetaTags((record.tags || []).join(', '))
  }

  const saveMetadata = async () => {
    try {
      await api.put(`/api/v1/zones/${zoneId}/records/${metaRecord.id}/metadata`, {
        comment: metaComment,
        tags: metaTags.split(',').map(t => t.trim()).filter(Boolean),
      })
      notify?.success('Record metadata saved')
      setMetaRecord(null)
      load()
    } catch (e) {
      notify?.error(apiErrorMessage(e, 'metadata update failed'))
    }
  }

  const remove = async (record) => {
    const confirmed = await askConfirm({
      title: 'Delete record?',
      message: `"${record.name || '@'} ${record.record_type}" will be removed and the zone republished. This cannot be undone from this page.`,
      confirmLabel: 'Delete record',
    })
    if (!confirmed) return
    try {
      await api.delete(`/api/v1/zones/${zoneId}/records/${record.id}`)
      if (editing && editing.id === record.id) resetForm()
      load()
      notify?.success('Record deleted')
    } catch (e) {
      const errMsg = e.response?.data?.error || e.message || 'delete failed'
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

  // CAA is the advanced editable type with end-to-end Hickory/API coverage.
  // Types not parsed and served by Hickory (for example DNAME and LOC) are
  // intentionally omitted; the API rejects them with an explicit error.
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
          <div className="icon-box">
            <FileText className="w-5 h-5" />
          </div>
          <div>
            <h1 className="section-title">DNS records</h1>
            <p className="section-desc">Zone: {zoneId?.substring(0, 8)}…</p>
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
      {!readOnly && (
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        className="card"
      >
        <div className="p-5">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-4">
            <div>
              <label className="form-label">Name</label>
              <input className="input" aria-label="Record name" placeholder="e.g., www" value={name} onChange={e=>setName(e.target.value)} />
            </div>
            <div>
              <label className="form-label">Type</label>
              <select className="select" aria-label="Record type" value={type} onChange={e=>setType(e.target.value)}>
                {recordTypes.map(t => <option key={t} value={t}>{t === 'CAA' ? 'CAA — Certificate Authority Authorization' : t}</option>)}
              </select>
            </div>
            <div>
              <label className="form-label">Value</label>
              <input className="input" aria-label="Record value" placeholder="e.g., 192.0.2.1" value={value} onChange={e=>setValue(e.target.value)} />
            </div>
            <div>
              <label className="form-label">TTL</label>
              <input type="number" className="input" aria-label="Record TTL" placeholder="3600" value={ttl} onChange={e=>setTtl(Number(e.target.value))} />
            </div>
            <div>
              <label className="form-label">Priority</label>
              <input type="number" className="input" aria-label="Record priority" value={priority} onChange={e => setPriority(Number(e.target.value))} />
              <p className="text-xs text-muted mt-1">Only used for MX/SRV</p>
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
                <div className="bg-danger-500/10 text-danger-600 dark:text-danger-400 px-4 py-2 rounded-[14px] text-sm border border-danger-500/40">{error}</div>
              </motion.div>
            )}
          </AnimatePresence>

          <div className="flex items-center gap-3 mt-4 pt-4 border-t border-line">
            <BulkImport endpoint={`/api/v1/zones/${zoneId}/import`} onComplete={onBulkComplete} />
            <button onClick={downloadTemplate} className="btn-sm btn-ghost">
              <Download className="w-4 h-4" />
              Template
            </button>
          </div>
        </div>
      </motion.div>
      )}

      <input className="input" aria-label="Search records by name, value or type" placeholder="Search records by name, value or type…" value={paged.query} onChange={e => paged.setQuery(e.target.value)} />

      {/* Table */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="card overflow-hidden"
      >
        {records.length === 0 ? (
          <div className="p-12 text-center">
            <FileText className="w-14 h-14 text-muted/40 mx-auto mb-3" />
            <p className="text-muted">No records in this zone yet.</p>
          </div>
        ) : (
          <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="Scrollable table">
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
                    <td className="font-medium text-ink">{r.name || '@'}</td>
                    <td>
                      <span className="badge badge-default font-mono">{r.record_type}</span>
                    </td>
                    <td className="font-mono text-muted max-w-xs truncate">
                      {r.value}
                      {r.comment && <span className="block text-xs text-muted/70 truncate" title={r.comment}>{r.comment}</span>}
                    </td>
                    <td className="text-muted">{r.ttl}</td>
                    <td className="text-muted">{r.priority || ''}</td>
                    <td className="text-right">
                      {!readOnly && <div className="flex items-center justify-end gap-1">
                        <button onClick={() => startMetadata(r)} aria-label={`Edit metadata for ${r.name || '@'}`} className="btn-sm btn-ghost" title={r.comment || 'Add comment/tags'}>
                          <Tag className="w-3.5 h-3.5" />
                        </button>
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
                        <button onClick={() => remove(r)} aria-label={`Delete record ${r.name || '@'}`} className="btn-sm text-danger-500 hover:bg-danger-500/[0.07] rounded-[14px] transition-colors">
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>}
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="px-5 py-3 border-t border-line flex items-center justify-between text-xs text-muted">
          <span>{paged.total} record{paged.total !== 1 ? 's' : ''}</span>
          <PaginationControls pagination={paged.pagination} />
        </div>
      </motion.div>

      {metaRecord && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4" role="dialog" aria-modal="true" aria-label="Record metadata">
          <div className="bg-surface rounded-2xl border border-line p-5 w-full max-w-md space-y-3">
            <h2 className="font-semibold">Metadata for {metaRecord.name || '@'} {metaRecord.record_type}</h2>
            <div>
              <label className="form-label" htmlFor="record-comment">Comment</label>
              <input id="record-comment" className="input" value={metaComment} onChange={e => setMetaComment(e.target.value)} placeholder="Why this record exists" />
            </div>
            <div>
              <label className="form-label" htmlFor="record-tags">Tags (comma separated)</label>
              <input id="record-tags" className="input" value={metaTags} onChange={e => setMetaTags(e.target.value)} placeholder="web, prod" />
            </div>
            <div className="flex justify-end gap-2">
              <button className="btn-ghost" onClick={() => setMetaRecord(null)}>Cancel</button>
              <button className="btn-primary" onClick={saveMetadata}>Save</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
