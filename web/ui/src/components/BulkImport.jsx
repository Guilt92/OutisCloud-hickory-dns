import React from 'react'
import { Upload } from 'lucide-react'
import api from '../api/client'
import Notifications from './Notifications'

export default function BulkImport({ endpoint, onComplete, accept='text/csv,application/json' }){
  const notify = React.useContext(Notifications)
  const [file, setFile] = React.useState(null)
  const [loading, setLoading] = React.useState(false)

  const parseCSV = (text) => {
    const lines = text.trim().split(/\r?\n/)
    const headers = lines[0].split(',').map(h=>h.trim())
    return lines.slice(1).map(l => {
      const cols = l.split(',').map(c=>c.trim())
      const obj = {}
      headers.forEach((h,i)=> obj[h]=cols[i])
      return obj
    })
  }

  // Normalise CSV/JSON rows into what POST /zones/{id}/import expects:
  // { records: [{ name, record_type, value, ttl?, priority? }] }
  const toRecords = (payload) => {
    const rows = Array.isArray(payload) ? payload : (payload && payload.records) || []
    return rows.map(r => {
      const rec = {
        name: String(r.name ?? '').trim(),
        record_type: String(r.record_type ?? r.type ?? '').trim(),
        value: String(r.value ?? '').trim(),
      }
      const ttl = parseInt(r.ttl, 10)
      if (!Number.isNaN(ttl)) rec.ttl = ttl
      const pr = parseInt(r.priority, 10)
      if (!Number.isNaN(pr)) rec.priority = pr
      return rec
    })
  }

  const submit = async ()=>{
    if (!file) return notify?.warning('Select a file')
    setLoading(true)
    try {
      const text = await file.text()
      let payload = null
      if (file.type === 'application/json' || file.name.endsWith('.json')) payload = JSON.parse(text)
      else payload = parseCSV(text)
      const records = toRecords(payload)
      if (records.length === 0) throw new Error('no records found in file')
      const res = await api.post(endpoint, { records })
      const d = res.data || {}
      if (typeof d.imported === 'number') notify?.success(`Imported ${d.imported} record(s)` + (d.skipped ? `, skipped ${d.skipped} duplicate(s)` : ''))
      onComplete && onComplete()
      setFile(null)
    } catch (e) {
      console.error(e)
      const d = e.response?.data
      notify?.error('Import failed: ' + (d?.details || d?.error || e.message || ''))
    }
    setLoading(false)
  }

  return (
    <div className="flex items-center gap-2">
      <label className="flex items-center gap-1.5 text-sm text-muted cursor-pointer hover:text-gray-800 dark:hover:text-gray-200 px-3 py-1.5 rounded-lg hover:bg-ink/5 transition-colors border border-dashed border-line">
        <Upload className="w-4 h-4" />
        <span className="truncate max-w-[120px]">{file ? file.name : 'Choose file'}</span>
        <input type="file" accept={accept} onChange={e=>{setFile(e.target.files[0]); e.target.value=''}} className="hidden" />
      </label>
      <button className="btn-sm btn-primary" onClick={submit} disabled={loading || !file}>
        {loading ? 'Importing...' : 'Import'}
      </button>
    </div>
  )
}
