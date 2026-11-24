import React from 'react'
import { parse } from 'csv-parse/browser/esm/sync'
import { apiErrorMessage } from '../api/errors'
import { Upload } from 'lucide-react'
import api from '../api/client'
import Notifications from './Notifications'

export default function BulkImport({ endpoint, onComplete, accept='text/csv,application/json' }){
  const notify = React.useContext(Notifications)
  const [file, setFile] = React.useState(null)
  const [loading, setLoading] = React.useState(false)

  const [preview, setPreview] = React.useState(null)
  const [error, setError] = React.useState('')
  const ready = preview?.endpoint === endpoint && preview.file === file

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
      setError('')
      if (!ready) {
        if (file.size > 1024 * 1024) throw new Error('Select a file of 1 MiB or less.')
        const text = await file.text()
        const payload = file.type === 'application/json' || file.name.toLowerCase().endsWith('.json')
          ? JSON.parse(text)
          : parse(text, { columns: true, bom: true, trim: true, skip_empty_lines: true })
        const records = toRecords(payload)
        if (!records.length || records.length > 5000) throw new Error('Select between 1 and 5,000 records.')
        const { data } = await api.post(endpoint, { records, dry_run: true })
        if (data.dry_run !== true) throw new Error('Preview was not confirmed by the server.')
        setPreview({ endpoint, file, records, count: data.would_import, skipped: data.skipped })
        return
      }
      const res = await api.post(endpoint, { records: preview.records })
      const d = res.data || {}
      if (typeof d.imported === 'number') notify?.success(`Imported ${d.imported} record(s)` + (d.skipped ? `, skipped ${d.skipped} duplicate(s)` : ''))
      onComplete && onComplete()
      setFile(null)
    } catch (e) {
      setPreview(null)
      const d = e.response?.data
      setError(d?.errors?.map(row => `Record ${row.row + 1}: ${row.error?.message || row.error}`).join('\n') || (d?.error === 'quota_exceeded' ? apiErrorMessage(e) : d?.details || d?.error || e.message))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex items-center gap-2">
      <label className="flex items-center gap-1.5 text-sm text-muted cursor-pointer hover:text-ink px-3 py-1.5 rounded-[12px] hover:bg-ink/5 transition-colors border border-dashed border-line focus-within:ring-2 focus-within:ring-accent">
        <Upload className="w-4 h-4" />
        <span className="truncate max-w-[120px]">{file ? file.name : 'Choose file'}</span>
        <input type="file" aria-label="Choose import file" accept={accept} disabled={loading} onChange={e=>{setPreview(null); setError(''); setFile(e.target.files[0]); e.target.value=''}} className="sr-only" />
      </label>
      <button className="btn-sm btn-primary" onClick={submit} disabled={loading || !file}>
        {loading ? 'Working…' : ready ? 'Import' : 'Preview import'}
      </button>
      {ready && <span role="status">{preview.count} to import, {preview.skipped} duplicates</span>}
      {error && <span role="alert" className="whitespace-pre-line">{error}</span>}
    </div>
  )
}
