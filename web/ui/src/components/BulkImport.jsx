import React from 'react'
import { Upload } from 'lucide-react'
import api from '../api/client'

export default function BulkImport({ endpoint, onComplete, accept='text/csv,application/json' }){
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

  const submit = async ()=>{
    if (!file) return alert('Select a file')
    setLoading(true)
    try {
      const text = await file.text()
      let payload = null
      if (file.type === 'application/json' || file.name.endsWith('.json')) payload = JSON.parse(text)
      else payload = parseCSV(text)
      await api.post(endpoint, payload)
      onComplete && onComplete()
      setFile(null)
    } catch (e) { console.error(e); alert('Import failed: ' + (e.message || '')) }
    setLoading(false)
  }

  return (
    <div className="flex items-center gap-2">
      <label className="flex items-center gap-1.5 text-sm text-gray-600 dark:text-gray-400 cursor-pointer hover:text-gray-800 dark:hover:text-gray-200 px-3 py-1.5 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors border border-dashed border-gray-300 dark:border-gray-600">
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
