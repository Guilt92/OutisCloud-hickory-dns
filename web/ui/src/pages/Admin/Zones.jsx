import React from 'react'
import axios from 'axios'
import { Link } from 'react-router-dom'

export default function Zones(){
  const [zones, setZones] = React.useState([])
  const [domain, setDomain] = React.useState('')

  const load = async () => {
    try { const r = await axios.get('/api/v1/zones'); setZones(r.data || []) } catch (e) { console.error('Error loading zones', e) }
  }

  React.useEffect(()=>{ const token = localStorage.getItem('token'); if (token) axios.defaults.headers.common['Authorization'] = `Bearer ${token}`; load() }, [])

  const create = async () => { try { await axios.post('/api/v1/zones', { domain }); setDomain(''); load() } catch (e) { alert('Error creating zone') } }

  return (
    <div className="bg-white shadow rounded p-6">
      <h3 className="text-lg font-semibold mb-3">Zones</h3>
      <div className="grid gap-2 mb-4 max-w-md">
        <input className="border rounded px-3 py-2" placeholder="domain" value={domain} onChange={e=>setDomain(e.target.value)} />
        <button className="bg-blue-600 text-white px-4 py-2 rounded" onClick={create}>Create Zone</button>
      </div>

      <table className="w-full table-auto border-collapse">
        <thead>
          <tr className="bg-gray-50"><th className="border px-2 py-1">ID</th><th className="border px-2 py-1">Domain</th><th className="border px-2 py-1">Actions</th></tr>
        </thead>
        <tbody>
          {zones.map(z => (
            <tr key={z.id}><td className="border px-2 py-1">{z.id}</td><td className="border px-2 py-1">{z.domain}</td><td className="border px-2 py-1"><Link to={`/admin/zones/${z.id}/records`} className="text-blue-600">Manage Records</Link></td></tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
