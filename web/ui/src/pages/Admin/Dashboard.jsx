import React from 'react'
import api from '../../api'

export default function Dashboard(){
  const [stats, setStats] = React.useState(null)
  const [servers, setServers] = React.useState([])

  const load = async ()=>{
    try {
      const r = await api.get('/api/v1/admin/stats')
      setStats(r.data)
    } catch(e){ console.warn('stats', e) }
    try { const s = await api.get('/api/v1/servers'); setServers(s.data||[]) } catch(e){}
  }

  React.useEffect(()=>{ const t=localStorage.getItem('token'); if(t) api.setToken(t); load() }, [])

  return (
    <div className="bg-white shadow rounded p-6">
      <h3 className="text-lg font-semibold mb-4">Admin Dashboard</h3>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="p-4 border rounded">
          <div className="text-sm text-gray-500">Zones</div>
          <div className="text-2xl font-bold">{stats ? stats.zones : '-'}</div>
        </div>
        <div className="p-4 border rounded">
          <div className="text-sm text-gray-500">Records</div>
          <div className="text-2xl font-bold">{stats ? stats.records : '-'}</div>
        </div>
        <div className="p-4 border rounded">
          <div className="text-sm text-gray-500">Active Servers</div>
          <div className="text-2xl font-bold">{servers.length}</div>
        </div>
      </div>

      <div>
        <h4 className="font-semibold mb-2">Servers</h4>
        <table className="w-full table-auto border-collapse">
          <thead><tr className="bg-gray-50"><th className="border px-2 py-1">ID</th><th className="border px-2 py-1">Name</th><th className="border px-2 py-1">Address</th><th className="border px-2 py-1">Status</th></tr></thead>
          <tbody>
            {servers.map(s=> (
              <tr key={s.id}><td className="border px-2 py-1">{s.id}</td><td className="border px-2 py-1">{s.name}</td><td className="border px-2 py-1">{s.address}</td><td className="border px-2 py-1">{s.status||'unknown'}</td></tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
