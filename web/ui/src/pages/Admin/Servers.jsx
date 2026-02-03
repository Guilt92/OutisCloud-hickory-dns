import React from 'react'
import axios from 'axios'

export default function Servers(){
  const [servers, setServers] = React.useState([])
  const [name, setName] = React.useState('')
  const [addr, setAddr] = React.useState('')
  const [region, setRegion] = React.useState('')

  const load = async () => {
    try {
      const r = await axios.get('/api/v1/servers')
      setServers(r.data || [])
    } catch (e) { console.error(e) }
  }

  React.useEffect(()=>{ const token = localStorage.getItem('token'); if(token) axios.defaults.headers.common['Authorization'] = `Bearer ${token}`; load() }, [])

  const create = async () => {
    try { await axios.post('/api/v1/servers', { name, address: addr, region: region || null }); setName(''); setAddr(''); setRegion(''); load() } catch (e) { alert('Error creating server') }
  }

  return (
    <div className="bg-white shadow rounded p-6">
      <h3 className="text-lg font-semibold mb-3">Servers</h3>
      <div className="grid gap-2 mb-4 max-w-md">
        <input className="border rounded px-3 py-2" placeholder="name" value={name} onChange={e=>setName(e.target.value)} />
        <input className="border rounded px-3 py-2" placeholder="address" value={addr} onChange={e=>setAddr(e.target.value)} />
        <input className="border rounded px-3 py-2" placeholder="region (optional)" value={region} onChange={e=>setRegion(e.target.value)} />
        <button className="bg-blue-600 text-white px-4 py-2 rounded" onClick={create}>Create Server</button>
      </div>

      <table className="w-full table-auto border-collapse">
        <thead>
          <tr className="bg-gray-50"><th className="border px-2 py-1">ID</th><th className="border px-2 py-1">Name</th><th className="border px-2 py-1">Address</th><th className="border px-2 py-1">Region</th></tr>
        </thead>
        <tbody>
          {servers.map(s => (
            <tr key={s.id}><td className="border px-2 py-1">{s.id}</td><td className="border px-2 py-1">{s.name}</td><td className="border px-2 py-1">{s.address}</td><td className="border px-2 py-1">{s.region || '-'}</td></tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
