import React from 'react'
import axios from 'axios'
import { useParams } from 'react-router-dom'

export default function Records(){
  const { id } = useParams()
  const zoneId = id
  const [records, setRecords] = React.useState([])
  const [name, setName] = React.useState('')
  const [type, setType] = React.useState('A')
  const [value, setValue] = React.useState('')
  const [ttl, setTtl] = React.useState(3600)

  const load = async () => { try { const r = await axios.get(`/api/v1/zones/${zoneId}/records`); setRecords(r.data || []) } catch (e) { console.error('load records', e) } }
  React.useEffect(()=>{ const token = localStorage.getItem('token'); if (token) axios.defaults.headers.common['Authorization'] = `Bearer ${token}`; load() }, [zoneId])

  const create = async () => { try { await axios.post(`/api/v1/zones/${zoneId}/records`, { name, record_type: type, value, ttl }); setName(''); setValue(''); setTtl(3600); load() } catch (e) { alert('create failed') } }
  const remove = async (rid) => { try { await axios.delete(`/api/v1/zones/${zoneId}/records/${rid}`); load() } catch (e) { alert('delete failed') } }

  return (
    <div className="bg-white shadow rounded p-6 max-w-4xl">
      <h3 className="text-lg font-semibold mb-3">Records for zone {zoneId}</h3>
      <div className="grid gap-2 mb-4 max-w-md">
        <input className="border rounded px-3 py-2" placeholder="name" value={name} onChange={e=>setName(e.target.value)} />
        <input className="border rounded px-3 py-2" placeholder="type" value={type} onChange={e=>setType(e.target.value)} />
        <input className="border rounded px-3 py-2" placeholder="value" value={value} onChange={e=>setValue(e.target.value)} />
        <input className="border rounded px-3 py-2" placeholder="ttl" value={ttl} onChange={e=>setTtl(Number(e.target.value))} />
        <button className="bg-blue-600 text-white px-4 py-2 rounded" onClick={create}>Create Record</button>
      </div>

      <table className="w-full table-auto border-collapse">
        <thead>
          <tr className="bg-gray-50"><th className="border px-2 py-1">ID</th><th className="border px-2 py-1">Name</th><th className="border px-2 py-1">Type</th><th className="border px-2 py-1">Value</th><th className="border px-2 py-1">TTL</th><th className="border px-2 py-1">Actions</th></tr>
        </thead>
        <tbody>
          {records.map(r => (
            <tr key={r.id}><td className="border px-2 py-1">{r.id}</td><td className="border px-2 py-1">{r.name}</td><td className="border px-2 py-1">{r.record_type}</td><td className="border px-2 py-1">{r.value}</td><td className="border px-2 py-1">{r.ttl}</td><td className="border px-2 py-1"><button className="bg-red-500 text-white px-2 py-1 rounded" onClick={()=>remove(r.id)}>Delete</button></td></tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
