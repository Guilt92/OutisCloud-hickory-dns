import React from 'react'
import api from '../../api'

export default function GeoRules(){
  const [rules, setRules] = React.useState([])
  const [zones, setZones] = React.useState([])
  const [zone, setZone] = React.useState('')
  const [matchType, setMatchType] = React.useState('country')
  const [matchValue, setMatchValue] = React.useState('US')
  const [target, setTarget] = React.useState('192.0.2.1')
  const [testIp, setTestIp] = React.useState('8.8.8.8')
  const [resolveResult, setResolveResult] = React.useState(null)

  const load = async () => {
    try { const r = await api.get('/api/v1/georules'); setRules(r.data || []) } catch (e) { console.error(e) }
    try { const z = await api.get('/api/v1/zones'); setZones(z.data || []) } catch (e) { console.warn('zones load failed', e) }
  }
  React.useEffect(()=>{ const t=localStorage.getItem('token'); if(t) api.setToken(t); load() }, [])

  const create = async () => {
    try { await api.post('/api/v1/georules', { zone_id: zone, match_type: matchType, match_value: matchValue, target }); setZone(''); load() } catch (e) { alert('Error creating rule') }
  }

  const remove = async (id)=>{ if(!confirm('Delete rule?')) return; try { await api.delete(`/api/v1/georules/${id}`); load() } catch(e){ alert('Delete failed') } }

  const testResolve = async () => {
    try { if (!zone) { alert('Select a zone'); return } const r = await api.post('/api/v1/georules/resolve', { zone_id: zone, client_ip: testIp }); setResolveResult(r.data) } catch (e) { alert('Error resolving') }
  }

  return (
    <div className="bg-white shadow rounded p-6">
      <h3 className="text-lg font-semibold mb-3">GeoDNS Rules</h3>
      <div className="grid gap-2 mb-4 max-w-md">
        <select className="border rounded px-3 py-2" value={zone} onChange={e=>setZone(e.target.value)}>
          <option value="">Select a zone</option>
          {zones.map(z=> <option key={z.id} value={z.id}>{z.domain}</option>)}
        </select>
        <select className="border rounded px-3 py-2" value={matchType} onChange={e=>setMatchType(e.target.value)}>
          <option value="country">Country</option>
          <option value="region">Region</option>
          <option value="continent">Continent</option>
        </select>
        <input className="border rounded px-3 py-2" placeholder="match value (e.g., US)" value={matchValue} onChange={e=>setMatchValue(e.target.value)} />
        <input className="border rounded px-3 py-2" placeholder="target IP" value={target} onChange={e=>setTarget(e.target.value)} />
        <button className="bg-blue-600 text-white px-4 py-2 rounded" onClick={create}>Create Rule</button>
      </div>

      <h4 className="font-semibold">Test Rule</h4>
      <div className="grid gap-2 mb-4 max-w-md">
        <input className="border rounded px-3 py-2" placeholder="client IP" value={testIp} onChange={e=>setTestIp(e.target.value)} />
        <button className="bg-blue-600 text-white px-4 py-2 rounded" onClick={testResolve}>Resolve</button>
      </div>
      {resolveResult && <pre className="bg-gray-100 p-3 rounded">{JSON.stringify(resolveResult, null, 2)}</pre>}

      <table className="w-full table-auto border-collapse">
        <thead>
          <tr className="bg-gray-50"><th className="border px-2 py-1">ID</th><th className="border px-2 py-1">Zone</th><th className="border px-2 py-1">Type</th><th className="border px-2 py-1">Value</th><th className="border px-2 py-1">Target</th><th className="border px-2 py-1">Actions</th></tr>
        </thead>
        <tbody>
          {rules.map(r => (
            <tr key={r.id}><td className="border px-2 py-1">{r.id}</td><td className="border px-2 py-1">{r.zone_id}</td><td className="border px-2 py-1">{r.match_type}</td><td className="border px-2 py-1">{r.match_value}</td><td className="border px-2 py-1">{r.target}</td><td className="border px-2 py-1"><button className="text-red-600" onClick={()=>remove(r.id)}>Delete</button></td></tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
