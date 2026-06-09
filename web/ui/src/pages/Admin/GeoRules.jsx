import React from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import api from '../../api/client'
import { Globe, Plus, Trash2, MapPin, Play, Edit3 } from 'lucide-react'

export default function GeoRules(){
  const [rules, setRules] = React.useState([])
  const [zones, setZones] = React.useState([])
  const [zone, setZone] = React.useState('')
  const [matchType, setMatchType] = React.useState('country')
  const [matchValue, setMatchValue] = React.useState('US')
  const [target, setTarget] = React.useState('192.0.2.1')
  const [priority, setPriority] = React.useState(0)
  const [enabled, setEnabled] = React.useState(true)
  const [recordName, setRecordName] = React.useState('')
  const [recordType, setRecordType] = React.useState('')
  const [editingRule, setEditingRule] = React.useState(null)
  const [testIp, setTestIp] = React.useState('8.8.8.8')
  const [resolveResult, setResolveResult] = React.useState(null)
  const [loading, setLoading] = React.useState(false)
  const [testing, setTesting] = React.useState(false)

  const load = async () => {
    setLoading(true)
    try { 
      const r = await api.get('/api/v1/georules'); 
      setRules(r.data || []) 
    } catch (e) { console.error(e) }
    try { 
      const z = await api.get('/api/v1/zones'); 
      setZones(z.data || []) 
    } catch (e) { console.warn('zones load failed', e) }
    setLoading(false)
  }
  React.useEffect(()=>{ 
    const t=localStorage.getItem('token')
    if(t) api.setToken(t)
    load() 
  }, [])

  const create = async () => {
    if (!zone || !matchValue || !target) return
    try {
      if (editingRule) {
        await api.put(`/api/v1/georules/${editingRule.id}`, {
          zone_id: zone, match_type: matchType, match_value: matchValue, target,
          priority, enabled, record_name: recordName || null, record_type: recordType || null
        });
      } else {
        await api.post('/api/v1/georules', { 
          zone_id: zone, match_type: matchType, match_value: matchValue, target,
          priority, enabled, record_name: recordName || null, record_type: recordType || null
        });
      }
      // reset form
      setZone(''); setPriority(0); setEnabled(true); setRecordName(''); setRecordType('');
      setEditingRule(null);
      load()
    } catch (e) { alert('Error saving rule') }
  }

  const remove = async (id)=>{ 
    if(!confirm('Delete rule?')) return; 
    try { 
      await api.delete(`/api/v1/georules/${id}`); 
      load() 
    } catch(e){ alert('Delete failed') } 
  }

  const startEditRule = (r) => {
    setEditingRule(r);
    setZone(r.zone_id);
    setMatchType(r.match_type);
    setMatchValue(r.match_value);
    setTarget(r.target);
    setPriority(r.priority || 0);
    setEnabled(r.enabled);
    setRecordName(r.record_name || '');
    setRecordType(r.record_type || '');
  }

  const testResolve = async () => {
    if (!zone) { alert('Select a zone'); return }
    setTesting(true)
    try { 
      const r = await api.post('/api/v1/georules/resolve', { zone_id: zone, client_ip: testIp }); 
      setResolveResult(r.data) 
    } catch (e) { alert('Error resolving') }
    setTesting(false)
  }

  const getZoneName = (zoneId) => {
    const z = zones.find(z => z.id === zoneId)
    return z ? z.domain : zoneId
  }

  const toggleEnabled = async (rule) => {
    try {
      await api.put(`/api/v1/georules/${rule.id}`, { enabled: !rule.enabled });
      load();
    } catch (e) {
      alert('Failed to update rule');
    }
  }

  return (
    <div className="space-y-6">
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        className="card"
      >
        <div className="p-5">
          <div className="flex items-center gap-3 mb-5">
            <div className="icon-box bg-green-100 dark:bg-green-900/30">
              <Globe className="w-5 h-5 text-green-600 dark:text-green-400" />
            </div>
            <h3 className="text-lg font-bold text-gray-900 dark:text-white">GeoDNS Rules</h3>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div>
              <label className="form-label">Zone</label>
              <select className="select" value={zone} onChange={e=>setZone(e.target.value)}>
                <option value="">Select a zone</option>
                {zones.map(z=> <option key={z.id} value={z.id}>{z.domain}</option>)}
              </select>
            </div>
            <div>
              <label className="form-label">Match Type</label>
              <select className="select" value={matchType} onChange={e=>setMatchType(e.target.value)}>
                <option value="country">Country</option>
                <option value="region">Region</option>
                <option value="continent">Continent</option>
              </select>
            </div>
            <div>
              <label className="form-label">Match Value</label>
              <input className="input" placeholder="e.g., US, EU, NA" value={matchValue} onChange={e=>setMatchValue(e.target.value)} />
            </div>
            <div>
              <label className="form-label">Target IP</label>
              <input className="input" placeholder="e.g., 192.0.2.1" value={target} onChange={e=>setTarget(e.target.value)} />
            </div>
            <div>
              <label className="form-label">Priority</label>
              <input type="number" min="0" className="input" value={priority} onChange={e=>setPriority(parseInt(e.target.value)||0)} />
            </div>
            <div className="flex items-end pb-0.5">
              <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300 cursor-pointer select-none">
                <input type="checkbox" checked={enabled} onChange={e=>setEnabled(e.target.checked)} className="w-4 h-4 rounded border-gray-300 dark:border-gray-600 text-green-600 focus:ring-green-500" />
                Enabled
              </label>
            </div>
            <div>
              <label className="form-label">Record Name</label>
              <input className="input" placeholder="optional" value={recordName} onChange={e=>setRecordName(e.target.value)} />
            </div>
            <div>
              <label className="form-label">Record Type</label>
              <input className="input" placeholder="e.g., A, AAAA" value={recordType} onChange={e=>setRecordType(e.target.value)} />
            </div>
          </div>
          <div className="form-actions mt-4">
            <button className="btn-success" onClick={create}>
              <Plus className="w-4 h-4" />
              {editingRule ? 'Update Rule' : 'Add Rule'}
            </button>
            {editingRule && (
              <button className="btn-secondary" onClick={()=>setEditingRule(null)}>Cancel</button>
            )}
          </div>
        </div>
      </motion.div>

      {/* Test Resolution */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="card p-5"
      >
        <div className="flex items-center gap-3 mb-4">
          <div className="icon-box bg-blue-100 dark:bg-blue-900/30">
            <Play className="w-5 h-5 text-blue-600 dark:text-blue-400" />
          </div>
          <h3 className="text-lg font-bold text-gray-900 dark:text-white">Test Resolution</h3>
        </div>

        <div className="flex flex-wrap items-end gap-3">
          <div className="flex-1 min-w-[200px]">
            <label className="form-label">Client IP Address</label>
            <input className="input" placeholder="e.g., 8.8.8.8" value={testIp} onChange={e=>setTestIp(e.target.value)} />
          </div>
          <button className="btn-primary" onClick={testResolve} disabled={testing}>
            <Play className={`w-4 h-4 ${testing ? 'animate-pulse' : ''}`} />
            Resolve
          </button>
        </div>

        <AnimatePresence>
          {resolveResult && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="mt-4"
            >
              <div className="bg-gray-900 dark:bg-black rounded-lg p-4 overflow-x-auto border border-gray-800">
                <pre className="text-green-400 text-sm font-mono">{JSON.stringify(resolveResult, null, 2)}</pre>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>

      {/* Rules Table */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.15 }}
        className="card overflow-hidden"
      >
        {rules.length === 0 ? (
          <div className="p-12 text-center">
            <Globe className="w-14 h-14 text-gray-300 dark:text-gray-600 mx-auto mb-3" />
            <p className="text-gray-500 dark:text-gray-400">No GeoDNS rules configured yet</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="table">
              <thead>
                <tr>
                  <th>Zone</th>
                  <th>Match</th>
                  <th>Value</th>
                  <th>Target</th>
                  <th>Pri</th>
                  <th>Enabled</th>
                  <th>Record</th>
                  <th className="text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((r, i) => (
                  <motion.tr
                    key={r.id}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: i * 0.03 }}
                  >
                    <td className="font-medium text-gray-900 dark:text-white">{getZoneName(r.zone_id)}</td>
                    <td>
                      <span className="badge badge-info capitalize">{r.match_type}</span>
                    </td>
                    <td>
                      <div className="flex items-center gap-1.5">
                        <MapPin className="w-4 h-4 text-gray-400 dark:text-gray-500 flex-shrink-0" />
                        <span>{r.match_value}</span>
                      </div>
                    </td>
                    <td className="font-mono text-gray-600 dark:text-gray-300">{r.target}</td>
                    <td className="text-gray-500 dark:text-gray-400">{r.priority}</td>
                    <td>
                      <input type="checkbox" checked={r.enabled} onChange={()=>toggleEnabled(r)} className="w-4 h-4 rounded border-gray-300 dark:border-gray-600 text-green-600 focus:ring-green-500" />
                    </td>
                    <td className="text-gray-500 dark:text-gray-400">
                      {r.record_name || '-'}{r.record_type ? `/${r.record_type}` : ''}
                    </td>
                    <td className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        <button onClick={()=>startEditRule(r)} className="btn-sm btn-ghost">
                          <Edit3 className="w-3.5 h-3.5" />
                        </button>
                        <button onClick={()=>remove(r.id)} className="btn-sm text-red-600 hover:bg-red-50 dark:text-red-400 dark:hover:bg-red-900/20 rounded-lg transition-colors">
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
