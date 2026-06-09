import React from 'react'
import { motion } from 'framer-motion'
import api from '../../api/client'
import { Upload, Server, ArrowRight } from 'lucide-react'

export default function ConfigPush(){
  const [agentId, setAgentId] = React.useState('')
  const [zoneId, setZoneId] = React.useState('')
  const [result, setResult] = React.useState(null)

  React.useEffect(() => {
    const token = localStorage.getItem('token')
    if (token) api.setToken(token)
  }, [])

  const push = async () => {
    try { const r = await api.post('/api/v1/config/push', { agent_id: agentId, zone_id: zoneId, zone_config: {} }); setResult(r.data) } catch (e) { alert('Error pushing config') }
  }

  return (
    <div className="page space-y-6">
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        className="section-header"
      >
        <div className="flex items-center gap-3">
          <div className="icon-box bg-gradient-to-br from-indigo-500 to-indigo-600">
            <Upload className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="section-title">Push Configuration</h1>
            <p className="section-desc">Deploy zone configuration to remote agents</p>
          </div>
        </div>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        className="card max-w-xl"
      >
        <div className="p-5 space-y-4">
          <div className="flex items-center gap-3 pb-3 border-b border-gray-100 dark:border-gray-700">
            <Server className="w-5 h-5 text-indigo-500" />
            <span className="font-medium text-gray-900 dark:text-white">Agent & Zone Configuration</span>
          </div>
          <div className="space-y-3">
            <div>
              <label className="form-label">Agent ID</label>
              <input className="input" placeholder="Enter agent ID" value={agentId} onChange={e=>setAgentId(e.target.value)} />
            </div>
            <div>
              <label className="form-label">Zone ID</label>
              <input className="input" placeholder="Enter zone ID" value={zoneId} onChange={e=>setZoneId(e.target.value)} />
            </div>
            <button className="btn-primary w-full mt-1" onClick={push}>
              <ArrowRight className="w-4 h-4" />
              Push Config
            </button>
          </div>
          {result && (
            <div className="mt-4 pt-4 border-t border-gray-100 dark:border-gray-700">
              <p className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Result</p>
              <pre className="bg-gray-50 dark:bg-gray-900 text-gray-800 dark:text-gray-200 p-3 rounded-lg text-xs font-mono overflow-x-auto border border-gray-200 dark:border-gray-700">{JSON.stringify(result, null, 2)}</pre>
            </div>
          )}
        </div>
      </motion.div>
    </div>
  )
}
