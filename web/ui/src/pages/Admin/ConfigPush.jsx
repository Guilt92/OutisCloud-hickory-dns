import React from 'react'
import { motion } from 'framer-motion'
import api from '../../api/client'
import { Upload, Server, ArrowRight } from 'lucide-react'

export default function ConfigPush(){
  const [agentId, setAgentId] = React.useState('')
  const [agents, setAgents] = React.useState([])
  const [result, setResult] = React.useState(null)

  React.useEffect(() => {
    const token = localStorage.getItem('token')
    if (token) api.setToken(token)
    api.get('/api/v1/agents').then(r => setAgents(r.data || [])).catch(() => {})
  }, [])

  const push = async () => {
    try { const r = await api.post('/api/v1/config/push', { agent_id: agentId, zone_id: '', zone_config: {} }); setResult(r.data) } catch (e) { setResult(e.response?.data || { success: false, message: e.message }) }
  }

  return (
    <div className="page space-y-6">
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        className="section-header"
      >
        <div className="flex items-center gap-3">
          <div className="icon-box">
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
          <div className="flex items-center gap-3 pb-3 border-b border-line">
            <Server className="w-5 h-5 text-indigo-500" />
            <span className="font-medium text-ink">Agent & Zone Configuration</span>
          </div>
          <div className="space-y-3">
            <div>
              <label className="form-label">Agent</label>
              <select className="select" aria-label="Agent" value={agentId} onChange={e=>setAgentId(e.target.value)}>
                <option value="">Select an agent</option>
                <option value="all">All enabled agents</option>
                {agents.map(a => <option key={a.id} value={a.id} disabled={!a.enabled}>{a.name} ({a.addr}){a.enabled ? '' : ' - disabled'}</option>)}
              </select>
              <p className="text-xs text-gray-500 mt-1">Agents pull the signed configuration bundle; this asks them to do it on their next heartbeat.</p>
            </div>
            <button className="btn-primary w-full mt-1" onClick={push} disabled={!agentId}>
              <ArrowRight className="w-4 h-4" />
              Push Config
            </button>
          </div>
          {result && (
            <div className="mt-4 pt-4 border-t border-line">
              <p className="text-sm font-medium text-ink/80 mb-2">Result</p>
              <pre className="bg-gray-50 dark:bg-gray-900 text-ink p-3 rounded-lg text-xs font-mono overflow-x-auto border border-line">{JSON.stringify(result, null, 2)}</pre>
            </div>
          )}
        </div>
      </motion.div>
    </div>
  )
}
