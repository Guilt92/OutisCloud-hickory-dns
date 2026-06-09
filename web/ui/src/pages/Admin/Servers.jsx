import React from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import api from '../../api/client'
import { Server, MapPin, Plus, Trash2, RefreshCw, Play, Square, Shield, Clock, FileText, Settings, X, Check, AlertTriangle } from 'lucide-react'

export default function Servers(){
  const [servers, setServers] = React.useState([])
  const [loading, setLoading] = React.useState(false)
  const [showModal, setShowModal] = React.useState(false)
  const [editingServer, setEditingServer] = React.useState(null)
  const [form, setForm] = React.useState({
    name: '', address: '', port: 53, region: '',
    enabled: true, dnssec: false, enable_logging: true,
    max_cache_ttl: 3600, min_cache_ttl: 60
  })
  // DNS control is handled externally; only configuration is managed here

  const load = async () => {
    setLoading(true)
    try {
      const r = await api.get('/api/v1/servers')
      setServers(r.data || [])
    } catch (e) { console.error(e) }
    setLoading(false)
  }

  React.useEffect(()=>{ 
    const token = localStorage.getItem('token')
    if(token) api.setToken(token)
    load() 
  }, [])

  const openCreate = () => {
    setForm({
      name: '', address: '', port: 53, region: '',
      enabled: true, dnssec: false, enable_logging: true,
      max_cache_ttl: 3600, min_cache_ttl: 60
    })
    setEditingServer(null)
    setShowModal(true)
  }

  const openEdit = (server) => {
    setForm({
      name: server.name,
      address: server.address,
      port: server.port || 53,
      region: server.region || '',
      enabled: server.enabled !== false,
      dnssec: server.dnssec === true,
      enable_logging: server.enable_logging !== false,
      max_cache_ttl: server.max_cache_ttl || 3600,
      min_cache_ttl: server.min_cache_ttl || 60
    })
    setEditingServer(server)
    setShowModal(true)
  }

  const save = async () => {
    if (!form.name || !form.address) return
    try { 
      if (editingServer) {
        // Update - for now just recreate
      }
      await api.post('/api/v1/servers', form)
      setShowModal(false)
      load() 
    } catch (e) { alert('Error saving server') }
  }

  const remove = async (id) => {
    if (!confirm('Delete this server?')) return
    try {
      await api.delete(`/api/v1/servers/${id}`)
      load()
    } catch (e) { alert('Error deleting server') }
  }


  const getStatus = (server) => {
    return server.status === 'running' ? 'running' : 'stopped'
  }

  return (
    <div className="page space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        className="section-header"
      >
        <div className="flex items-center gap-3">
          <div className="icon-box bg-gradient-to-br from-blue-600 to-blue-700">
            <Server className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="section-title">DNS Server Management</h1>
            <p className="section-desc">Configure and manage multiple DNS server instances</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={load} className="btn-secondary btn-sm" disabled={loading}>
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button onClick={openCreate} className="btn-primary">
            <Plus className="w-4 h-4" />
            Add Server
          </button>
        </div>
      </motion.div>

      {servers.length === 0 ? (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="card p-12 text-center">
          <Server className="w-14 h-14 text-gray-300 dark:text-gray-600 mx-auto mb-3" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-1">No DNS Servers Configured</h3>
          <p className="text-gray-500 dark:text-gray-400 mb-5">Add your first DNS server to start serving zone data</p>
          <button onClick={openCreate} className="btn-primary">
            <Plus className="w-4 h-4" />
            Add Server
          </button>
        </motion.div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {servers.map((server, i) => (
            <motion.div
              key={server.id}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.1 }}
              className="card overflow-hidden"
            >
              <div className="p-5">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div className={`w-3 h-3 rounded-full ${getStatus(server) === 'running' ? 'bg-green-500' : 'bg-gray-300 dark:bg-gray-600'}`}></div>
                    <div>
                      <h3 className="text-lg font-bold text-gray-900 dark:text-white">{server.name}</h3>
                      <p className="text-sm text-gray-500 dark:text-gray-400">{server.address}:{server.port || 53}</p>
                    </div>
                  </div>
                  <span className={`badge ${getStatus(server) === 'running' ? 'badge-success' : 'badge-default'}`}>
                    {getStatus(server) === 'running' ? 'Running' : 'Stopped'}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-3 mb-4">
                  <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300">
                    <MapPin className="w-4 h-4 text-gray-400 flex-shrink-0" />
                    <span>{server.region || 'No region'}</span>
                  </div>
                  <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300">
                    <Clock className="w-4 h-4 text-gray-400 flex-shrink-0" />
                    <span>Cache: {server.min_cache_ttl || 60}s - {server.max_cache_ttl || 3600}s</span>
                  </div>
                  <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300">
                    {server.dnssec ? <Shield className="w-4 h-4 text-green-500 flex-shrink-0" /> : <AlertTriangle className="w-4 h-4 text-yellow-500 flex-shrink-0" />}
                    <span>{server.dnssec ? 'DNSSEC Enabled' : 'DNSSEC Disabled'}</span>
                  </div>
                  <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300">
                    <FileText className="w-4 h-4 text-gray-400 flex-shrink-0" />
                    <span>{server.enable_logging !== false ? 'Logging On' : 'Logging Off'}</span>
                  </div>
                </div>

                <div className="flex items-center gap-2 pt-4 border-t border-gray-100 dark:border-gray-700">
                  <span className="text-xs text-gray-400 dark:text-gray-500 flex-1">Process runs externally; manage config only</span>
                  <button onClick={() => openEdit(server)} className="btn-secondary btn-sm">
                    <Settings className="w-3.5 h-3.5" />
                    Config
                  </button>
                  <button onClick={() => remove(server.id)} className="btn-sm text-red-600 hover:bg-red-50 dark:text-red-400 dark:hover:bg-red-900/20 rounded-lg">
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      )}

      <AnimatePresence>
        {showModal && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4"
            onClick={() => setShowModal(false)}
          >
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="bg-white dark:bg-gray-800 rounded-2xl shadow-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto"
              onClick={e => e.stopPropagation()}
            >
              <div className="flex items-center justify-between px-6 py-5 border-b border-gray-200 dark:border-gray-700">
                <h3 className="text-lg font-bold text-gray-900 dark:text-white">
                  {editingServer ? 'Edit Server' : 'Add DNS Server'}
                </h3>
                <button onClick={() => setShowModal(false)} className="btn-sm btn-ghost"><X className="w-4 h-4" /></button>
              </div>

              <div className="p-6 space-y-5">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="form-label">Server Name</label>
                    <input className="input" placeholder="e.g., US-East-1 Primary" value={form.name} onChange={e=>setForm({...form, name: e.target.value})} />
                  </div>
                  <div>
                    <label className="form-label">IP Address</label>
                    <input className="input" placeholder="e.g., 192.168.1.10" value={form.address} onChange={e=>setForm({...form, address: e.target.value})} />
                  </div>
                  <div>
                    <label className="form-label">Port</label>
                    <input type="number" className="input" placeholder="53" value={form.port} onChange={e=>setForm({...form, port: parseInt(e.target.value) || 53})} />
                  </div>
                  <div>
                    <label className="form-label">Region</label>
                    <input className="input" placeholder="e.g., us-east" value={form.region} onChange={e=>setForm({...form, region: e.target.value})} />
                  </div>
                </div>

                <div className="border-t border-gray-100 dark:border-gray-700 pt-5">
                  <h4 className="text-sm font-semibold text-gray-900 dark:text-white mb-4">DNS Configuration</h4>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                      <label className="form-label">Max Cache TTL (seconds)</label>
                      <input type="number" className="input" value={form.max_cache_ttl} onChange={e=>setForm({...form, max_cache_ttl: parseInt(e.target.value) || 3600})} />
                    </div>
                    <div>
                      <label className="form-label">Min Cache TTL (seconds)</label>
                      <input type="number" className="input" value={form.min_cache_ttl} onChange={e=>setForm({...form, min_cache_ttl: parseInt(e.target.value) || 60})} />
                    </div>
                  </div>
                </div>

                <div className="border-t border-gray-100 dark:border-gray-700 pt-5">
                  <h4 className="text-sm font-semibold text-gray-900 dark:text-white mb-4">Security & Logging</h4>
                  <div className="space-y-3">
                    {[
                      { key: 'enabled', label: 'Enable Server', desc: 'Allow this server to respond to queries' },
                      { key: 'dnssec', label: 'Enable DNSSEC', desc: 'Sign zone data with DNSSEC' },
                      { key: 'enable_logging', label: 'Enable Query Logging', desc: 'Log all DNS queries received' },
                    ].map(item => (
                      <label key={item.key} className="flex items-center gap-3 p-3 rounded-lg border border-gray-200 dark:border-gray-700 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors">
                        <input
                          type="checkbox"
                          checked={form[item.key]}
                          onChange={e=>setForm({...form, [item.key]: e.target.checked})}
                          className="w-4 h-4 rounded border-gray-300 dark:border-gray-600 text-blue-600 focus:ring-blue-500"
                        />
                        <div>
                          <span className="font-medium text-sm text-gray-900 dark:text-white">{item.label}</span>
                          <p className="text-xs text-gray-500 dark:text-gray-400">{item.desc}</p>
                        </div>
                      </label>
                    ))}
                  </div>
                </div>
              </div>

              <div className="flex items-center justify-end gap-2 px-6 py-4 border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50">
                <button onClick={() => setShowModal(false)} className="btn-secondary">Cancel</button>
                <button onClick={save} className="btn-primary">
                  <Check className="w-4 h-4" />
                  {editingServer ? 'Update' : 'Create'} Server
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
