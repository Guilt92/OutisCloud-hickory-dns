import React from 'react'
import { motion } from 'framer-motion'
import Modal from '../../components/Modal'
import api from '../../api/client'
import { Server, MapPin, Plus, Trash2, RefreshCw, Shield, Clock, FileText, Settings, Check, AlertTriangle } from 'lucide-react'
import { useConfirm } from '../../components/ui'
import Notifications from '../../components/Notifications'
import { validators } from '../../hooks/useFormValidation'

export default function Servers(){
  const askConfirm = useConfirm()
  const notify = React.useContext(Notifications)
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
    if (!form.name.trim() || !form.address.trim()) {
      notify?.error('Name and IP address are required')
      return
    }
    if (validators.ipAddress(form.address)) {
      notify?.error('Enter a valid IPv4 or IPv6 address')
      return
    }
    if (!Number.isInteger(form.port) || form.port < 1 || form.port > 65535) {
      notify?.error('Port must be between 1 and 65535')
      return
    }
    if (form.min_cache_ttl > form.max_cache_ttl) {
      notify?.error('Minimum cache TTL cannot exceed maximum cache TTL')
      return
    }
    try {
      if (editingServer) {
        await api.put(`/api/v1/servers/${editingServer.id}`, form)
        notify?.success('Server updated')
      } else {
        await api.post('/api/v1/servers', form)
        notify?.success('Server created')
      }
      setShowModal(false)
      load()
    } catch (e) {
      notify?.error(e.response?.data?.error || e.message || 'Error saving server')
    }
  }

  const remove = async (id) => {
    if (!(await askConfirm({ title: 'Delete server?', message: 'It is removed from monitoring. The DNS server itself is not touched.', confirmLabel: 'Delete server' }))) return
    try {
      await api.delete(`/api/v1/servers/${id}`)
      load()
    } catch (e) { notify?.error('Error deleting server') }
  }


  const getStatus = (server) => {
    return server.status === 'running' || server.status === 'disabled' ? server.status : 'unknown'
  }

  const statusLabel = (status) => {
    if (status === 'running') return 'Running'
    if (status === 'disabled') return 'Disabled'
    return 'Unknown'
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
          <div className="icon-box">
            <Server className="w-5 h-5" />
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
          <Server className="w-14 h-14 text-muted/40 mx-auto mb-3" />
          <h3 className="text-lg font-semibold text-ink mb-1">No DNS Servers Configured</h3>
          <p className="text-muted mb-5">Add your first DNS server to start serving zone data</p>
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
                    <span className={`dot ${getStatus(server) === 'running' ? 'bg-success-500' : 'bg-muted/40'}`} aria-hidden="true" />
                    <div>
                      <h3 className="text-lg font-bold text-ink">{server.name}</h3>
                      <p className="text-sm text-muted">{server.address}:{server.port || 53}</p>
                    </div>
                  </div>
                  <span className={`badge ${getStatus(server) === 'running' ? 'badge-success' : 'badge-default'}`}>
                    {statusLabel(getStatus(server))}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-3 mb-4">
                  <div className="flex items-center gap-2 text-sm text-muted">
                    <MapPin className="w-4 h-4 text-muted flex-shrink-0" />
                    <span>{server.region || 'No region'}</span>
                  </div>
                  <div className="flex items-center gap-2 text-sm text-muted">
                    <Clock className="w-4 h-4 text-muted flex-shrink-0" />
                    <span>Cache: {server.min_cache_ttl || 60}s - {server.max_cache_ttl || 3600}s</span>
                  </div>
                  <div className="flex items-center gap-2 text-sm text-muted">
                    {server.dnssec ? <Shield className="w-4 h-4 text-success-500 flex-shrink-0" /> : <AlertTriangle className="w-4 h-4 text-warning-500 flex-shrink-0" />}
                    <span>{server.dnssec ? 'DNSSEC Enabled' : 'DNSSEC Disabled'}</span>
                  </div>
                  <div className="flex items-center gap-2 text-sm text-muted">
                    <FileText className="w-4 h-4 text-muted flex-shrink-0" />
                    <span>{server.enable_logging !== false ? 'Logging On' : 'Logging Off'}</span>
                  </div>
                </div>

                <div className="flex items-center gap-2 pt-4 border-t border-line">
                  <span className="text-xs text-muted flex-1">Process runs externally; manage config only</span>
                  <button onClick={() => openEdit(server)} aria-label={`Configure ${server.name}`} className="btn-secondary btn-sm">
                    <Settings className="w-3.5 h-3.5" />
                    Config
                  </button>
                  <button onClick={() => remove(server.id)} aria-label={`Delete ${server.name}`} className="btn-sm text-danger-500 hover:bg-danger-500/[0.07] rounded-[14px]">
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      )}

      <Modal open={showModal} onClose={() => setShowModal(false)} title={editingServer ? 'Edit server' : 'Add DNS server'}>
              <div className="p-6 space-y-5">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label htmlFor="server-name" className="form-label">Server Name</label>
                    <input id="server-name" className="input" placeholder="e.g., US-East-1 Primary" value={form.name} onChange={e=>setForm({...form, name: e.target.value})} />
                  </div>
                  <div>
                    <label htmlFor="server-address" className="form-label">IP Address</label>
                    <input id="server-address" className="input" placeholder="e.g., 192.168.1.10" value={form.address} onChange={e=>setForm({...form, address: e.target.value})} />
                  </div>
                  <div>
                    <label htmlFor="server-port" className="form-label">Port</label>
                    <input id="server-port" type="number" className="input" placeholder="53" value={form.port} onChange={e=>setForm({...form, port: parseInt(e.target.value) || 53})} />
                  </div>
                  <div>
                    <label htmlFor="server-region" className="form-label">Region</label>
                    <input id="server-region" className="input" placeholder="e.g., us-east" value={form.region} onChange={e=>setForm({...form, region: e.target.value})} />
                  </div>
                </div>

                <div className="border-t border-line pt-5">
                  <h4 className="text-sm font-semibold text-ink mb-4">DNS Configuration</h4>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                      <label htmlFor="server-max-cache-ttl" className="form-label">Max Cache TTL (seconds)</label>
                      <input id="server-max-cache-ttl" type="number" className="input" value={form.max_cache_ttl} onChange={e=>setForm({...form, max_cache_ttl: parseInt(e.target.value) || 3600})} />
                    </div>
                    <div>
                      <label htmlFor="server-min-cache-ttl" className="form-label">Min Cache TTL (seconds)</label>
                      <input id="server-min-cache-ttl" type="number" className="input" value={form.min_cache_ttl} onChange={e=>setForm({...form, min_cache_ttl: parseInt(e.target.value) || 60})} />
                    </div>
                  </div>
                </div>

                <div className="border-t border-line pt-5">
                  <h4 className="text-sm font-semibold text-ink mb-4">Security & Logging</h4>
                  <div className="space-y-3">
                    {[
                      { key: 'enabled', label: 'Enable Server', desc: 'Allow this server to respond to queries' },
                      { key: 'dnssec', label: 'Enable DNSSEC', desc: 'Sign zone data with DNSSEC' },
                      { key: 'enable_logging', label: 'Enable Query Logging', desc: 'Log all DNS queries received' },
                    ].map(item => (
                      <label key={item.key} className="flex items-center gap-3 p-3 rounded-[14px] border border-line cursor-pointer hover:bg-ink/5 transition-colors">
                        <input
                          type="checkbox"
                          checked={form[item.key]}
                          onChange={e=>setForm({...form, [item.key]: e.target.checked})}
                          className="w-4 h-4 rounded border-line"
                        />
                        <div>
                          <span className="font-medium text-sm text-ink">{item.label}</span>
                          <p className="text-xs text-muted">{item.desc}</p>
                        </div>
                      </label>
                    ))}
                  </div>
                </div>
              </div>

              <div className="flex items-center justify-end gap-2 px-6 py-4 border-t border-line bg-surface-2">
                <button onClick={() => setShowModal(false)} className="btn-secondary">Cancel</button>
                <button onClick={save} className="btn-primary">
                  <Check className="w-4 h-4" />
                  {editingServer ? 'Update' : 'Create'} Server
                </button>
              </div>
      </Modal>
    </div>
  )
}
