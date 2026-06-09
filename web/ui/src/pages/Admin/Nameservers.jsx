import React from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import api from '../../api/client'
import Notifications from '../../components/Notifications'
import { Globe, Plus, Trash2, RefreshCw, X, Check, Network, Edit3 } from 'lucide-react'

export default function Nameservers(){
  const [nameservers, setNameservers] = React.useState([])
  const [loading, setLoading] = React.useState(false)
  const [showModal, setShowModal] = React.useState(false)
  const [editingNs, setEditingNs] = React.useState(null)
  const [form, setForm] = React.useState({
    hostname: '', 
    ip_address: '', 
    glue_ip: '',
    sort_order: 0,
    enabled: true
  })
  const notify = React.useContext(Notifications)

  const load = async () => {
    setLoading(true)
    try {
      const r = await api.get('/api/v1/nameservers')
      setNameservers(r.data || [])
    } catch (e) { 
      console.error(e)
      notify?.error('Failed to load nameservers')
    }
    setLoading(false)
  }

  React.useEffect(()=>{ 
    const token = localStorage.getItem('token')
    if(token) api.setToken(token)
    load() 
  }, [])

  const openCreate = () => {
    setForm({
      hostname: '', 
      ip_address: '', 
      glue_ip: '',
      sort_order: nameservers.length + 1,
      enabled: true
    })
    setEditingNs(null)
    setShowModal(true)
  }

  const openEdit = (ns) => {
    setForm({
      hostname: ns.hostname,
      ip_address: ns.ip_address,
      glue_ip: ns.glue_ip || '',
      sort_order: ns.sort_order || 0,
      enabled: ns.enabled !== false
    })
    setEditingNs(ns)
    setShowModal(true)
  }

  const save = async () => {
    if (!form.hostname || !form.ip_address) {
      notify?.error('Hostname and IP address are required')
      return
    }
    try { 
      const payload = {
        hostname: form.hostname,
        ip_address: form.ip_address,
        glue_ip: form.glue_ip || null,
        sort_order: parseInt(form.sort_order) || 0,
        enabled: form.enabled
      }
      
      if (editingNs) {
        await api.put(`/api/v1/nameservers/${editingNs.id}`, payload)
        notify?.success('Nameserver updated')
      } else {
        await api.post('/api/v1/nameservers', payload)
        notify?.success('Nameserver created')
      }
      setShowModal(false)
      load() 
    } catch (e) { 
      const errMsg = e.response?.data?.error || e.message || 'Error saving nameserver';
      notify?.error(errMsg)
    }
  }

  const remove = async (ns) => {
    if (!confirm(`Delete nameserver ${ns.hostname}?`)) return
    try {
      await api.delete(`/api/v1/nameservers/${ns.id}`)
      notify?.success('Nameserver deleted')
      load()
    } catch (e) { 
      const errMsg = e.response?.data?.error || e.message || 'Error deleting nameserver';
      notify?.error(errMsg)
    }
  }

  return (
    <div className="page">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        className="section-header"
      >
        <div className="flex items-center gap-3">
          <div className="icon-box bg-gradient-to-br from-purple-500 to-purple-600">
            <Globe className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="section-title">Authoritative Nameservers</h1>
            <p className="section-desc">Configure the nameservers that serve your zones</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={load}
            className="btn-secondary btn-sm"
            disabled={loading}
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button onClick={openCreate} className="btn-primary">
            <Plus className="w-4 h-4" />
            Add Nameserver
          </button>
        </div>
      </motion.div>

      {/* Info card */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.05 }}
        className="card p-4"
      >
        <p className="text-sm text-gray-600 dark:text-gray-400 flex items-center gap-2">
          <Network className="w-4 h-4 text-purple-500 flex-shrink-0" />
          These nameservers will be automatically added as NS records to all your zones. At least two are recommended for redundancy.
        </p>
      </motion.div>

      {/* Table */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="card overflow-hidden"
      >
        {nameservers.length === 0 ? (
          <div className="p-12 text-center">
            <Globe className="w-14 h-14 text-gray-300 dark:text-gray-600 mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-1">No Nameservers Configured</h3>
            <p className="text-gray-500 dark:text-gray-400 mb-5">Add at least one nameserver to serve your zones</p>
            <button onClick={openCreate} className="btn-primary">
              <Plus className="w-4 h-4" />
              Add Nameserver
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="table">
              <thead>
                <tr>
                  <th>Order</th>
                  <th>Hostname</th>
                  <th>IP Address</th>
                  <th>Glue IP</th>
                  <th>Status</th>
                  <th className="text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {nameservers.map((ns) => (
                  <motion.tr
                    key={ns.id}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                  >
                    <td className="text-gray-500 dark:text-gray-400">{ns.sort_order || '-'}</td>
                    <td>
                      <div className="flex items-center gap-2">
                        <Globe className="w-4 h-4 text-purple-500 flex-shrink-0" />
                        <span className="font-medium text-gray-900 dark:text-white">{ns.hostname}</span>
                      </div>
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        <Network className="w-4 h-4 text-gray-400 flex-shrink-0" />
                        <span className="font-mono text-gray-600 dark:text-gray-300">{ns.ip_address}</span>
                      </div>
                    </td>
                    <td className="font-mono text-gray-500 dark:text-gray-400">{ns.glue_ip || '-'}</td>
                    <td>
                      <span className={`badge ${ns.enabled ? 'badge-success' : 'badge-warning'}`}>
                        {ns.enabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </td>
                    <td className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        <button onClick={() => openEdit(ns)} className="btn-sm btn-ghost">
                          <Edit3 className="w-3.5 h-3.5" />
                        </button>
                        <button onClick={() => remove(ns)} className="btn-sm text-red-600 hover:bg-red-50 dark:text-red-400 dark:hover:bg-red-900/20 rounded-lg transition-colors">
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
              className="bg-white dark:bg-gray-800 rounded-2xl shadow-2xl w-full max-w-lg"
              onClick={e => e.stopPropagation()}
            >
              <div className="flex items-center justify-between p-6 border-b border-gray-200 dark:border-gray-700">
                <h3 className="text-xl font-bold text-gray-900 dark:text-white">
                  {editingNs ? 'Edit Nameserver' : 'Add Nameserver'}
                </h3>
                <button onClick={() => setShowModal(false)} className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg">
                  <X className="w-5 h-5 text-gray-500" />
                </button>
              </div>

              <div className="p-6 space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Hostname *</label>
                  <input 
                    className="w-full border border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded-lg px-4 py-2 focus:ring-2 focus:ring-purple-500 focus:border-transparent" 
                    placeholder="e.g., ns1.example.com" 
                    value={form.hostname} 
                    onChange={e=>setForm({...form, hostname: e.target.value})} 
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">IP Address *</label>
                  <input 
                    className="w-full border border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded-lg px-4 py-2 focus:ring-2 focus:ring-purple-500 focus:border-transparent" 
                    placeholder="e.g., 192.0.2.1" 
                    value={form.ip_address} 
                    onChange={e=>setForm({...form, ip_address: e.target.value})} 
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Glue IP (optional)</label>
                  <input 
                    className="w-full border border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded-lg px-4 py-2 focus:ring-2 focus:ring-purple-500 focus:border-transparent" 
                    placeholder="IP for glue record (if NS is under this zone)" 
                    value={form.glue_ip} 
                    onChange={e=>setForm({...form, glue_ip: e.target.value})} 
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Sort Order</label>
                  <input 
                    type="number"
                    className="w-full border border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded-lg px-4 py-2 focus:ring-2 focus:ring-purple-500 focus:border-transparent" 
                    placeholder="Display order" 
                    value={form.sort_order} 
                    onChange={e=>setForm({...form, sort_order: e.target.value})} 
                  />
                </div>
                <label className="flex items-center space-x-3 p-3 rounded-lg border border-gray-200 dark:border-gray-600 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700">
                  <input 
                    type="checkbox" 
                    checked={form.enabled} 
                    onChange={e=>setForm({...form, enabled: e.target.checked})}
                    className="w-5 h-5 text-purple-600 rounded focus:ring-purple-500"
                  />
                  <span className="font-medium text-gray-900 dark:text-white">Enable Nameserver</span>
                </label>
              </div>

              <div className="flex items-center justify-end space-x-3 p-6 border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700/50">
                <button 
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-lg transition-colors"
                >
                  Cancel
                </button>
                <button 
                  onClick={save}
                  className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors flex items-center space-x-2"
                >
                  <Check className="w-4 h-4" />
                  <span>{editingNs ? 'Update' : 'Create'}</span>
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
