import React from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import api from '../../api/client'
import Notifications from '../../components/Notifications'
import { Server, Plus, Trash2, RefreshCw, X, Check, Globe, Network } from 'lucide-react'

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
    <div className="space-y-6">
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-gradient-to-r from-purple-600 to-purple-800 rounded-xl p-6 text-white"
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <div className="p-3 bg-white/20 rounded-lg">
              <Globe className="w-8 h-8" />
            </div>
            <div>
              <h2 className="text-2xl font-bold">Authoritative Nameservers</h2>
              <p className="text-purple-100">Configure the nameservers that serve your zones</p>
            </div>
          </div>
          <div className="flex items-center space-x-3">
            <button 
              onClick={load}
              className="p-2 bg-white/20 hover:bg-white/30 rounded-lg transition-colors"
            >
              <RefreshCw className={`w-5 h-5 ${loading ? 'animate-spin' : ''}`} />
            </button>
            <button 
              onClick={openCreate}
              className="flex items-center space-x-2 bg-white text-purple-600 px-4 py-2 rounded-lg hover:bg-purple-50 transition-colors font-medium"
            >
              <Plus className="w-5 h-5" />
              <span>Add Nameserver</span>
            </button>
          </div>
        </div>
      </motion.div>

      <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        <div className="p-4 border-b border-gray-200">
          <p className="text-sm text-gray-600">
            These nameservers will be automatically added as NS records to all your zones. 
            At least two nameservers are recommended for redundancy.
          </p>
        </div>
        
        {nameservers.length === 0 ? (
          <div className="p-12 text-center">
            <Globe className="w-16 h-16 text-gray-300 mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-gray-700 mb-2">No Nameservers Configured</h3>
            <p className="text-gray-500 mb-4">Add at least one nameserver to serve your zones</p>
            <button 
              onClick={openCreate}
              className="inline-flex items-center space-x-2 bg-purple-600 text-white px-4 py-2 rounded-lg hover:bg-purple-700 transition-colors"
            >
              <Plus className="w-5 h-5" />
              <span>Add Nameserver</span>
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Order</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Hostname</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">IP Address</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Glue IP</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {nameservers.map((ns) => (
                  <motion.tr 
                    key={ns.id}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="hover:bg-gray-50"
                  >
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {ns.sort_order || '-'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center space-x-2">
                        <Globe className="w-4 h-4 text-purple-500" />
                        <span className="font-medium text-gray-900">{ns.hostname}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center space-x-2">
                        <Network className="w-4 h-4 text-gray-400" />
                        <span className="text-gray-600 font-mono">{ns.ip_address}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-gray-500 font-mono">
                      {ns.glue_ip || '-'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                        ns.enabled ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-600'
                      }`}>
                        {ns.enabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right space-x-2">
                      <button 
                        onClick={() => openEdit(ns)}
                        className="text-purple-600 hover:text-purple-800 font-medium text-sm"
                      >
                        Edit
                      </button>
                      <button 
                        onClick={() => remove(ns)}
                        className="text-red-600 hover:text-red-800 text-sm"
                      >
                        Delete
                      </button>
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

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
              className="bg-white rounded-2xl shadow-2xl w-full max-w-lg"
              onClick={e => e.stopPropagation()}
            >
              <div className="flex items-center justify-between p-6 border-b">
                <h3 className="text-xl font-bold text-gray-900">
                  {editingNs ? 'Edit Nameserver' : 'Add Nameserver'}
                </h3>
                <button onClick={() => setShowModal(false)} className="p-2 hover:bg-gray-100 rounded-lg">
                  <X className="w-5 h-5 text-gray-500" />
                </button>
              </div>

              <div className="p-6 space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Hostname *</label>
                  <input 
                    className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:ring-2 focus:ring-purple-500 focus:border-transparent" 
                    placeholder="e.g., ns1.example.com" 
                    value={form.hostname} 
                    onChange={e=>setForm({...form, hostname: e.target.value})} 
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">IP Address *</label>
                  <input 
                    className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:ring-2 focus:ring-purple-500 focus:border-transparent" 
                    placeholder="e.g., 192.0.2.1" 
                    value={form.ip_address} 
                    onChange={e=>setForm({...form, ip_address: e.target.value})} 
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Glue IP (optional)</label>
                  <input 
                    className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:ring-2 focus:ring-purple-500 focus:border-transparent" 
                    placeholder="IP for glue record (if NS is under this zone)" 
                    value={form.glue_ip} 
                    onChange={e=>setForm({...form, glue_ip: e.target.value})} 
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Sort Order</label>
                  <input 
                    type="number"
                    className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:ring-2 focus:ring-purple-500 focus:border-transparent" 
                    placeholder="Display order" 
                    value={form.sort_order} 
                    onChange={e=>setForm({...form, sort_order: e.target.value})} 
                  />
                </div>
                <label className="flex items-center space-x-3 p-3 rounded-lg border border-gray-200 cursor-pointer hover:bg-gray-50">
                  <input 
                    type="checkbox" 
                    checked={form.enabled} 
                    onChange={e=>setForm({...form, enabled: e.target.checked})}
                    className="w-5 h-5 text-purple-600 rounded focus:ring-purple-500"
                  />
                  <span className="font-medium text-gray-900">Enable Nameserver</span>
                </label>
              </div>

              <div className="flex items-center justify-end space-x-3 p-6 border-t bg-gray-50">
                <button 
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 text-gray-700 hover:bg-gray-200 rounded-lg transition-colors"
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
