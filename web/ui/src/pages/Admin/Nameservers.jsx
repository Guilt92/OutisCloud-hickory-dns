import React from 'react'
import { motion } from 'framer-motion'
import Modal from '../../components/Modal'
import api from '../../api/client'
import Notifications from '../../components/Notifications'
import { Globe, Plus, Trash2, RefreshCw, Check, Network, Edit3 } from 'lucide-react'
import { EmptyState, PageHeader, useConfirm } from '../../components/ui'
import { validators } from '../../hooks/useFormValidation'

export default function Nameservers(){
  const askConfirm = useConfirm()
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
  const notifyRef = React.useRef(notify)
  notifyRef.current = notify

  const load = React.useCallback(async () => {
    setLoading(true)
    try {
      const r = await api.get('/api/v1/nameservers')
      setNameservers(r.data || [])
    } catch (e) {
      console.error(e)
      notifyRef.current?.error('Failed to load nameservers')
    }
    setLoading(false)
  }, [])

  React.useEffect(()=>{
    const token = localStorage.getItem('token')
    if(token) api.setToken(token)
    load()
  }, [load])

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
    if (validators.ipAddress(form.ip_address)) {
      notify?.error('Enter a valid IPv4 or IPv6 address')
      return
    }
    if (form.glue_ip && validators.ipAddress(form.glue_ip)) {
      notify?.error('Enter a valid glue IPv4 or IPv6 address')
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
    if (!(await askConfirm({ title: `Delete ${ns.hostname}?`, message: 'Zones using this nameserver will be republished without it.', confirmLabel: 'Delete nameserver' }))) return
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
      <PageHeader
        icon={Globe}
        eyebrow="Infrastructure"
        title="Authoritative nameservers"
        description="Configure the nameservers that serve your zones."
        actions={<>
          <button onClick={load} className="btn-secondary" disabled={loading}>
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button onClick={openCreate} className="btn-primary">
            <Plus className="w-4 h-4" />
            Add nameserver
          </button>
        </>}
      />

      {/* Info card */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.05 }}
        className="card p-4"
      >
        <p className="text-sm text-muted flex items-center gap-2">
          <Network className="w-4 h-4 text-muted flex-shrink-0" />
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
          <EmptyState
            icon={Globe}
            title="No nameservers configured"
            description="Add at least one nameserver to serve your zones."
            action={<button onClick={openCreate} className="btn-primary"><Plus className="w-4 h-4" />Add nameserver</button>}
          />
        ) : (
          <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="Scrollable table">
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
                    <td className="text-muted">{ns.sort_order || '-'}</td>
                    <td>
                      <div className="flex items-center gap-2">
                        <Globe className="w-4 h-4 text-muted flex-shrink-0" />
                        <span className="font-medium text-ink">{ns.hostname}</span>
                      </div>
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        <Network className="w-4 h-4 text-muted flex-shrink-0" />
                        <span className="font-mono text-muted">{ns.ip_address}</span>
                      </div>
                    </td>
                    <td className="font-mono text-muted">{ns.glue_ip || '-'}</td>
                    <td>
                      <span className={`badge ${ns.enabled ? 'badge-success' : 'badge-warning'}`}>
                        {ns.enabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </td>
                    <td className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        <button onClick={() => openEdit(ns)} aria-label={`Edit ${ns.hostname}`} className="btn-icon">
                          <Edit3 className="w-4 h-4" />
                        </button>
                        <button onClick={() => remove(ns)} aria-label={`Delete ${ns.hostname}`} className="btn-icon text-danger-500 hover:bg-danger-500/[0.07] hover:text-danger-600">
                          <Trash2 className="w-4 h-4" />
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

      <Modal open={showModal} onClose={() => setShowModal(false)} title={editingNs ? 'Edit nameserver' : 'Add nameserver'}>
              <div className="p-6 space-y-4">
                <div>
                  <label htmlFor="nameserver-hostname" className="form-label">Hostname <span className="text-danger-500">*</span></label>
                  <input 
                    id="nameserver-hostname"
                    className="input"
                    placeholder="e.g., ns1.example.com" 
                    value={form.hostname} 
                    onChange={e=>setForm({...form, hostname: e.target.value})} 
                  />
                </div>
                <div>
                  <label htmlFor="nameserver-ip" className="form-label">IP address <span className="text-danger-500">*</span></label>
                  <input 
                    id="nameserver-ip"
                    className="input"
                    placeholder="e.g., 192.0.2.1" 
                    value={form.ip_address} 
                    onChange={e=>setForm({...form, ip_address: e.target.value})} 
                  />
                </div>
                <div>
                  <label htmlFor="nameserver-glue-ip" className="form-label">Glue IP <span className="text-muted">(optional)</span></label>
                  <input 
                    id="nameserver-glue-ip"
                    className="input"
                    placeholder="IP for glue record (if NS is under this zone)" 
                    value={form.glue_ip} 
                    onChange={e=>setForm({...form, glue_ip: e.target.value})} 
                  />
                </div>
                <div>
                  <label htmlFor="nameserver-sort-order" className="form-label">Sort order</label>
                  <input 
                    id="nameserver-sort-order"
                    type="number"
                    className="input"
                    placeholder="Display order" 
                    value={form.sort_order} 
                    onChange={e=>setForm({...form, sort_order: e.target.value})} 
                  />
                </div>
                <label className="flex items-center gap-3 p-3 rounded-[14px] border border-line cursor-pointer hover:bg-ink/[0.025]">
                  <input 
                    type="checkbox" 
                    checked={form.enabled} 
                    onChange={e=>setForm({...form, enabled: e.target.checked})}
                    className="w-4 h-4 rounded border-line"
                  />
                  <span className="font-medium text-[13px] text-ink">Enable nameserver</span>
                </label>
              </div>

              <div className="flex items-center justify-end space-x-3 p-6 border-t border-line bg-surface-2">
                <button onClick={() => setShowModal(false)} className="btn-secondary">Cancel</button>
                <button onClick={save} className="btn-primary">
                  <Check className="w-4 h-4" />
                  <span>{editingNs ? 'Update nameserver' : 'Create nameserver'}</span>
                </button>
              </div>
      </Modal>
    </div>
  )
}
