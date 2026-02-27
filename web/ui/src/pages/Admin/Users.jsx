import React from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Navigate } from 'react-router-dom'
import api from '../../api/client'
import Modal from '../../components/Modal'
import SearchInput from '../../components/SearchInput'
import { useAuthStore } from '../../store'
import { Users as UsersIcon, Plus, Edit2, Trash2, Shield, Mail, User, Eye, Edit, ShieldCheck, ShieldOff, Lock } from 'lucide-react'

const ROLES = [
  { value: 'admin', label: 'Admin', description: 'Full access to all features', icon: ShieldCheck },
  { value: 'editor', label: 'Editor', description: 'Can manage zones and records', icon: Edit },
  { value: 'viewer', label: 'Viewer', description: 'Read-only access', icon: Eye },
]

const roleColors = {
  admin: 'bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-400',
  editor: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',
  viewer: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300',
}

export default function Users(){
  const { user } = useAuthStore()
  const [users, setUsers] = React.useState([])
  const [q, setQ] = React.useState('')
  const [open, setOpen] = React.useState(false)
  const [editing, setEditing] = React.useState(null)
  const [form, setForm] = React.useState({ username:'', email:'', role:'viewer', password:'' })
  const [loading, setLoading] = React.useState(false)

  // RBAC: Only admins can access user management
  if (!user || user.role !== 'admin') {
    return (
      <div className="p-8 text-center">
        <Shield className="w-16 h-16 text-red-500 mx-auto mb-4" />
        <h2 className="text-xl font-bold text-gray-800 dark:text-white mb-2">Access Denied</h2>
        <p className="text-gray-500 dark:text-gray-400">You don't have permission to manage users.</p>
      </div>
    )
  }

  const load = async () => {
    setLoading(true)
    try { 
      const r = await api.get('/api/v1/users')
      setUsers(r.data || []) 
    } catch(e){ console.error(e) }
    setLoading(false)
  }
  React.useEffect(()=>{ const t=localStorage.getItem('token'); if(t) api.setToken(t); load() }, [])

  const openCreate = ()=>{ setForm({ username:'', email:'', role:'viewer', password:'' }); setEditing(null); setOpen(true) }
  const openEdit = (u)=>{ setForm({ username:u.username, email:u.email || '', role:u.role || 'viewer', password:'' }); setEditing(u); setOpen(true) }

  const save = async ()=>{
    try {
      if (!form.username || form.username.length < 3) {
        alert('Username must be at least 3 characters')
        return
      }
      if (editing) {
        const updateData = { username: form.username, role: form.role }
        await api.put(`/api/v1/users/${editing.id}`, updateData)
      } else {
        if (!form.password || form.password.length < 8) {
          alert('Password must be at least 8 characters')
          return
        }
        await api.post('/api/v1/users', { username: form.username, password: form.password, role: form.role })
      }
      setOpen(false)
      load()
    } catch(e){ alert('Save failed: ' + (e.response?.data?.error || e.message)) }
  }

  const remove = async (id)=>{ if(!confirm('Delete user?')) return; try { await api.delete(`/api/v1/users/${id}`); load() } catch(e){ alert('Delete failed') } }

  const filtered = users.filter(u=> (u.username||'').toLowerCase().includes(q.toLowerCase()) || (u.email||'').toLowerCase().includes(q.toLowerCase()))

  return (
    <div className="space-y-6">
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-white dark:bg-gray-800 shadow-lg rounded-xl p-6 border border-gray-100 dark:border-gray-700"
      >
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-purple-100 dark:bg-purple-900/30 rounded-lg">
              <UsersIcon className="w-6 h-6 text-purple-600 dark:text-purple-400" />
            </div>
            <div>
              <h3 className="text-xl font-bold text-gray-800 dark:text-white">User Management</h3>
              <p className="text-sm text-gray-500 dark:text-gray-400">Manage users and access levels</p>
            </div>
          </div>
          <button 
            onClick={openCreate}
            className="bg-gradient-to-r from-purple-600 to-purple-700 text-white px-4 py-2 rounded-lg hover:from-purple-700 hover:to-purple-800 transition-all flex items-center space-x-2 font-medium"
          >
            <Plus className="w-5 h-5" />
            <span>New User</span>
          </button>
        </div>

        <div className="max-w-md">
          <SearchInput value={q} onChange={setQ} placeholder="Search users..." />
        </div>
      </motion.div>

      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="bg-white dark:bg-gray-800 shadow-lg rounded-xl border border-gray-100 dark:border-gray-700 overflow-hidden"
      >
        {filtered.length === 0 ? (
          <div className="p-12 text-center">
            <UsersIcon className="w-16 h-16 text-gray-300 dark:text-gray-600 mx-auto mb-4" />
            <p className="text-gray-500 dark:text-gray-400">No users found</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 dark:bg-gray-700">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 dark:text-gray-300 uppercase tracking-wider">User</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 dark:text-gray-300 uppercase tracking-wider">Role</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 dark:text-gray-300 uppercase tracking-wider">Created</th>
                  <th className="px-6 py-3 text-right text-xs font-semibold text-gray-600 dark:text-gray-300 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
                {filtered.map((u, i) => (
                  <motion.tr 
                    key={u.id}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: i * 0.05 }}
                    className="hover:bg-gray-50 dark:hover:bg-gray-700/50"
                  >
                    <td className="px-6 py-4">
                      <div className="flex items-center space-x-3">
                        <div className="w-10 h-10 rounded-full bg-gradient-to-br from-primary-500 to-primary-600 flex items-center justify-center text-white font-semibold">
                          {u.username?.charAt(0).toUpperCase()}
                        </div>
                        <div>
                          <p className="text-sm font-medium text-gray-900 dark:text-white">{u.username}</p>
                          <p className="text-xs text-gray-500 dark:text-gray-400">{u.email || 'No email'}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className={`inline-flex items-center space-x-1 px-2.5 py-1 rounded-full text-xs font-medium ${roleColors[u.role] || roleColors.viewer}`}>
                        {u.role === 'admin' && <ShieldCheck className="w-3 h-3" />}
                        {u.role === 'editor' && <Edit className="w-3 h-3" />}
                        {u.role === 'viewer' && <Eye className="w-3 h-3" />}
                        <span className="capitalize">{u.role || 'viewer'}</span>
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">
                      {u.createdAt ? new Date(u.createdAt).toLocaleDateString() : '-'}
                    </td>
                    <td className="px-6 py-4 text-right">
                      <div className="flex items-center justify-end space-x-2">
                        <button 
                          onClick={()=>openEdit(u)}
                          className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 p-1 rounded hover:bg-blue-50 dark:hover:bg-blue-900/20"
                        >
                          <Edit2 className="w-4 h-4" />
                        </button>
                        <button 
                          onClick={()=>remove(u.id)}
                          className="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300 p-1 rounded hover:bg-red-50 dark:hover:bg-red-900/20"
                        >
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

      <AnimatePresence>
        {open && (
          <Modal title={editing ? 'Edit User' : 'Create User'} open={open} onClose={()=>setOpen(false)}>
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="space-y-4"
            >
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Username</label>
                <input 
                  className="w-full border border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded-lg px-4 py-2 focus:ring-2 focus:ring-purple-500 focus:border-transparent" 
                  placeholder="username" 
                  value={form.username} 
                  onChange={e=>setForm({...form, username:e.target.value})} 
                />
              </div>
              {!editing && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Password</label>
                  <input 
                    type="password"
                    className="w-full border border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded-lg px-4 py-2 focus:ring-2 focus:ring-purple-500 focus:border-transparent" 
                    placeholder="min 8 characters" 
                    value={form.password} 
                    onChange={e=>setForm({...form, password:e.target.value})} 
                  />
                </div>
              )}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Role</label>
                <div className="grid grid-cols-1 gap-2">
                  {ROLES.map((role) => {
                    const Icon = role.icon
                    return (
                      <label
                        key={role.value}
                        className={`flex items-center p-3 rounded-lg border-2 cursor-pointer transition-all ${
                          form.role === role.value
                            ? 'border-purple-500 bg-purple-50 dark:bg-purple-900/20'
                            : 'border-gray-200 dark:border-gray-600 hover:border-gray-300 dark:hover:border-gray-500'
                        }`}
                      >
                        <input
                          type="radio"
                          name="role"
                          value={role.value}
                          checked={form.role === role.value}
                          onChange={(e) => setForm({ ...form, role: e.target.value })}
                          className="sr-only"
                        />
                        <Icon className={`w-5 h-5 mr-3 ${form.role === role.value ? 'text-purple-600 dark:text-purple-400' : 'text-gray-400'}`} />
                        <div className="flex-1">
                          <p className="text-sm font-medium text-gray-900 dark:text-white">{role.label}</p>
                          <p className="text-xs text-gray-500 dark:text-gray-400">{role.description}</p>
                        </div>
                        {form.role === role.value && (
                          <ShieldCheck className="w-5 h-5 text-purple-600 dark:text-purple-400" />
                        )}
                      </label>
                    )
                  })}
                </div>
              </div>
              <div className="flex justify-end space-x-3 pt-4">
                <button 
                  className="px-4 py-2 text-gray-700 bg-gray-100 dark:bg-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors" 
                  onClick={()=>setOpen(false)}
                >
                  Cancel
                </button>
                <button 
                  className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors" 
                  onClick={save}
                >
                  {editing ? 'Update' : 'Create'}
                </button>
              </div>
            </motion.div>
          </Modal>
        )}
      </AnimatePresence>
    </div>
  )
}
