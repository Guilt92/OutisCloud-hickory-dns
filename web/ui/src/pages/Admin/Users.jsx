import React from 'react'
import api from '../../api/client'
import Modal from '../../components/Modal'
import SearchInput from '../../components/SearchInput'
import { useAuthStore } from '../../store'
import { useServerPagination, PaginationControls } from '../../hooks/useAdvancedUI'
import { Users as UsersIcon, Plus, Edit2, Trash2, Shield, Eye, Edit, ShieldCheck, KeyRound } from 'lucide-react'
import { PageHeader, useConfirm } from '../../components/ui'
import Notifications from '../../components/Notifications'
import { validators } from '../../hooks/useFormValidation'

const ROLES = [
  { value: 'admin', label: 'Admin', description: 'Full access to all features', icon: ShieldCheck },
  { value: 'editor', label: 'Editor', description: 'Can manage zones and records', icon: Edit },
  { value: 'viewer', label: 'Viewer', description: 'Read-only access', icon: Eye },
  { value: 'user', label: 'User', description: 'Standard tenant user', icon: UsersIcon },
]

const roleColors = {
  admin: 'bg-accent text-on-accent',
  editor: 'bg-surface-2 text-ink border border-line',
  viewer: 'bg-surface-2 text-muted border border-line',
  user: 'bg-surface-2 text-ink border border-line',
}

export default function Users() {
  const askConfirm = useConfirm()
  const notify = React.useContext(Notifications)
  const { user } = useAuthStore()
  const paged = useServerPagination(api, user?.role === 'admin' ? '/api/v1/users' : null, { pageSize: 15 })
  const users = paged.items
  const q = paged.query
  const setQ = paged.setQuery
  const [open, setOpen] = React.useState(false)
  const [editing, setEditing] = React.useState(null)
  const [form, setForm] = React.useState({ username: '', email: '', role: 'viewer', password: '' })
  const [resetting, setResetting] = React.useState(null)
  const [resetPassword, setResetPassword] = React.useState('')
  React.useEffect(() => { const t = localStorage.getItem('token'); if (t) api.setToken(t) }, [])

  if (!user || user.role !== 'admin') {
    return (
      <div className="p-8 text-center">
        <Shield className="w-16 h-16 text-muted mx-auto mb-4" />
        <h2 className="section-title mb-2">Access denied</h2>
        <p className="text-muted">You don&apos;t have permission to manage users.</p>
      </div>
    )
  }

  const load = paged.reload
  const openCreate = () => { setForm({ username: '', email: '', role: 'viewer', password: '' }); setEditing(null); setOpen(true) }
  const openEdit = (u) => { setForm({ username: u.username, email: u.email || '', role: u.role || 'viewer', password: '' }); setEditing(u); setOpen(true) }

  const save = async () => {
    try {
      if (!form.username || form.username.length < 3) { notify?.warning('Username must be at least 3 characters'); return }
      const email = form.email.trim()
      if (email && validators.email(email)) { notify?.warning('Enter a valid email address'); return }
      if (editing) {
        await api.put(`/api/v1/users/${editing.id}`, { username: form.username, role: form.role, email })
      } else {
        if (!form.password || form.password.length < 8) { notify?.warning('Password must be at least 8 characters'); return }
        await api.post('/api/v1/users', { username: form.username, password: form.password, role: form.role, email })
      }
      setOpen(false)
      load()
    } catch (e) { notify?.error('Save failed: ' + (e.response?.data?.error || e.message)) }
  }

  const submitReset = async () => {
    if (resetPassword.length < 8) { notify?.warning('Password must be at least 8 characters'); return }
    try {
      await api.post(`/api/v1/users/${resetting.id}/password`, { new_password: resetPassword })
      setResetting(null); setResetPassword(''); notify?.success('Password reset and sessions revoked')
    } catch (e) { notify?.error('Reset failed: ' + (e.response?.data?.error || e.message)) }
  }

  const remove = async (id) => {
    if (!(await askConfirm({ title: 'Delete user?', message: 'The account loses access immediately. Their zones are not deleted.', confirmLabel: 'Delete user' }))) return
    try { await api.delete(`/api/v1/users/${id}`); load() } catch { notify?.error('Delete failed') }
  }

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Administration" title="Users & roles" description="Manage people, permissions and account access." icon={UsersIcon}
        actions={<button onClick={openCreate} className="btn-primary"><Plus className="w-4 h-4" />New user</button>} />

      <div className="card overflow-hidden">
        <div className="px-5 py-4 border-b border-line">
          <div className="max-w-md"><SearchInput value={q} onChange={setQ} placeholder="Search users..." /></div>
        </div>

        {users.length === 0 ? (
          <div className="p-12 text-center">
            <UsersIcon className="w-12 h-12 text-muted/40 mx-auto mb-3" />
            <p className="text-muted">No users found.</p>
          </div>
        ) : (
          <div className="table-container" tabIndex={0} role="region" aria-label="Scrollable table">
            <table>
              <thead><tr><th>User</th><th>Role</th><th>Created</th><th className="text-right">Actions</th></tr></thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id}>
                    <td>
                      <div className="flex items-center gap-3">
                        <div className="w-9 h-9 rounded-full bg-accent text-on-accent flex items-center justify-center text-sm font-semibold flex-shrink-0">{u.username?.charAt(0).toUpperCase()}</div>
                        <div className="min-w-0"><p className="text-[13px] font-medium text-ink truncate">{u.username}</p><p className="text-xs text-muted truncate">{u.email || 'No email'}</p></div>
                      </div>
                    </td>
                    <td>
                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium ${roleColors[u.role] || roleColors.viewer}`}>
                        {u.role === 'admin' && <ShieldCheck className="w-3 h-3" />}
                        {u.role === 'editor' && <Edit className="w-3 h-3" />}
                        {u.role === 'viewer' && <Eye className="w-3 h-3" />}
                        {u.role === 'user' && <UsersIcon className="w-3 h-3" />}
                        <span className="capitalize">{u.role || 'viewer'}</span>
                      </span>
                    </td>
                    <td className="text-muted">{u.createdAt ? new Date(u.createdAt).toLocaleDateString() : '-'}</td>
                    <td>
                      <div className="flex items-center justify-end gap-1">
                        <button onClick={() => openEdit(u)} aria-label={`Edit ${u.username}`} className="btn-icon"><Edit2 className="w-4 h-4" /></button>
                        <button onClick={() => { setResetting(u); setResetPassword('') }} aria-label={`Reset password for ${u.username}`} className="btn-icon"><KeyRound className="w-4 h-4" /></button>
                        <button onClick={() => remove(u.id)} aria-label={`Delete ${u.username}`} className="btn-icon text-danger-500 hover:bg-danger-500/[0.07] hover:text-danger-500"><Trash2 className="w-4 h-4" /></button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="px-5 py-3 border-t border-line flex items-center justify-between text-xs text-muted">
          <span>{paged.total} user{paged.total !== 1 ? 's' : ''}</span>
          <PaginationControls pagination={paged.pagination} />
        </div>
      </div>

      <Modal title={editing ? 'Edit user' : 'Create user'} open={open} onClose={() => setOpen(false)}>
        <div className="space-y-4">
          <div><label htmlFor="user-name" className="form-label">Username</label><input id="user-name" className="input" placeholder="username" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} /></div>
          <div><label htmlFor="user-email" className="form-label">Email <span className="text-muted">(optional)</span></label><input id="user-email" type="email" className="input" placeholder="user@example.com" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></div>
          {!editing && (
            <div><label htmlFor="user-password" className="form-label">Password</label><input id="user-password" type="password" className="input" placeholder="Minimum 8 characters" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></div>
          )}
          <fieldset>
            <legend className="form-label">Role</legend>
            <div className="grid grid-cols-1 gap-2">
              {ROLES.map((role) => {
                const Icon = role.icon
                const selected = form.role === role.value
                return (
                  <label key={role.value} className={`flex items-center p-3 rounded-[14px] border cursor-pointer transition-colors ${selected ? 'border-ink bg-surface-2' : 'border-line hover:border-muted/40'}`}>
                    <input type="radio" name="role" value={role.value} checked={selected} onChange={(e) => setForm({ ...form, role: e.target.value })} className="sr-only" />
                    <Icon className={`w-[18px] h-[18px] mr-3 ${selected ? 'text-ink' : 'text-muted'}`} />
                    <div className="flex-1"><p className="text-[13px] font-medium text-ink">{role.label}</p><p className="text-xs text-muted">{role.description}</p></div>
                    {selected && <ShieldCheck className="w-[18px] h-[18px] text-ink" />}
                  </label>
                )
              })}
            </div>
          </fieldset>
          <div className="flex justify-end gap-2 pt-2">
            <button type="button" className="btn-secondary" onClick={() => setOpen(false)}>Cancel</button>
            <button type="button" className="btn-primary" onClick={save}>{editing ? 'Update user' : 'Create user'}</button>
          </div>
        </div>
      </Modal>

      <Modal title={`Reset password for ${resetting?.username || ''}`} open={!!resetting} onClose={() => setResetting(null)}>
        <div className="space-y-4">
          <div><label htmlFor="reset-password" className="form-label">New password</label><input id="reset-password" type="password" className="input" value={resetPassword} onChange={e => setResetPassword(e.target.value)} placeholder="Minimum 8 characters" /></div>
          <div className="flex justify-end gap-2">
            <button type="button" className="btn-secondary" onClick={() => setResetting(null)}>Cancel</button>
            <button type="button" className="btn-primary" onClick={submitReset}>Reset password</button>
          </div>
        </div>
      </Modal>
    </div>
  )
}
