import React from 'react'
import api from '../../api'
import Modal from '../../components/Modal'
import SearchInput from '../../components/SearchInput'

export default function Users(){
  const [users, setUsers] = React.useState([])
  const [q, setQ] = React.useState('')
  const [open, setOpen] = React.useState(false)
  const [editing, setEditing] = React.useState(null)
  const [form, setForm] = React.useState({ username:'', email:'', role:'user' })

  const load = async ()=>{ try { const r = await api.get('/api/v1/users'); setUsers(r.data||[]) } catch(e){ console.error(e) } }
  React.useEffect(()=>{ const t=localStorage.getItem('token'); if(t) api.setToken(t); load() }, [])

  const openCreate = ()=>{ setForm({ username:'', email:'', role:'user' }); setEditing(null); setOpen(true) }
  const openEdit = (u)=>{ setForm({ username:u.username, email:u.email, role:u.role }); setEditing(u); setOpen(true) }

  const save = async ()=>{
    try {
      if (editing) await api.put(`/api/v1/users/${editing.id}`, form)
      else await api.post('/api/v1/users', form)
      setOpen(false)
      load()
    } catch(e){ alert('Save failed') }
  }

  const remove = async (id)=>{ if(!confirm('Delete user?')) return; try { await api.delete(`/api/v1/users/${id}`); load() } catch(e){ alert('Delete failed') } }

  const filtered = users.filter(u=> (u.username||'').includes(q) || (u.email||'').includes(q))

  return (
    <div className="bg-white shadow rounded p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold">Users</h3>
        <div className="flex items-center space-x-2">
          <SearchInput value={q} onChange={setQ} placeholder="Search users..." />
          <button className="bg-blue-600 text-white px-3 py-1 rounded" onClick={openCreate}>New</button>
        </div>
      </div>

      <table className="w-full table-auto border-collapse">
        <thead>
          <tr className="bg-gray-50"><th className="border px-2 py-1">ID</th><th className="border px-2 py-1">Username</th><th className="border px-2 py-1">Email</th><th className="border px-2 py-1">Role</th><th className="border px-2 py-1">Actions</th></tr>
        </thead>
        <tbody>
          {filtered.map(u=> (
            <tr key={u.id}><td className="border px-2 py-1">{u.id}</td><td className="border px-2 py-1">{u.username}</td><td className="border px-2 py-1">{u.email}</td><td className="border px-2 py-1">{u.role}</td><td className="border px-2 py-1"><button className="text-blue-600 mr-2" onClick={()=>openEdit(u)}>Edit</button><button className="text-red-600" onClick={()=>remove(u.id)}>Delete</button></td></tr>
          ))}
        </tbody>
      </table>

      <Modal title={editing ? 'Edit User' : 'Create User'} open={open} onClose={()=>setOpen(false)}>
        <div className="grid gap-2">
          <input className="border rounded px-3 py-2" placeholder="username" value={form.username} onChange={e=>setForm({...form, username:e.target.value})} />
          <input className="border rounded px-3 py-2" placeholder="email" value={form.email} onChange={e=>setForm({...form, email:e.target.value})} />
          <select className="border rounded px-3 py-2" value={form.role} onChange={e=>setForm({...form, role:e.target.value})}>
            <option value="user">user</option>
            <option value="admin">admin</option>
          </select>
          <div className="flex justify-end">
            <button className="bg-gray-200 px-3 py-1 rounded mr-2" onClick={()=>setOpen(false)}>Cancel</button>
            <button className="bg-blue-600 text-white px-3 py-1 rounded" onClick={save}>Save</button>
          </div>
        </div>
      </Modal>
    </div>
  )
}
