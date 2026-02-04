import React from 'react'
import axios from 'axios'
import { useNavigate } from 'react-router-dom'
import Notifications from '../components/Notifications'

export default function Login({ onLogin }){
  const [username, setUsername] = React.useState('')
  const [password, setPassword] = React.useState('')
  const [error, setError] = React.useState('')
  const nav = useNavigate()
  const notify = React.useContext(Notifications)

  const submit = async (e) => {
    e.preventDefault()
    if (!username || !password) { setError('username and password required'); return }
    try {
      const r = await axios.post('/api/v1/auth/login', { username, password })
      const token = r.data.token
      localStorage.setItem('token', token)
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
      onLogin()
      notify && notify.push('Logged in')
      nav('/admin')
    } catch (e) {
      setError('Login failed')
    }
  }

  return (
    <div className="max-w-md mx-auto bg-white shadow rounded p-6">
      <h2 className="text-xl font-semibold mb-4">Hickory DNS Control - Login</h2>
      <form onSubmit={submit} className="space-y-4">
        <input className="w-full border rounded px-3 py-2" placeholder="username" value={username} onChange={e=>setUsername(e.target.value)} />
        <input className="w-full border rounded px-3 py-2" placeholder="password" type="password" value={password} onChange={e=>setPassword(e.target.value)} />
        <div>
          <button className="bg-blue-600 text-white px-4 py-2 rounded">Login</button>
        </div>
      </form>
      {error && <p className="text-red-600 mt-3">{error}</p>}
    </div>
  )
}
