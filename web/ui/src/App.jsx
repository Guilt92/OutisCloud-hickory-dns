import React from 'react'
import { Routes, Route, useNavigate } from 'react-router-dom'
import axios from 'axios'
import Layout from './components/Layout'
import Login from './pages/Login'
import Admin from './pages/Admin'
import User from './pages/User'

export default function App(){
  const [authed, setAuthed] = React.useState(!!localStorage.getItem('token'))
  const nav = useNavigate()

  const logout = () => {
    localStorage.removeItem('token')
    delete axios.defaults.headers.common['Authorization']
    setAuthed(false)
    nav('/')
  }

  return (
    <Layout authed={authed} onLogout={logout}>
      <Routes>
        <Route path="/login" element={<Login onLogin={()=>setAuthed(true)} />} />
        <Route path="/admin/*" element={authed ? <Admin /> : <Login onLogin={()=>setAuthed(true)} />} />
        <Route path="/user" element={authed ? <User /> : <Login onLogin={()=>setAuthed(true)} />} />
        <Route path="/" element={<div className="p-6 max-w-4xl mx-auto"><h2 className="text-2xl font-semibold">Welcome to Hickory DNS Control</h2>{!authed && <a href="/login" className="text-blue-600 underline">Click here to login</a>}</div>} />
      </Routes>
    </Layout>
  )
}
