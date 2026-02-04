import React from 'react'
import { Link } from 'react-router-dom'
import { useContext } from 'react'
import AuthContext from '../contexts/AuthContext'

export default function Layout({ children, authed, onLogout }){
  const auth = useContext(AuthContext)
  const [dark, setDark] = React.useState(() => localStorage.getItem('dark') === '1')

  React.useEffect(()=>{
    if (dark) document.documentElement.classList.add('dark')
    else document.documentElement.classList.remove('dark')
    localStorage.setItem('dark', dark ? '1' : '0')
  }, [dark])
  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      <header className="border-b border-gray-200 dark:border-gray-700 py-4 px-6 bg-white dark:bg-gray-800">
        <div className="max-w-6xl mx-auto flex items-center justify-between">
          <h1 className="text-xl font-bold">🌐 Hickory DNS Control</h1>
          <nav className="space-x-4">
            {authed ? (
              <>
                <Link to="/admin" className="text-blue-600">Admin</Link>
                <Link to="/user" className="text-blue-600">User</Link>
                <span className="text-sm text-gray-600 dark:text-gray-300">{auth.user ? auth.user.username : ''}</span>
                <button onClick={()=>setDark(d=>!d)} className="ml-2 inline-block bg-gray-200 dark:bg-gray-700 text-sm px-2 py-1 rounded">{dark ? 'Light' : 'Dark'}</button>
                <button onClick={onLogout} className="ml-4 inline-block bg-red-500 text-white px-3 py-1 rounded">Logout</button>
              </>
            ) : (
              <Link to="/login" className="text-blue-600">Login</Link>
            )}
          </nav>
        </div>
      </header>
      <main className="p-6">
        {children}
      </main>
    </div>
  )
}
