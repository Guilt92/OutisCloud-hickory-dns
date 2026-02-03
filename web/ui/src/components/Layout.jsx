import React from 'react'
import { Link } from 'react-router-dom'

export default function Layout({ children, authed, onLogout }){
  return (
    <div>
      <header className="border-b border-gray-200 py-4 px-6">
        <div className="max-w-6xl mx-auto flex items-center justify-between">
          <h1 className="text-xl font-bold">🌐 Hickory DNS Control</h1>
          <nav className="space-x-4">
            {authed ? (
              <>
                <Link to="/admin" className="text-blue-600">Admin</Link>
                <Link to="/user" className="text-blue-600">User</Link>
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
