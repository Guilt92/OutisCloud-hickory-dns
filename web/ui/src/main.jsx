import React from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import api from './api'
import './index.css'
import App from './App'
import { AuthProvider } from './contexts/AuthContext'
import { NotificationsProvider } from './components/Notifications'

const token = localStorage.getItem('token')
if (token) api.setToken(token)

createRoot(document.getElementById('root')).render(
  <BrowserRouter>
    <AuthProvider>
      <NotificationsProvider>
        <App />
      </NotificationsProvider>
    </AuthProvider>
  </BrowserRouter>
)
