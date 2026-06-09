import React from 'react'
import { X, CheckCircle, AlertCircle, AlertTriangle, Info } from 'lucide-react'

const NotificationsContext = React.createContext()

const typeStyles = {
  success: 'bg-green-600 dark:bg-green-700 text-white',
  error: 'bg-red-600 dark:bg-red-700 text-white',
  warning: 'bg-amber-500 dark:bg-amber-600 text-white',
  info: 'bg-blue-600 dark:bg-blue-700 text-white',
}

const typeIcons = {
  success: CheckCircle,
  error: AlertCircle,
  warning: AlertTriangle,
  info: Info,
}

function NotificationItem({ m, onRemove }){
  const Icon = typeIcons[m.type] || Info
  return (
    <div className={`flex items-start gap-3 px-4 py-3 rounded-xl shadow-lg ${typeStyles[m.type] || typeStyles.info}`}>
      <Icon className="w-5 h-5 flex-shrink-0 mt-0.5" />
      <p className="text-sm flex-1">{m.text}</p>
      <button
        className="flex-shrink-0 opacity-70 hover:opacity-100 transition-opacity"
        onClick={() => onRemove(m.id)}
      >
        <X className="w-4 h-4" />
      </button>
    </div>
  )
}

export function NotificationsProvider({ children }){
  const [messages, setMessages] = React.useState([])

  const pushMessage = (msg, type = 'info', duration = 3000) => {
    const id = Date.now() + Math.random()
    setMessages(m => [...m, { id, text: msg, type }])
    if (duration > 0) {
      setTimeout(() => {
        setMessages(m => m.filter(x => x.id !== id))
      }, duration)
    }
  }

  const remove = (id) => {
    setMessages(m => m.filter(x => x.id !== id))
  }

  const notify = {
    push: (msg) => pushMessage(msg, 'info'),
    success: (msg) => pushMessage(msg, 'success'),
    error: (msg) => pushMessage(msg, 'error'),
    warning: (msg) => pushMessage(msg, 'warning'),
  }

  return (
    <NotificationsContext.Provider value={notify}>
      {children}
      <div className="fixed bottom-4 right-4 space-y-2 z-50 max-w-sm">
        {messages.map(m => (
          <NotificationItem key={m.id} m={m} onRemove={remove} />
        ))}
      </div>
    </NotificationsContext.Provider>
  )
}

export default NotificationsContext