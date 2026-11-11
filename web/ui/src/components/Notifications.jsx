import React from 'react'
import { X, CheckCircle, AlertCircle, AlertTriangle, Info } from 'lucide-react'

const NotificationsContext = React.createContext()

const typeStyles = {
  success: 'border-success-500/50 [&_svg:first-child]:text-success-500',
  error: 'border-danger-500/50 [&_svg:first-child]:text-danger-500',
  warning: 'border-warning-500/50 [&_svg:first-child]:text-warning-500',
  info: 'border-accent/50 [&_svg:first-child]:text-primary-700 dark:[&_svg:first-child]:text-accent',
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
    <div role="status" className={`flex items-start gap-3 px-4 py-3 rounded-xl border bg-surface text-ink shadow-pop animate-slide-in ${typeStyles[m.type] || typeStyles.info}`}>
      <Icon className="w-5 h-5 flex-shrink-0 mt-0.5" />
      <p className="text-sm flex-1 break-words">{m.text}</p>
      <button
        aria-label="Dismiss" className="flex-shrink-0 text-muted hover:text-ink transition-colors"
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
      <div className="fixed bottom-4 right-4 left-4 sm:left-auto space-y-2 z-[70] sm:max-w-sm" aria-live="polite">
        {messages.map(m => (
          <NotificationItem key={m.id} m={m} onRemove={remove} />
        ))}
      </div>
    </NotificationsContext.Provider>
  )
}

export default NotificationsContext