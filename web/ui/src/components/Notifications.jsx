import React from 'react'

const NotificationsContext = React.createContext()

export function NotificationsProvider({ children }){
  const [messages, setMessages] = React.useState([])
  const push = (msg) => setMessages(m => [...m, { id: Date.now(), text: msg }])
  const remove = (id) => setMessages(m => m.filter(x=>x.id!==id))
  return (
    <NotificationsContext.Provider value={{ push }}>
      {children}
      <div className="fixed bottom-4 right-4 space-y-2">
        {messages.map(m=> (
          <div key={m.id} className="bg-gray-900 text-white px-4 py-2 rounded shadow">{m.text} <button className="ml-2" onClick={()=>remove(m.id)}>x</button></div>
        ))}
      </div>
    </NotificationsContext.Provider>
  )
}

export default NotificationsContext
