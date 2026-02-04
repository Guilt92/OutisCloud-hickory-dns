import React from 'react'

export default function SearchInput({ value, onChange, placeholder='Search...' }){
  return (
    <div className="flex items-center space-x-2">
      <input className="border rounded px-3 py-2 w-full" placeholder={placeholder} value={value} onChange={e=>onChange(e.target.value)} />
    </div>
  )
}
