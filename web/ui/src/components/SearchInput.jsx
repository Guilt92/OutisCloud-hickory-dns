import React from 'react'

export default function SearchInput({ value, onChange, placeholder='Search...' }){
  return (
    <div className="flex items-center space-x-2">
      <input className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-4 py-2 dark:bg-gray-700 dark:text-white dark:placeholder-gray-400 focus:ring-2 focus:ring-primary-500 focus:border-transparent transition-all" placeholder={placeholder} value={value} onChange={e=>onChange(e.target.value)} />
    </div>
  )
}
