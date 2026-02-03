import React from 'react'
import Zones from './Admin/Zones'

export default function User(){
  return (
    <div className="max-w-6xl mx-auto">
      <h2 className="text-xl font-semibold mb-3">User Panel</h2>
      <p className="mb-4 text-gray-600">View your DNS zones and manage records</p>
      <Zones />
    </div>
  )
}
