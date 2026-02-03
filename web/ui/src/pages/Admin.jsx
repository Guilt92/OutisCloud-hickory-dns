import React from 'react'
import { Routes, Route, Link } from 'react-router-dom'
import Servers from './Admin/Servers'
import Zones from './Admin/Zones'
import GeoRules from './Admin/GeoRules'
import ConfigPush from './Admin/ConfigPush'

export default function Admin(){
  return (
    <div className="max-w-6xl mx-auto">
      <nav className="mb-4 space-x-4">
        <Link to="servers" className="text-blue-600">Servers</Link>
        <Link to="zones" className="text-blue-600">Zones</Link>
        <Link to="georules" className="text-blue-600">GeoRules</Link>
        <Link to="config" className="text-blue-600">Config Push</Link>
      </nav>
      <Routes>
        <Route path="servers" element={<Servers/>} />
        <Route path="zones" element={<Zones/>} />
        <Route path="georules" element={<GeoRules/>} />
        <Route path="config" element={<ConfigPush/>} />
        <Route path="" element={<div className="text-gray-600">Select a section</div>} />
      </Routes>
    </div>
  )
}
