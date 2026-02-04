import React from 'react'
import { Routes, Route, Link } from 'react-router-dom'
import Servers from './Admin/Servers'
import Zones from './Admin/Zones'
import GeoRules from './Admin/GeoRules'
import ConfigPush from './Admin/ConfigPush'
import Records from './Records'
import Users from './Admin/Users'
import Dashboard from './Admin/Dashboard'
import AuditLogs from './Admin/AuditLogs'

export default function Admin(){
  return (
    <div className="max-w-6xl mx-auto">
      <nav className="mb-4 space-x-4">
        <Link to="" className="text-blue-600">Dashboard</Link>
        <Link to="servers" className="text-blue-600">Servers</Link>
        <Link to="zones" className="text-blue-600">Zones</Link>
        <Link to="users" className="text-blue-600">Users</Link>
        <Link to="georules" className="text-blue-600">GeoRules</Link>
        <Link to="audit" className="text-blue-600">Audit</Link>
        <Link to="config" className="text-blue-600">Config Push</Link>
      </nav>
      <Routes>
        <Route path="servers" element={<Servers/>} />
        <Route path="users" element={<Users/>} />
        <Route path="audit" element={<AuditLogs/>} />
        <Route path="dashboard" element={<Dashboard/>} />
        <Route path="zones" element={<Zones/>} />
        <Route path="zones/:id/records" element={<Records/>} />
        <Route path="georules" element={<GeoRules/>} />
        <Route path="config" element={<ConfigPush/>} />
        <Route path="" element={<Dashboard/>} />
      </Routes>
    </div>
  )
}
