import React from 'react'
import api from '../../api/client'
import { Link } from 'react-router-dom'
import BulkImport from '../../components/BulkImport'
import Notifications from '../../components/Notifications'
import { useFormValidation, validators, FormField, downloadTemplate } from '../../hooks/useFormValidation'
import { usePagination, useTableSort, useAdvancedSearch, PaginationControls, SortableHeader, FadeIn, SkeletonTable } from '../../hooks/useAdvancedUI'

export default function Zones(){
  const [zones, setZones] = React.useState([])
  const [loading, setLoading] = React.useState(false)
  const notify = React.useContext(Notifications)
  const { values, errors, bind, validate, reset, setFieldValue } = useFormValidation(
    { domain: '' },
    (vals) => ({ domain: validators.domain(vals.domain) })
  )
  const [geodnsEnabled, setGeodnsEnabled] = React.useState(false)
  const [editingZone, setEditingZone] = React.useState(null)
  const [editDomain, setEditDomain] = React.useState('')
  const [editType, setEditType] = React.useState('primary')
  const [editGeodns, setEditGeodns] = React.useState(false)
  const [zoneNameservers, setZoneNameservers] = React.useState({})

  // Advanced search with debouncing
  const { searchTerm, filteredItems, handleSearch } = useAdvancedSearch(
    zones,
    ['domain', 'id']
  )
  
  // Table sorting
  const { sortedItems, sortConfig, requestSort } = useTableSort(filteredItems, { field: 'domain', order: 'asc' })
  
  // Pagination
  const pagination = usePagination(sortedItems, 10)

  const load = async () => { 
    setLoading(true)
    try { 
      const r = await api.get('/api/v1/zones')
      const zonesData = r.data || []
      setZones(zonesData)
      
      // Load nameservers for each zone
      const nameserversMap = {}
      for (const zone of zonesData) {
        try {
          const zoneRes = await api.get(`/api/v1/zones/${zone.id}`)
          if (zoneRes.data?.data?.nameservers) {
            nameserversMap[zone.id] = zoneRes.data.data.nameservers
          }
        } catch (e) {
          console.error('Error loading nameservers for zone', zone.id, e)
        }
      }
      setZoneNameservers(nameserversMap)
    } catch (e) { 
      console.error('Error loading zones', e)
      const errMsg = e.response?.data?.error || e.message || 'Failed to load zones';
      notify?.error(errMsg)
    } finally {
      setLoading(false)
    }
  }

  React.useEffect(()=>{ 
    const token = localStorage.getItem('token')
    if (token) api.setToken(token)
    load()
  }, [])

  const handleCreateClick = async (e) => {
    e.preventDefault()
    e.stopPropagation()
    
    console.log('handleCreateClick called, domain:', values.domain)
    
    if (!values.domain || values.domain.trim() === '') {
      notify?.error('Please enter a domain name')
      return
    }
    
    // Basic validation
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$/
    if (!domainRegex.test(values.domain.trim())) {
      notify?.error('Please enter a valid domain name (e.g., example.com)')
      return
    }
    
    try { 
      const domain = values.domain.trim().endsWith('.') ? values.domain.trim() : values.domain.trim() + '.';
      console.log('Creating zone with domain:', domain)
      
      const response = await api.post('/api/v1/zones', { domain: domain, geodns_enabled: geodnsEnabled })
      console.log('Zone created response:', response)
      
      setFieldValue('domain', '')
      setGeodnsEnabled(false)
      load()
      
      if (response.data && response.data.nameservers && response.data.nameservers.length > 0) {
        const nsList = response.data.nameservers.join(', ')
        notify?.success(`Zone ${domain} created! Nameservers: ${nsList}`)
      } else {
        notify?.success(`Zone ${domain} created`)
      }
    } catch (err) { 
      console.error('Create zone error:', err)
      const errMsg = err.response?.data?.error || err.message || 'Error creating zone';
      notify?.error(errMsg)
    } 
  }
  
  const startEdit = (zone) => {
    setEditingZone(zone)
    setEditDomain(zone.domain)
    setEditType(zone.zone_type || 'primary')
    setEditGeodns(zone.geodns_enabled || false)
  }

  const cancelEdit = () => {
    setEditingZone(null)
    setEditDomain('')
    setEditType('primary')
  }

  const saveEdit = async () => {
    if (!editDomain || validators.domain(editDomain)) {
      notify?.error('Invalid domain')
      return
    }
    try {
      // Ensure domain has trailing dot for DNS standard
      const domain = editDomain.endsWith('.') ? editDomain : editDomain + '.';
      await api.put(`/api/v1/zones/${editingZone.id}`, { domain: domain, zone_type: editType, geodns_enabled: editGeodns })
      notify?.success('Zone updated')
      cancelEdit()
      load()
    } catch (e) {
      const errMsg = e.response?.data?.error || e.message || 'Error updating zone';
      notify?.error(errMsg)
    }
  }

  const deleteZone = async (zone) => {
    if (!window.confirm(`Delete zone ${zone.domain}?`)) return
    try {
      await api.delete(`/api/v1/zones/${zone.id}`)
      notify?.success('Zone deleted')
      if (editingZone && editingZone.id === zone.id) cancelEdit()
      load()
    } catch (e) {
      const errMsg = e.response?.data?.error || e.message || 'Error deleting zone';
      notify?.error(errMsg)
    }
  }

  const toggleZoneGeo = async (zone) => {
    try {
      await api.put(`/api/v1/zones/${zone.id}`, { geodns_enabled: !zone.geodns_enabled });
      load();
    } catch (e) {
      const errMsg = e.response?.data?.error || e.message || 'Failed to update zone';
      notify?.error(errMsg);
    }
  }

  const onBulkComplete = () => { load(); notify?.success('Zones imported'); }

  return (
    <div className="bg-white dark:bg-gray-800 shadow rounded p-6">
      <div className="mb-6">
        <h3 className="text-lg font-semibold mb-4">Zones</h3>
        {!editingZone ? (
          <div className="grid gap-2 mb-4 max-w-md">
            <FormField label="Domain" error={errors.domain}>
              <input className="w-full border dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded px-3 py-2" placeholder="example.com" {...bind('domain')} />
            </FormField>
            <FormField label="Enable GeoDNS">
              <input type="checkbox" checked={geodnsEnabled} onChange={e=>setGeodnsEnabled(e.target.checked)} className="h-5 w-5" />
            </FormField>
            <div className="flex items-center space-x-2">
              <button type="button" className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded transition-colors" onClick={handleCreateClick}>Create Zone</button>
              <BulkImport endpoint={'/api/v1/zones/bulk'} onComplete={onBulkComplete} />
              <button className="text-sm text-gray-600 dark:text-gray-400 hover:underline" onClick={() => downloadTemplate('zones_template.csv', ['domain'], [['example.com'], ['test.io']])}>Template</button>
            </div>
          </div>
        ) : (
          <div className="grid gap-2 mb-4 max-w-md">
            <FormField label="Domain">
              <input className="w-full border dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded px-3 py-2" value={editDomain} onChange={e=>setEditDomain(e.target.value)} />
            </FormField>
            <FormField label="Zone Type">
              <select className="w-full border dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded px-3 py-2" value={editType} onChange={e=>setEditType(e.target.value)}>
                <option value="primary">primary</option>
                <option value="secondary">secondary</option>
              </select>
            </FormField>
            <FormField label="Enable GeoDNS">
              <input type="checkbox" checked={editGeodns} onChange={e=>setEditGeodns(e.target.checked)} className="h-5 w-5" />
            </FormField>
            <div className="flex items-center space-x-2">
              <button className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded" onClick={saveEdit}>Save</button>
              <button className="bg-gray-300 hover:bg-gray-400 text-gray-800 px-4 py-2 rounded" onClick={cancelEdit}>Cancel</button>
            </div>
          </div>
        )}
      </div>

      {/* Advanced Search */}
      <div className="mb-4">
        <input
          type="text"
          placeholder="Search zones by domain or ID..."
          value={searchTerm}
          onChange={(e) => handleSearch(e.target.value)}
          className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-700 dark:border-gray-600 dark:text-white dark:placeholder-gray-400 transition-all"
        />
        {filteredItems.length > 0 && (
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
            Found {filteredItems.length} zone{filteredItems.length !== 1 ? 's' : ''}
          </p>
        )}
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-gray-50 dark:bg-gray-700 border-b dark:border-gray-600">
              <SortableHeader 
                field="domain" 
                label="Domain" 
                sortConfig={sortConfig} 
                onSort={requestSort}
              />
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">Nameservers</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">Created</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">Type</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">GeoDNS</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <SkeletonTable rows={5} columns={6} />
            ) : pagination.currentItems.length > 0 ? (
              pagination.currentItems.map(z => (
                <FadeIn key={z.id}>
                  <tr className="border-b dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                    <td className="px-6 py-4 whitespace-nowrap text-gray-900 dark:text-gray-100">{z.domain}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-xs text-gray-500 dark:text-gray-400">
                      {zoneNameservers[z.id] ? (
                        <div className="flex flex-col">
                          {zoneNameservers[z.id].map((ns, i) => (
                            <span key={i}>{ns}</span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-gray-400">Loading...</span>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-xs text-gray-500 dark:text-gray-400">
                      {z.created_at ? new Date(z.created_at).toLocaleDateString() : 'N/A'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">{z.zone_type || 'primary'}</td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <input type="checkbox" checked={z.geodns_enabled} onChange={()=>toggleZoneGeo(z)} className="h-4 w-4" />
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap space-x-2">
                      <Link to={`/admin/zones/${z.id}/records`} className="text-blue-600 dark:text-blue-400 hover:underline font-medium">
                        Manage Records
                      </Link>
                      <button onClick={()=>startEdit(z)} className="text-green-600 hover:text-green-800">Edit</button>
                      <button onClick={()=>deleteZone(z)} className="text-red-600 hover:text-red-800">Delete</button>
                    </td>
                  </tr>
                </FadeIn>
              ))
            ) : (
              <tr>
                <td colSpan="6" className="px-6 py-4 text-center text-gray-500 dark:text-gray-400">
                  No zones found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <PaginationControls pagination={pagination} />
    </div>
  )
}
