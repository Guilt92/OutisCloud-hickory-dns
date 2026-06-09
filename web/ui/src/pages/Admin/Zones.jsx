import React from 'react'
import { motion } from 'framer-motion'
import api from '../../api/client'
import { Link } from 'react-router-dom'
import { Globe, Plus, Download, Search, Edit2, Trash2, RefreshCw, CheckSquare, Square } from 'lucide-react'
import BulkImport from '../../components/BulkImport'
import Notifications from '../../components/Notifications'
import { useFormValidation, validators, FormField, downloadTemplate } from '../../hooks/useFormValidation'
import { usePagination, useTableSort, useAdvancedSearch, PaginationControls, SortableHeader, FadeIn, SkeletonTable } from '../../hooks/useAdvancedUI'

export default function Zones(){
  const [zones, setZones] = React.useState([])
  const [loading, setLoading] = React.useState(false)
  const notify = React.useContext(Notifications)
  const { values, errors, bind, setFieldValue } = useFormValidation(
    { domain: '' },
    (vals) => ({ domain: validators.domain(vals.domain) })
  )
  const [geodnsEnabled, setGeodnsEnabled] = React.useState(false)
  const [editingZone, setEditingZone] = React.useState(null)
  const [editDomain, setEditDomain] = React.useState('')
  const [editType, setEditType] = React.useState('primary')
  const [editGeodns, setEditGeodns] = React.useState(false)
  const [zoneNameservers, setZoneNameservers] = React.useState({})
  const [creating, setCreating] = React.useState(false)

  const { searchTerm, filteredItems, handleSearch } = useAdvancedSearch(zones, ['domain', 'id'])
  const { sortedItems, sortConfig, requestSort } = useTableSort(filteredItems, { field: 'domain', order: 'asc' })
  const pagination = usePagination(sortedItems, 10)

  const load = async () => {
    setLoading(true)
    try {
      const r = await api.get('/api/v1/zones')
      const zonesData = r.data || []
      setZones(zonesData)
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
      notify?.error(e.response?.data?.error || e.message || 'Failed to load zones')
    } finally {
      setLoading(false)
    }
  }

  React.useEffect(() => {
    const token = localStorage.getItem('token')
    if (token) api.setToken(token)
    load()
  }, [])

  const handleCreateClick = async (e) => {
    e.preventDefault()
    e.stopPropagation()
    if (!values.domain || values.domain.trim() === '') {
      notify?.error('Please enter a domain name')
      return
    }
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$/
    if (!domainRegex.test(values.domain.trim())) {
      notify?.error('Please enter a valid domain name (e.g., example.com)')
      return
    }
    setCreating(true)
    try {
      const domain = values.domain.trim().endsWith('.') ? values.domain.trim() : values.domain.trim() + '.'
      const response = await api.post('/api/v1/zones', { domain, geodns_enabled: geodnsEnabled })
      setFieldValue('domain', '')
      setGeodnsEnabled(false)
      load()
      const nsList = response.data?.nameservers
      notify?.success(nsList?.length ? `Zone ${domain} created! Nameservers: ${nsList.join(', ')}` : `Zone ${domain} created`)
    } catch (err) {
      notify?.error(err.response?.data?.error || err.message || 'Error creating zone')
    } finally {
      setCreating(false)
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
      const domain = editDomain.endsWith('.') ? editDomain : editDomain + '.'
      await api.put(`/api/v1/zones/${editingZone.id}`, { domain, zone_type: editType, geodns_enabled: editGeodns })
      notify?.success('Zone updated')
      cancelEdit()
      load()
    } catch (e) {
      notify?.error(e.response?.data?.error || e.message || 'Error updating zone')
    }
  }

  const deleteZone = async (zone) => {
    if (!window.confirm(`Delete zone ${zone.domain}?`)) return
    try {
      await api.delete(`/api/v1/zones/${zone.id}`)
      notify?.success('Zone deleted')
      if (editingZone?.id === zone.id) cancelEdit()
      load()
    } catch (e) {
      notify?.error(e.response?.data?.error || e.message || 'Error deleting zone')
    }
  }

  const toggleZoneGeo = async (zone) => {
    try {
      await api.put(`/api/v1/zones/${zone.id}`, { geodns_enabled: !zone.geodns_enabled })
      load()
    } catch (e) {
      notify?.error(e.response?.data?.error || e.message || 'Failed to update zone')
    }
  }

  const onBulkComplete = () => { load(); notify?.success('Zones imported') }

  return (
    <div className="page">
      {/* Header */}
      <div className="section-header">
        <div className="flex items-center gap-3">
          <div className="icon-box bg-primary-100 dark:bg-primary-900/30">
            <Globe className="w-5 h-5 text-primary-600 dark:text-primary-400" />
          </div>
          <div>
            <h1 className="section-title">Zones</h1>
            <p className="section-desc">Manage DNS zones and domain delegation</p>
          </div>
        </div>
      </div>

      {/* Create / Edit Card */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        className="card"
      >
        <div className="p-5">
          {!editingZone ? (
            <div className="flex flex-col lg:flex-row lg:items-end gap-4">
              <div className="flex-1 max-w-md">
                <FormField label="Domain" error={errors.domain}>
                  <input
                    className="input"
                    placeholder="example.com"
                    {...bind('domain')}
                  />
                </FormField>
              </div>
              <div className="flex items-center gap-3 pb-0.5">
                <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={geodnsEnabled}
                    onChange={e => setGeodnsEnabled(e.target.checked)}
                    className="w-4 h-4 rounded border-gray-300 dark:border-gray-600 text-primary-600 focus:ring-primary-500"
                  />
                  GeoDNS
                </label>
              </div>
              <div className="flex items-center gap-2 pb-0.5">
                <button
                  type="button"
                  className="btn-primary"
                  onClick={handleCreateClick}
                  disabled={creating}
                >
                  {creating ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                  {creating ? 'Creating...' : 'Create Zone'}
                </button>
                <BulkImport endpoint="/api/v1/zones/bulk" onComplete={onBulkComplete} />
              </div>
            </div>
          ) : (
            <div className="flex flex-col lg:flex-row lg:items-end gap-4">
              <div className="flex-1 max-w-md">
                <FormField label="Domain">
                  <input className="input" value={editDomain} onChange={e => setEditDomain(e.target.value)} />
                </FormField>
              </div>
              <div>
                <FormField label="Zone Type">
                  <select className="select" value={editType} onChange={e => setEditType(e.target.value)}>
                    <option value="primary">Primary</option>
                    <option value="secondary">Secondary</option>
                  </select>
                </FormField>
              </div>
              <div className="flex items-center gap-3 pb-0.5">
                <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={editGeodns}
                    onChange={e => setEditGeodns(e.target.checked)}
                    className="w-4 h-4 rounded border-gray-300 dark:border-gray-600 text-primary-600 focus:ring-primary-500"
                  />
                  GeoDNS
                </label>
              </div>
              <div className="flex items-center gap-2 pb-0.5">
                <button className="btn-success" onClick={saveEdit}>
                  <CheckSquare className="w-4 h-4" />
                  Save
                </button>
                <button className="btn-secondary" onClick={cancelEdit}>
                  Cancel
                </button>
              </div>
            </div>
          )}
        </div>
      </motion.div>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 pointer-events-none" />
        <input
          type="text"
          placeholder="Search zones by domain or ID..."
          value={searchTerm}
          onChange={(e) => handleSearch(e.target.value)}
          className="input pl-10"
        />
        {filteredItems.length > 0 && (
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-1.5">
            {filteredItems.length} zone{filteredItems.length !== 1 ? 's' : ''} found
          </p>
        )}
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="table">
            <thead>
              <tr>
                <SortableHeader field="domain" label="Domain" sortConfig={sortConfig} onSort={requestSort} />
                <th>Nameservers</th>
                <th>Created</th>
                <th>Type</th>
                <th>GeoDNS</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <SkeletonTable rows={5} columns={6} />
              ) : pagination.currentItems.length > 0 ? (
                pagination.currentItems.map(z => (
                  <FadeIn key={z.id}>
                    <tr>
                      <td className="font-medium text-gray-900 dark:text-white">{z.domain}</td>
                      <td>
                        <div className="flex flex-col gap-0.5">
                          {zoneNameservers[z.id] ? (
                            zoneNameservers[z.id].length > 0 ? (
                              zoneNameservers[z.id].map((ns, i) => (
                                <span key={i} className="text-xs text-gray-500 dark:text-gray-400 font-mono">{ns}</span>
                              ))
                            ) : (
                              <span className="text-xs text-gray-400 italic">No NS records</span>
                            )
                          ) : (
                            <span className="text-xs text-gray-400 animate-pulse">Loading...</span>
                          )}
                        </div>
                      </td>
                      <td className="text-sm text-gray-500 dark:text-gray-400">
                        {z.created_at ? new Date(z.created_at).toLocaleDateString() : 'N/A'}
                      </td>
                      <td>
                        <span className={`badge ${z.zone_type === 'secondary' ? 'badge-warning' : 'badge-primary'}`}>
                          {z.zone_type || 'primary'}
                        </span>
                      </td>
                      <td>
                        <button
                          onClick={() => toggleZoneGeo(z)}
                          className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium transition-colors ${
                            z.geodns_enabled
                              ? 'bg-success-100 text-success-700 dark:bg-success-900/30 dark:text-success-400'
                              : 'bg-gray-100 text-gray-500 dark:bg-gray-700 dark:text-gray-400'
                          }`}
                        >
                          {z.geodns_enabled ? <CheckSquare className="w-3 h-3" /> : <Square className="w-3 h-3" />}
                          {z.geodns_enabled ? 'Enabled' : 'Disabled'}
                        </button>
                      </td>
                      <td className="text-right">
                        <div className="flex items-center justify-end gap-1">
                          <Link
                            to={`/admin/zones/${z.id}/records`}
                            className="btn-sm btn-ghost"
                          >
                            Records
                          </Link>
                          <button onClick={() => startEdit(z)} className="btn-sm btn-ghost">
                            <Edit2 className="w-3.5 h-3.5" />
                          </button>
                          <button onClick={() => deleteZone(z)} className="btn-sm text-red-600 hover:bg-red-50 dark:text-red-400 dark:hover:bg-red-900/20 rounded-lg transition-colors">
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  </FadeIn>
                ))
              ) : (
                <tr>
                  <td colSpan="6" className="text-center text-gray-400 dark:text-gray-500 py-12">
                    <Globe className="w-12 h-12 mx-auto mb-3 text-gray-300 dark:text-gray-600" />
                    <p className="font-medium text-gray-600 dark:text-gray-400 mb-1">No zones found</p>
                    <p className="text-sm">Create a zone to get started.</p>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <div className="px-5 py-3 border-t border-gray-100 dark:border-gray-700">
          <PaginationControls pagination={pagination} />
        </div>
      </div>
    </div>
  )
}
