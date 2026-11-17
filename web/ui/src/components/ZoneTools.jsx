import React from 'react'
import api from '../api/client'
import Modal from './Modal'
import DnssecTab from './DnssecTab'
import { useConfirm } from './ui'

// Sharing, history/rollback and domain verification for one zone.
export default function ZoneTools({ zone, onClose, onChanged }) {
  const askConfirm = useConfirm()
  const [tab, setTab] = React.useState('sharing')
  const [members, setMembers] = React.useState([])
  const [revisions, setRevisions] = React.useState([])
  const [username, setUsername] = React.useState('')
  const [role, setRole] = React.useState('viewer')
  const [msg, setMsg] = React.useState(null)
  const [busy, setBusy] = React.useState(false)
  const [verification, setVerification] = React.useState(null)
  const owner = zone.access === 'admin' || zone.access === 'owner'
  const err = (e) => setMsg({ bad: true, text: e.response?.data?.details || e.response?.data?.error || e.message })

  const load = React.useCallback(async () => {
    try { setMembers((await api.get(`/api/v1/zones/${zone.id}/members`)).data || []) } catch (e) { err(e) }
    try { setRevisions((await api.get(`/api/v1/zones/${zone.id}/revisions`)).data || []) } catch (e) { err(e) }
    if (zone.status === 'pending') { try { setVerification((await api.get(`/api/v1/zones/${zone.id}`)).data?.verification || null) } catch (e) { err(e) } }
  }, [zone.id, zone.status])
  React.useEffect(() => { load() }, [load])

  const share = async () => {
    setBusy(true); setMsg(null)
    try { await api.put(`/api/v1/zones/${zone.id}/members`, { username, role }); setUsername(''); await load(); setMsg({ text: 'Shared' }) }
    catch (e) { err(e) }
    setBusy(false)
  }
  const unshare = async (m) => {
    setBusy(true); setMsg(null)
    try { await api.delete(`/api/v1/zones/${zone.id}/members/${m.user_id}`); await load() } catch (e) { err(e) }
    setBusy(false)
  }
  const restore = async (r) => {
    if (!(await askConfirm({ title: 'Restore this revision?', message: `Restore the zone to the state of ${new Date(r.created_at).toLocaleString()}? The current state is saved as a revision first.`, confirmLabel: 'Restore', danger: false }))) return
    setBusy(true); setMsg(null)
    try { await api.post(`/api/v1/zones/${zone.id}/revisions/${r.id}/restore`, {}); await load(); setMsg({ text: 'Restored and published' }); onChanged && onChanged() }
    catch (e) { err(e) }
    setBusy(false)
  }
  const verify = async () => {
    setBusy(true); setMsg(null)
    try { await api.post(`/api/v1/zones/${zone.id}/verify`, {}); setMsg({ text: 'Domain verified - zone is now active' }); onChanged && onChanged() }
    catch (e) { err(e) }
    setBusy(false)
  }

  const tabs = [['sharing', 'Sharing'], ['history', 'History'], ['dnssec', 'DNSSEC'], ...(zone.status === 'pending' ? [['verify', 'Verification']] : [])]
  return (
    <Modal open={true} onClose={onClose} title={`Manage ${zone.domain}`}>
      <div className="flex gap-2 mb-4">
        {tabs.map(([id, label]) => (
          <button key={id} onClick={() => setTab(id)} className={`btn-sm ${tab === id ? 'btn-primary' : 'btn-ghost'}`}>{label}</button>
        ))}
      </div>
      {msg && <div role={msg.bad ? 'alert' : 'status'} className={`mb-3 text-sm px-3.5 py-2.5 rounded-[14px] border ${msg.bad ? 'border-danger-500/30 text-danger-600' : 'border-success-500/25 text-success-700'}`}>{msg.text}</div>}

      {tab === 'sharing' && (
        <div className="space-y-3">
          <table className="table"><thead><tr><th>User</th><th>Role</th><th /></tr></thead>
            <tbody>
              {members.length === 0 && <tr><td colSpan="3" className="text-muted text-sm">Not shared with anyone</td></tr>}
              {members.map(m => (
                <tr key={m.user_id}><td>{m.username}</td><td>{m.role}</td>
                  <td className="text-right">{owner && <button className="btn-sm btn-ghost" disabled={busy} onClick={() => unshare(m)}>Remove</button>}</td></tr>
              ))}
            </tbody></table>
          {owner ? (
            <div className="flex gap-2 items-end">
              <div className="flex-1"><label className="form-label">Username</label>
                <input className="input" value={username} onChange={e => setUsername(e.target.value)} placeholder="username" /></div>
              <div><label className="form-label">Access</label>
                <select className="select" value={role} onChange={e => setRole(e.target.value)}>
                  <option value="viewer">Viewer (read only)</option><option value="editor">Editor (records + geo rules)</option></select></div>
              <button className="btn-primary" disabled={busy || !username.trim()} onClick={share}>Share</button>
            </div>
          ) : <p className="text-sm text-muted">Only the zone owner can change sharing.</p>}
        </div>
      )}

      {tab === 'dnssec' && <DnssecTab zone={zone} canManage={owner} onChanged={onChanged} />}

      {tab === 'history' && (
        <div className="space-y-2">
          <table className="table"><thead><tr><th>When</th><th>By</th><th>Change</th><th>Records</th><th /></tr></thead>
            <tbody>
              {revisions.length === 0 && <tr><td colSpan="5" className="text-muted text-sm">No revisions yet</td></tr>}
              {revisions.map(r => (
                <tr key={r.id}><td>{new Date(r.created_at).toLocaleString()}</td><td>{r.user || '-'}</td><td>{r.reason}</td><td>{r.record_count}</td>
                  <td className="text-right">{owner && <button className="btn-sm btn-ghost" disabled={busy} onClick={() => restore(r)}>Restore</button>}</td></tr>
              ))}
            </tbody></table>
          {!owner && <p className="text-sm text-muted">Only the zone owner can restore a revision.</p>}
        </div>
      )}

      {tab === 'verify' && (
        <div className="space-y-3 text-sm">
          <p>This zone is <b>pending</b>: it is not served until you prove control of <b>{zone.domain}</b>.</p>
          <p>Publish this TXT record at your current DNS provider, then click Verify:</p>
          <pre className="bg-surface-2 border border-line p-3 rounded-[14px] text-xs overflow-x-auto font-mono">{verification ? `${verification.name}.  TXT  "${verification.value}"` : 'loading…'}</pre>
          <button className="btn-primary" disabled={busy} onClick={verify}>Verify domain</button>
        </div>
      )}
    </Modal>
  )
}
