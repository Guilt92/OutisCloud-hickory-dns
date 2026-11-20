import React from 'react'
import api from '../api/client'
import { useConfirm } from './ui'

// DNSSEC management for one zone: enable (key generation), the DS record to publish at the
// registrar, key rollover and a guarded disable.
export default function DnssecTab({ zone, canManage, onChanged }) {
  const askConfirm = useConfirm()
  const [info, setInfo] = React.useState(null)
  const [algorithm, setAlgorithm] = React.useState('ECDSAP256SHA256')
  const [msg, setMsg] = React.useState(null)
  const [busy, setBusy] = React.useState(false)
  const [confirmDs, setConfirmDs] = React.useState(false)
  const [confirmRetireDs, setConfirmRetireDs] = React.useState(false)
  const err = (e) => setMsg({ bad: true, text: e.response?.data?.details || e.response?.data?.error || e.message })

  const load = React.useCallback(async () => {
    try { setInfo((await api.get(`/api/v1/zones/${zone.id}/dnssec`)).data) } catch (e) { err(e) }
  }, [zone.id])
  React.useEffect(() => { load() }, [load])

  const act = async (path, body, ok) => {
    setBusy(true); setMsg(null)
    try {
      const r = await api.post(`/api/v1/zones/${zone.id}/dnssec/${path}`, body)
      setInfo(r.data)
      setMsg({ text: r.data?.publish_warning ? `${ok} (warning: ${r.data.publish_warning})` : ok, bad: !!r.data?.publish_warning })
      onChanged && onChanged()
    } catch (e) { err(e) }
    setBusy(false)
  }

  if (!info) return <p className="text-sm text-muted">{msg ? msg.text : 'Loading…'}</p>
  const rolling = info.keys.length > 1
  const currentAlgorithm = info.keys.find(k => k.status === 'active' || k.status === 'new')?.algorithm || algorithm
  return (
    <div className="space-y-3" data-testid="dnssec-tab">
      {msg && <div role={msg.bad ? 'alert' : 'status'} className={`text-sm px-3.5 py-2.5 rounded-[14px] border ${msg.bad ? 'border-danger-500/30 text-danger-600' : 'border-success-500/25 text-success-700'}`}>{msg.text}</div>}
      <p className="text-sm text-muted">
        Status: <b>{info.enabled ? 'signed' : 'not signed'}</b>
        {info.enabled && <span className="ml-2 text-xs text-muted">{info.next_steps}</span>}
      </p>

      {!info.enabled && canManage && (
        <div className="flex items-end gap-2">
          <label className="text-sm">Algorithm
            <select className="select ml-2" value={algorithm} onChange={e => setAlgorithm(e.target.value)}>
              <option value="ECDSAP256SHA256">ECDSA P-256 (13, recommended)</option>
              <option value="ECDSAP384SHA384">ECDSA P-384 (14)</option>
              <option value="ED25519">Ed25519 (15)</option>
            </select>
          </label>
          <button className="btn-primary btn-sm" disabled={busy} onClick={() => act('enable', { algorithm }, 'DNSSEC enabled - publish the DS record at your registrar')}>Enable DNSSEC</button>
        </div>
      )}
      {!info.enabled && <p className="text-xs text-muted">GeoDNS and DNSSEC cannot be combined on one zone: signed zones are served statically.</p>}

      {rolling && canManage && (
        <label className="text-xs flex items-center gap-2">
          <input type="checkbox" checked={confirmRetireDs} onChange={e => setConfirmRetireDs(e.target.checked)} />
          The replacement DS is published at the registrar and the old DS has expired from caches
        </label>
      )}
      {info.keys.map(k => (
        <div key={k.key_tag} className="border border-line rounded-[14px] p-3 text-xs space-y-1 bg-surface-2/60">
          <div><b>Key {k.key_tag}</b> · {k.algorithm} · {k.status === 'new' ? 'new (rollover)' : k.status}</div>
          {k.ds.map(d => (
            <div key={d.digest_type}>
              <span className="text-muted">DS ({d.digest_name}):</span>
              <code className="block break-all select-all" data-testid={`ds-${d.digest_type}`}>{d.text}</code>
            </div>
          ))}
          <div><span className="text-muted">DNSKEY:</span><code className="block break-all select-all">{k.dnskey}</code></div>
          {rolling && canManage && k.status !== 'new' && <button className="btn-sm btn-ghost" disabled={busy || !confirmRetireDs} title={confirmRetireDs ? '' : 'Confirm the replacement DS is published first'} onClick={async () => { if (await askConfirm({ title: `Retire key ${k.key_tag}?`, message: 'Only do this after the DS for the other key is published and the old DS has expired from caches.', confirmLabel: 'Retire key' })) act('rollover/complete', { retire_key_tag: k.key_tag }, `Key ${k.key_tag} retired`) }}>Retire this key</button>}
        </div>
      ))}

      {info.enabled && canManage && !rolling && (
        <button className="btn-sm btn-ghost" disabled={busy} onClick={() => act('rollover', { algorithm: currentAlgorithm }, 'Rollover started - publish the new DS, then retire the old key')}>Start key rollover</button>
      )}
      {info.enabled && canManage && (
        <div className="border-t border-line pt-3">
          <label className="text-xs flex items-center gap-2">
            <input type="checkbox" checked={confirmDs} onChange={e => setConfirmDs(e.target.checked)} />
            I have removed the DS record at the registrar and it has expired from caches
          </label>
          <button className="btn-sm mt-2 text-danger-500" disabled={busy || !confirmDs} onClick={async () => { if (await askConfirm({ title: 'Disable DNSSEC?', message: 'The zone will be served unsigned. Make sure the DS record is already removed at your registrar.', confirmLabel: 'Disable DNSSEC' })) act('disable', { confirm_ds_removed: true }, 'DNSSEC disabled') }}>Disable DNSSEC</button>
        </div>
      )}
    </div>
  )
}
