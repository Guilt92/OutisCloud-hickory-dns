import React from 'react'
import api from '../api/client'

// DNSSEC management for one zone: enable (key generation), the DS record to publish at the
// registrar, key rollover and a guarded disable.
export default function DnssecTab({ zone, canManage, onChanged }) {
  const [info, setInfo] = React.useState(null)
  const [algorithm, setAlgorithm] = React.useState('ECDSAP256SHA256')
  const [msg, setMsg] = React.useState(null)
  const [busy, setBusy] = React.useState(false)
  const [confirmDs, setConfirmDs] = React.useState(false)
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

  if (!info) return <p className="text-sm text-gray-500">{msg ? msg.text : 'Loading...'}</p>
  const rolling = info.keys.length > 1
  return (
    <div className="space-y-3" data-testid="dnssec-tab">
      {msg && <div className={`text-sm px-3 py-2 rounded-lg ${msg.bad ? 'bg-red-50 text-red-600' : 'bg-green-50 text-green-700'}`}>{msg.text}</div>}
      <p className="text-sm text-gray-600 dark:text-gray-300">
        Status: <b>{info.enabled ? 'signed' : 'not signed'}</b>
        {info.enabled && <span className="ml-2 text-xs text-gray-500">{info.next_steps}</span>}
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
      {!info.enabled && <p className="text-xs text-gray-500">GeoDNS and DNSSEC cannot be combined on one zone: signed zones are served statically.</p>}

      {info.keys.map(k => (
        <div key={k.key_tag} className="border border-gray-200 dark:border-gray-700 rounded-lg p-3 text-xs space-y-1">
          <div><b>Key {k.key_tag}</b> · {k.algorithm} · {k.status === 'new' ? 'new (rollover)' : k.status}</div>
          {k.ds.map(d => (
            <div key={d.digest_type}>
              <span className="text-gray-500">DS ({d.digest_name}):</span>
              <code className="block break-all select-all" data-testid={`ds-${d.digest_type}`}>{d.text}</code>
            </div>
          ))}
          <div><span className="text-gray-500">DNSKEY:</span><code className="block break-all select-all">{k.dnskey}</code></div>
          {rolling && canManage && <button className="btn-sm btn-ghost" disabled={busy} onClick={() => confirm(`Retire key ${k.key_tag}? Only do this after the DS for the other key is published and the old DS has expired from caches.`) && act('rollover/complete', { retire_key_tag: k.key_tag }, `Key ${k.key_tag} retired`)}>Retire this key</button>}
        </div>
      ))}

      {info.enabled && canManage && !rolling && (
        <button className="btn-sm btn-ghost" disabled={busy} onClick={() => act('rollover', { algorithm: 'ECDSAP256SHA256' }, 'Rollover started - publish the new DS, then retire the old key')}>Start key rollover</button>
      )}
      {info.enabled && canManage && (
        <div className="border-t border-gray-100 dark:border-gray-700 pt-3">
          <label className="text-xs flex items-center gap-2">
            <input type="checkbox" checked={confirmDs} onChange={e => setConfirmDs(e.target.checked)} />
            I have removed the DS record at the registrar and it has expired from caches
          </label>
          <button className="btn-sm mt-2 text-red-600" disabled={busy || !confirmDs} onClick={() => act('disable', { confirm_ds_removed: true }, 'DNSSEC disabled')}>Disable DNSSEC</button>
        </div>
      )}
    </div>
  )
}
