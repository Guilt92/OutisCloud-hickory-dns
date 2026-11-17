import React from 'react'
import api from '../api/client'

// Two-factor authentication (TOTP) enrolment for the signed-in user.
export default function MfaCard() {
  const [enabled, setEnabled] = React.useState(null)
  const [setup, setSetup] = React.useState(null)
  const [code, setCode] = React.useState('')
  const [password, setPassword] = React.useState('')
  const [msg, setMsg] = React.useState(null)
  const err = (e) => setMsg({ bad: true, text: e.response?.data?.error || e.message })

  React.useEffect(() => {
    api.get('/api/v1/auth/me').then(r => setEnabled(!!r.data?.mfaEnabled)).catch(() => setEnabled(false))
  }, [])

  const start = async () => { setMsg(null); try { setSetup((await api.post('/api/v1/auth/mfa/setup', {})).data) } catch (e) { err(e) } }
  const enable = async () => {
    setMsg(null)
    try { await api.post('/api/v1/auth/mfa/enable', { code }); setEnabled(true); setSetup(null); setCode(''); setMsg({ text: 'Two-factor authentication is on' }) } catch (e) { err(e) }
  }
  const disable = async () => {
    setMsg(null)
    try { await api.post('/api/v1/auth/mfa/disable', { code, password }); setEnabled(false); setCode(''); setPassword(''); setMsg({ text: 'Two-factor authentication is off' }) } catch (e) { err(e) }
  }

  return (
    <div className="card p-5 space-y-3">
      <h3 className="font-semibold text-ink">Two-factor authentication</h3>
      {msg && <div role={msg.bad ? 'alert' : 'status'} className={`text-sm px-3.5 py-2.5 rounded-[14px] border ${msg.bad ? 'border-danger-500/30 text-danger-600' : 'border-success-500/25 text-success-700'}`}>{msg.text}</div>}
      {enabled === null && <p className="text-sm text-muted">Loading…</p>}
      {enabled === false && !setup && (
        <><p className="text-sm text-muted">Protect your account with an authenticator app (TOTP).</p>
          <button className="btn-primary" onClick={start}>Set up</button></>
      )}
      {setup && (
        <div className="space-y-2 text-sm">
          <p>Add this key to your authenticator app, then enter the 6-digit code to confirm:</p>
          <pre className="bg-surface-2 border border-line p-2.5 rounded-[12px] select-all break-all font-mono text-xs">{setup.secret}</pre>
          <a className="text-ink underline underline-offset-2 break-all" href={setup.otpauth_url}>{setup.otpauth_url}</a>
          <div className="flex gap-2"><input className="input w-32" inputMode="numeric" maxLength={6} placeholder="123456" value={code} onChange={e => setCode(e.target.value.replace(/\D/g, ''))} />
            <button className="btn-primary" onClick={enable} disabled={code.length !== 6}>Turn on</button></div>
        </div>
      )}
      {enabled === true && (
        <div className="space-y-2 text-sm">
          <p className="text-success-600">Enabled. Sign-in requires a code.</p>
          <div className="flex gap-2 flex-wrap">
            <input className="input w-48" type="password" placeholder="password" value={password} onChange={e => setPassword(e.target.value)} />
            <input className="input w-32" inputMode="numeric" maxLength={6} placeholder="code" value={code} onChange={e => setCode(e.target.value.replace(/\D/g, ''))} />
            <button className="btn-secondary" onClick={disable} disabled={code.length !== 6 || !password}>Turn off</button>
          </div>
        </div>
      )}
    </div>
  )
}
