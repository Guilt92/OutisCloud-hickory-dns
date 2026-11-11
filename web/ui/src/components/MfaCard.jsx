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
      <h3 className="font-semibold text-gray-900 dark:text-white">Two-factor authentication</h3>
      {msg && <div className={`text-sm px-3 py-2 rounded-lg ${msg.bad ? 'bg-red-50 text-red-600' : 'bg-green-50 text-green-700'}`}>{msg.text}</div>}
      {enabled === null && <p className="text-sm text-gray-500">Loading...</p>}
      {enabled === false && !setup && (
        <><p className="text-sm text-gray-600 dark:text-gray-300">Protect your account with an authenticator app (TOTP).</p>
          <button className="btn-primary" onClick={start}>Set up</button></>
      )}
      {setup && (
        <div className="space-y-2 text-sm">
          <p>Add this key to your authenticator app, then enter the 6-digit code to confirm:</p>
          <pre className="bg-gray-50 dark:bg-gray-900 p-2 rounded select-all break-all">{setup.secret}</pre>
          <a className="text-primary-600 break-all" href={setup.otpauth_url}>{setup.otpauth_url}</a>
          <div className="flex gap-2"><input className="input w-32" inputMode="numeric" maxLength={6} placeholder="123456" value={code} onChange={e => setCode(e.target.value.replace(/\D/g, ''))} />
            <button className="btn-primary" onClick={enable} disabled={code.length !== 6}>Turn on</button></div>
        </div>
      )}
      {enabled === true && (
        <div className="space-y-2 text-sm">
          <p className="text-green-700">Enabled. Sign-in requires a code.</p>
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
