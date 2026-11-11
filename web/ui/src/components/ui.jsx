import React from 'react'
import { Sun, Moon, AlertTriangle, Inbox } from 'lucide-react'
import clsx from 'clsx'
import { Link } from 'react-router-dom'
import { useUIStore } from '../store'

/* ---------------------------------------------------------------------------
   Shared building blocks of the OutisCloud design system.
   Everything here reads theme tokens from index.css, so both dashboards and
   both themes stay consistent.
   --------------------------------------------------------------------------- */

/** Original mark: two data streams crossing, drawn as flowing lines. */
export function LogoMark({ className = 'w-8 h-8' }) {
  return (
    <svg viewBox="0 0 64 64" className={className} aria-hidden="true">
      <rect width="64" height="64" rx="14" className="fill-[#0B0D12]" />
      <path d="M10 40c8 0 10-16 18-16s10 16 18 16 6-9 8-9" fill="none" stroke="#F5F020" strokeWidth="5" strokeLinecap="round" />
      <path d="M10 28c8 0 10-10 18-10s10 10 18 10 6-6 8-6" fill="none" stroke="#5B7CFA" strokeWidth="3" strokeLinecap="round" opacity=".85" />
    </svg>
  )
}

export function Brand({ compact = false }) {
  return (
    <span className="inline-flex items-center gap-2.5">
      <LogoMark />
      {!compact && <span className="font-display text-lg font-semibold tracking-tight text-ink">Outis<span className="text-primary-700 dark:text-accent">Cloud</span></span>}
    </span>
  )
}

/** Decorative "data in motion" lines. Pure SVG, no data implied. */
export function FlowArt({ className = '' }) {
  const lines = Array.from({ length: 9 }, (_, i) => i)
  return (
    <svg viewBox="0 0 800 400" preserveAspectRatio="xMidYMid slice" className={clsx('pointer-events-none', className)} aria-hidden="true">
      <defs>
        <linearGradient id="flow-a" x1="0" x2="1">
          <stop offset="0" stopColor="#F5F020" stopOpacity="0" />
          <stop offset=".5" stopColor="#F5F020" stopOpacity=".85" />
          <stop offset="1" stopColor="#5B7CFA" stopOpacity="0" />
        </linearGradient>
        <linearGradient id="flow-b" x1="0" x2="1">
          <stop offset="0" stopColor="#9B6BFF" stopOpacity="0" />
          <stop offset=".6" stopColor="#5B7CFA" stopOpacity=".6" />
          <stop offset="1" stopColor="#F5F020" stopOpacity="0" />
        </linearGradient>
      </defs>
      {lines.map((i) => {
        const y = 60 + i * 34
        const amp = 26 + (i % 4) * 12
        const d = `M-20 ${y} C 140 ${y - amp}, 260 ${y + amp}, 400 ${y} S 660 ${y - amp}, 820 ${y + amp / 2}`
        return (
          <path key={i} d={d} fill="none" stroke={i % 3 === 0 ? 'url(#flow-b)' : 'url(#flow-a)'} strokeWidth={i % 3 === 0 ? 1 : 1.6}
            strokeDasharray={i % 2 ? '2 14' : '90 40'} className="animate-flow" style={{ animationDuration: `${12 + i * 2}s` }} opacity={0.35 + (i % 4) * 0.15} />
        )
      })}
    </svg>
  )
}

export function ThemeToggle({ className = '' }) {
  const { theme, setTheme } = useUIStore()
  const dark = theme === 'dark'
  return (
    <button type="button" onClick={() => setTheme(dark ? 'light' : 'dark')} className={clsx('btn-icon', className)}
      aria-label={dark ? 'Switch to light theme' : 'Switch to dark theme'} title={dark ? 'Light theme' : 'Dark theme'} data-testid="theme-toggle">
      {dark ? <Sun className="w-[18px] h-[18px]" /> : <Moon className="w-[18px] h-[18px]" />}
    </button>
  )
}

/** Applies the theme class to <html>; mounted once at the app root so every route (incl. login) follows it. */
export function ThemeSync() {
  const theme = useUIStore((s) => s.theme)
  React.useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark')
    const m = document.querySelector('meta[name="theme-color"]')
    if (m) m.setAttribute('content', theme === 'dark' ? '#0B0D12' : '#F6F6F2')
  }, [theme])
  return null
}

export function PageHeader({ eyebrow, title, description, actions, icon: Icon }) {
  return (
    <div className="flex flex-col md:flex-row md:items-end md:justify-between gap-4 mb-6">
      <div className="flex items-start gap-3 min-w-0">
        {Icon && <div className="icon-box mt-0.5"><Icon className="w-5 h-5" /></div>}
        <div className="min-w-0">
          {eyebrow && <p className="eyebrow mb-1">{eyebrow}</p>}
          <h1 className="section-title">{title}</h1>
          {description && <p className="section-desc max-w-2xl">{description}</p>}
        </div>
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}

export function StatCard({ icon: Icon, label, value, hint, tone = 'neutral', to, loading }) {
  const toneDot = { neutral: '', ok: 'dot-ok', warn: 'dot-warn', bad: 'dot-bad' }[tone]
  const body = (
    <div className="card p-5 h-full transition-colors hover:border-muted/50" data-testid={`stat-${String(label).toLowerCase().replace(/\s+/g, '-')}`}>
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-medium text-muted">{label}</span>
        {Icon && <Icon className="w-4 h-4 text-muted" />}
      </div>
      {loading ? <div className="skeleton h-8 w-20" /> : (
        <p className="font-display text-3xl font-semibold tracking-tight text-ink tabular-nums flex items-center gap-2">
          {toneDot && <span className={toneDot} />}{value}
        </p>
      )}
      {hint && <p className="text-xs text-muted mt-1.5">{hint}</p>}
    </div>
  )
  return to ? <Link to={to} className="block">{body}</Link> : body
}

export function StatusBadge({ status, children }) {
  const map = {
    ok: 'badge-success', active: 'badge-success', running: 'badge-success', online: 'badge-success', synced: 'badge-success',
    warn: 'badge-warning', pending: 'badge-warning', behind: 'badge-warning', degraded: 'badge-warning',
    bad: 'badge-danger', failed: 'badge-danger', offline: 'badge-danger', error: 'badge-danger',
    off: 'badge-default', disabled: 'badge-default', unknown: 'badge-default',
  }
  return <span className={map[String(status).toLowerCase()] || 'badge-default'}>{children ?? status}</span>
}

export function EmptyState({ icon: Icon = Inbox, title, description, action }) {
  return (
    <div className="py-14 px-6 text-center" data-testid="empty-state">
      <div className="mx-auto mb-4 w-12 h-12 rounded-2xl border border-line bg-surface-2 flex items-center justify-center"><Icon className="w-5 h-5 text-muted" /></div>
      <p className="font-display font-semibold text-ink">{title}</p>
      {description && <p className="text-sm text-muted mt-1 max-w-sm mx-auto">{description}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}

export function ErrorState({ title = 'Something went wrong', description, onRetry }) {
  return (
    <div className="card p-6 flex items-start gap-3 border-danger-500/40" role="alert">
      <AlertTriangle className="w-5 h-5 text-danger-500 mt-0.5" />
      <div className="flex-1">
        <p className="font-display font-semibold text-ink">{title}</p>
        {description && <p className="text-sm text-muted mt-0.5">{description}</p>}
      </div>
      {onRetry && <button className="btn-secondary btn-sm" onClick={onRetry}>Retry</button>}
    </div>
  )
}

export function SkeletonRows({ rows = 5, cols = 4 }) {
  return Array.from({ length: rows }, (_, r) => (
    <tr key={r}>{Array.from({ length: cols }, (_, c) => <td key={c}><div className="skeleton h-4 w-full max-w-[160px]" /></td>)}</tr>
  ))
}

/* ---------------- confirmation dialog (replaces window.confirm) ---------------- */
const ConfirmContext = React.createContext(() => Promise.resolve(false))
export const useConfirm = () => React.useContext(ConfirmContext)

export function ConfirmProvider({ children }) {
  const [state, setState] = React.useState(null)
  const confirm = React.useCallback((opts) => new Promise((resolve) => setState({ ...opts, resolve })), [])
  const close = (v) => { state?.resolve(v); setState(null) }
  React.useEffect(() => {
    if (!state) return
    const onKey = (e) => { if (e.key === 'Escape') close(false) }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  })
  return (
    <ConfirmContext.Provider value={confirm}>
      {children}
      {state && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-fade-in" onClick={() => close(false)}>
          <div role="alertdialog" aria-modal="true" aria-labelledby="confirm-title" data-testid="confirm-dialog"
            className="card w-full max-w-md p-6 shadow-pop animate-slide-in" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-start gap-3">
              {state.danger !== false && <div className="w-9 h-9 rounded-lg bg-danger-500/10 border border-danger-500/30 flex items-center justify-center"><AlertTriangle className="w-4 h-4 text-danger-500" /></div>}
              <div>
                <h3 id="confirm-title" className="font-display text-lg font-semibold text-ink">{state.title || 'Are you sure?'}</h3>
                {state.message && <p className="text-sm text-muted mt-1.5">{state.message}</p>}
              </div>
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <button className="btn-secondary" onClick={() => close(false)} autoFocus>{state.cancelLabel || 'Cancel'}</button>
              <button className={state.danger === false ? 'btn-primary' : 'btn-danger'} onClick={() => close(true)} data-testid="confirm-yes">{state.confirmLabel || 'Confirm'}</button>
            </div>
          </div>
        </div>
      )}
    </ConfirmContext.Provider>
  )
}
