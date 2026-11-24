import React from 'react'
import { X } from 'lucide-react'

export default function Modal({ title, open, onClose, children, wide = false }) {
  const dialogRef = React.useRef(null)
  React.useEffect(() => {
    if (!open) return
    const previousFocus = document.activeElement
    const dialog = dialogRef.current
    const focusable = () => Array.from(dialog?.querySelectorAll('a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])') || [])
    const focusTarget = focusable()[0] || dialog
    focusTarget?.focus()
    // a confirmation dialog on top handles Escape itself; do not close the dialog underneath it as well
    const onKey = (e) => {
      if (document.querySelector('[data-testid="confirm-dialog"]')) return
      if (e.key === 'Escape') onClose?.()
      if (e.key !== 'Tab') return
      const candidates = focusable()
      if (!candidates.length) {
        e.preventDefault()
        dialog?.focus()
        return
      }
      const firstFocusable = candidates[0]
      const lastFocusable = candidates[candidates.length - 1]
      if (e.shiftKey && (document.activeElement === firstFocusable || !dialog?.contains(document.activeElement))) {
        e.preventDefault()
        lastFocusable.focus()
      } else if (!e.shiftKey && (document.activeElement === lastFocusable || !dialog?.contains(document.activeElement))) {
        e.preventDefault()
        firstFocusable.focus()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => {
      window.removeEventListener('keydown', onKey)
      if (previousFocus instanceof HTMLElement && previousFocus.isConnected) previousFocus.focus()
    }
  }, [open, onClose])
  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-black/45 backdrop-blur-sm animate-fade-in" onClick={onClose}>
      <div ref={dialogRef} role="dialog" aria-modal="true" aria-label={title} tabIndex={-1}
        className={`card shadow-pop w-full ${wide ? 'max-w-4xl' : 'max-w-2xl'} max-h-[92vh] overflow-y-auto animate-slide-in`} onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 sm:px-6 py-4 border-b border-line sticky top-0 bg-surface z-10">
          <h3 className="font-display text-lg font-semibold tracking-[-0.02em] text-ink">{title}</h3>
          <button onClick={onClose} className="btn-icon" aria-label="Close dialog"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-5 sm:p-6">{children}</div>
      </div>
    </div>
  )
}
