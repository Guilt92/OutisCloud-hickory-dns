import React from 'react'
import { X } from 'lucide-react'

export default function Modal({ title, open, onClose, children, wide = false }) {
  React.useEffect(() => {
    if (!open) return
    // a confirmation dialog on top handles Escape itself; do not close the dialog underneath it as well
    const onKey = (e) => { if (e.key === 'Escape' && !document.querySelector('[data-testid="confirm-dialog"]')) onClose && onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])
  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-black/45 backdrop-blur-sm animate-fade-in" onClick={onClose}>
      <div role="dialog" aria-modal="true" aria-label={title}
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
