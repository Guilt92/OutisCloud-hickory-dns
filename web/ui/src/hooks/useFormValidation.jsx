import React from 'react'

/**
 * useFormValidation - centralized form state with validation
 * Usage: const { values, errors, bind, setFieldValue, isValid } = useFormValidation(initialValues, validateFn)
 */
export function useFormValidation(initialValues, validateFn) {
  const [values, setValues] = React.useState(initialValues)
  const [errors, setErrors] = React.useState({})

  const validate = React.useCallback(() => {
    const errs = validateFn ? validateFn(values) : {}
    setErrors(errs)
    return Object.keys(errs).length === 0
  }, [values, validateFn])

  const bind = (name) => ({
    value: values[name] || '',
    onChange: (e) => {
      const val = e.target.value
      setValues((v) => ({ ...v, [name]: val }))
      if (errors[name]) {
        const errs = validateFn ? validateFn({ ...values, [name]: val }) : {}
        setErrors((e) => {
          const newErrs = { ...e }
          if (errs[name]) newErrs[name] = errs[name]
          else delete newErrs[name]
          return newErrs
        })
      }
    },
  })

  const setFieldValue = (name, value) => {
    setValues((v) => ({ ...v, [name]: value }))
  }

  const reset = () => {
    setValues(initialValues)
    setErrors({})
  }

  return { values, errors, bind, setFieldValue, validate, isValid: Object.keys(errors).length === 0, reset }
}

const isIPv4 = (value) => {
  const parts = value.split('.')
  return parts.length === 4 && parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false
    return Number(part) <= 255
  })
}

const isIPv6 = (value) => {
  const address = value.split('%')[0]
  if (!address.includes(':')) return false
  const halves = address.split('::')
  if (halves.length > 2) return false
  const expand = (part) => {
    if (!part) return []
    const groups = part.split(':')
    if (groups.some((group) => !/^[0-9a-f]{1,4}$/i.test(group))) {
      const last = groups[groups.length - 1]
      if (!last.includes('.') || !isIPv4(last)) return null
      groups.splice(groups.length - 1, 1, '0', '0')
    }
    return groups
  }
  const head = expand(halves[0])
  const tail = halves.length === 2 ? expand(halves[1]) : []
  if (!head || !tail) return false
  const count = head.length + tail.length
  return halves.length === 2 ? count <= 7 : count === 8
}

/**
 * Form validators
 */
export const validators = {
  required: (value) => !value || value.trim() === '' ? 'required' : '',
  email: (value) => {
    if (!value) return 'required'
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) ? '' : 'invalid email'
  },
  username: (value) => {
    if (!value) return 'required'
    if (value.length < 3) return 'min 3 chars'
    if (!/^[a-zA-Z0-9_-]+$/.test(value)) return 'only alphanumeric, _, -'
    return ''
  },
  domain: (value) => {
    if (!value) return 'required'
    return /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(value) ? '' : 'invalid domain'
  },
  ipAddress: (value) => {
    if (!value) return 'required'
    return isIPv4(value) || isIPv6(value) ? '' : 'invalid IP'
  },
}

/**
 * FormField component - wraps input with label and error display
 */
export function FormField({ label, error, htmlFor, children }) {
  return (
    <div className="mb-3">
      {label && <label className="form-label" htmlFor={htmlFor}>{label}</label>}
      {children}
      {error && <div role="alert" className="text-danger-500 text-sm mt-1.5">{error}</div>}
    </div>
  )
}

/**
 * useNotifications - notification management
 */
export function useNotifications() {
  const [notifications, setNotifications] = React.useState([])

  const add = React.useCallback((message, type = 'info', duration = 3000) => {
    const id = Date.now()
    setNotifications((n) => [...n, { id, message, type }])
    if (duration > 0) {
      setTimeout(() => {
        setNotifications((n) => n.filter((x) => x.id !== id))
      }, duration)
    }
    return id
  }, [])

  const remove = React.useCallback((id) => {
    setNotifications((n) => n.filter((x) => x.id !== id))
  }, [])

  const success = (msg, duration) => add(msg, 'success', duration)
  const error = (msg, duration) => add(msg, 'error', duration)
  const info = (msg, duration) => add(msg, 'info', duration)
  const warning = (msg, duration) => add(msg, 'warning', duration)

  return { notifications, add, remove, success, error, info, warning }
}

/**
 * NotificationsDisplay - display notifications at bottom right
 */
export function NotificationsDisplay({ notifications, onRemove }) {
  const getTypeStyles = (type) => {
    switch (type) {
      case 'success': return 'border-l-success-500'
      case 'error': return 'border-l-danger-500'
      case 'warning': return 'border-l-warning-500'
      default: return 'border-l-ink'
    }
  }

  return (
    <div className="fixed bottom-4 right-4 left-4 sm:left-auto space-y-2 z-50" aria-live="polite">
      {notifications.map((n) => (
        <div key={n.id} role={n.type === 'error' ? 'alert' : 'status'} className={`bg-surface border border-line border-l-2 ${getTypeStyles(n.type)} px-4 py-3 rounded-[14px] shadow-pop flex items-center justify-between gap-4 max-w-sm`}>
          <span className="text-sm text-ink">{n.message}</span>
          <button className="text-muted hover:text-ink text-lg leading-none" onClick={() => onRemove(n.id)} aria-label="Dismiss notification">×</button>
        </div>
      ))}
    </div>
  )
}

/**
 * exportAsCSV - helper to download data as CSV
 */
export function exportAsCSV(filename, headers, rows) {
  const csvContent = [
    headers.join(','),
    ...rows.map((row) => row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(',')),
  ].join('\n')

  const blob = new Blob([csvContent], { type: 'text/csv' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

/**
 * downloadTemplate - helper to download a CSV template
 */
export function downloadTemplate(filename, headers, exampleRows = []) {
  const rows = exampleRows.length > 0 ? exampleRows : [headers.map((h) => `example-${h}`)]
  exportAsCSV(filename, headers, rows)
}

/**
 * parseCSV - parse CSV text into array of objects
 */
export function parseCSV(csvText) {
  const lines = csvText.trim().split(/\r?\n/)
  const headers = lines[0].split(',').map((h) => h.trim())
  return lines.slice(1).map((line) => {
    const values = line.split(',').map((v) => v.trim())
    const obj = {}
    headers.forEach((h, i) => {
      obj[h] = values[i] || ''
    })
    return obj
  })
}
