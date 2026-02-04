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
    const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/
    const ipv6 = /^[0-9a-fA-F:]+$/
    return ipv4.test(value) || ipv6.test(value) ? '' : 'invalid IP'
  },
}

/**
 * FormField component - wraps input with label and error display
 */
export function FormField({ label, error, children }) {
  return (
    <div className="mb-3">
      {label && <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{label}</label>}
      {children}
      {error && <div className="text-red-500 text-sm mt-1">{error}</div>}
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
      case 'success':
        return 'bg-green-500 text-white'
      case 'error':
        return 'bg-red-500 text-white'
      case 'warning':
        return 'bg-yellow-500 text-white'
      default:
        return 'bg-blue-500 text-white'
    }
  }

  return (
    <div className="fixed bottom-4 right-4 space-y-2 z-50">
      {notifications.map((n) => (
        <div key={n.id} className={`${getTypeStyles(n.type)} px-4 py-3 rounded shadow-lg flex items-center justify-between`}>
          <span>{n.message}</span>
          <button className="ml-4 font-bold" onClick={() => onRemove(n.id)}>×</button>
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
