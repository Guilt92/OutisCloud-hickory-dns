import React from 'react'
import { createRoot } from 'react-dom/client'
import Modal from '../../src/components/Modal'

function Harness() {
  const [open, setOpen] = React.useState(false)
  return <>
    <button onClick={() => setOpen(true)}>Open dialog</button>
    <Modal title="Focus test" open={open} onClose={() => setOpen(false)}>
      <button>First action</button>
      <button>Last action</button>
    </Modal>
  </>
}

createRoot(document.getElementById('root')).render(<Harness />)
