import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import { Brand } from '../components/Layout'

export default function Setup() {
  const [root, setRoot] = useState('')
  const [detected, setDetected] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const nav = useNavigate()

  useEffect(() => {
    api.getSetup().then((s) => {
      if (s.complete) { nav('/', { replace: true }); return }
      setRoot(s.results_root || s.detected || '')
      setDetected(s.detected || '')
    }).catch(() => {})
  }, [])

  async function save() {
    setBusy(true); setError('')
    try {
      await api.saveSetup(root.trim())
      nav('/', { replace: true })
    } catch (e) { setError(e.message); setBusy(false) }
  }

  return (
    <div className="grid min-h-screen place-items-center bg-bg px-5">
      <div className="w-full max-w-lg">
        <div className="mb-6"><Brand link={false} tag={false} /></div>
        <div className="card p-6">
          <h1 className="text-lg font-semibold text-ink">Where should results be saved?</h1>
          <p className="mt-2 text-sm text-mute">
            Each project gets its own folder here, with a sub-folder per tool. Use a
            path on your Windows drive via the WSL mount so you can open the files in
            Windows. You can change this later in Settings.
          </p>

          <label className="label mt-5">Results folder</label>
          <input className="input font-mono text-[13px]" value={root} autoFocus
                 onChange={(e) => setRoot(e.target.value)}
                 onKeyDown={(e) => e.key === 'Enter' && root.trim() && save()} />
          {detected && detected !== root && (
            <button className="mt-2 text-xs text-brand hover:underline" onClick={() => setRoot(detected)}>
              Use detected path: {detected}
            </button>
          )}
          <p className="mt-2 text-xs text-faint">
            Example: <span className="font-mono">/mnt/c/Users/you/lasy</span>. The app files and
            database stay on the Kali side — only tool output lands here.
          </p>

          {error && <p className="mt-3 text-sm text-crit">{error}</p>}
          <button className="btn-primary mt-5 w-full" disabled={!root.trim() || busy} onClick={save}>
            {busy ? 'Checking the path…' : 'Save and continue'}
          </button>
        </div>
      </div>
    </div>
  )
}
