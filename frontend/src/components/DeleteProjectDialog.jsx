import { useEffect, useState } from 'react'
import { api } from '../api'
import { Icon } from './Icon'
import { Banner, Modal, Switch, formatBytes } from './ui'

/** Confirmation for deleting a project. Shows exactly what will go and needs the project name typed. */
export default function DeleteProjectDialog({ project, onClose, onDeleted }) {
  const [sum, setSum] = useState(null)
  const [typed, setTyped] = useState('')
  const [files, setFiles] = useState(true)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  useEffect(() => { api.projectSummary(project.id).then(setSum).catch((e) => setErr(e.message)) }, [project.id])

  const ready = typed === project.name && !(sum?.running > 0) && !busy
  async function go() {
    setBusy(true); setErr('')
    try { onDeleted(await api.deleteProject(project.id, typed, files)) } catch (e) { setErr(e.message); setBusy(false) }
  }
  return (
    <Modal title="Delete project" onClose={busy ? () => {} : onClose}>
      <div className="flex items-start gap-3.5">
        <span className="grid h-10 w-10 flex-none place-items-center rounded-xl bg-crit/15 text-crit"><Icon name="trash" size={20} /></span>
        <div className="min-w-0">
          <h2 className="text-lg font-semibold tracking-tight text-ink">Delete “{project.name}”?</h2>
          <p className="mt-1 text-sm leading-relaxed text-mute">
            {sum ? <>This removes the project, its {sum.scans} scan{sum.scans === 1 ? '' : 's'} and {sum.findings} finding{sum.findings === 1 ? '' : 's'} from lasy.</> : 'Checking what is in this project…'}
          </p>
        </div>
      </div>

      <div className="mt-5 rounded-xl border border-line bg-[var(--c-field)] p-3.5">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <p className="text-sm text-ink">Also delete the results folder on this PC</p>
            <p className="mt-0.5 break-all font-mono text-xs text-faint">{sum?.folder_name || '…'}</p>
            {sum && (files
              ? <p className="mt-1.5 text-xs text-crit">{sum.folder_exists ? `Permanently deletes ${sum.truncated ? 'more than ' : ''}${sum.files.toLocaleString()} file${sum.files === 1 ? '' : 's'} (${formatBytes(sum.size_bytes)}), including exports. This cannot be undone.` : 'The folder is already gone, so only the lasy records are removed.'}</p>
              : <p className="mt-1.5 text-xs text-mute">The folder and its files stay on your PC. Only lasy forgets the project.</p>)}
          </div>
          <Switch checked={files} onChange={setFiles} label="Also delete the results folder on this PC" />
        </div>
      </div>

      {sum?.running > 0 && <div className="mt-4"><Banner kind="warn" title="Scans are still running">{sum.running} scan{sum.running === 1 ? ' is' : 's are'} running in this project. Stop {sum.running === 1 ? 'it' : 'them'} first, then delete.</Banner></div>}
      {err && <div className="mt-4"><Banner kind="error">{err}</Banner></div>}

      <label className="label mt-5" htmlFor="confirm-name">Type <span className="font-mono text-ink">{project.name}</span> to confirm</label>
      <input id="confirm-name" className="input" autoFocus value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false}
        onKeyDown={(e) => e.key === 'Enter' && ready && go()} />

      <div className="mt-6 flex justify-end gap-2.5">
        <button className="btn-ghost" onClick={onClose} disabled={busy}>Cancel</button>
        <button className="btn-danger-solid" onClick={go} disabled={!ready}>{busy ? 'Deleting…' : files ? 'Delete project and files' : 'Remove from lasy'}</button>
      </div>
    </Modal>
  )
}
