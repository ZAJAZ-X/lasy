import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import { Crumbs, PageTitle } from '../components/Layout'

export default function NewProject() {
  const [name, setName] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const nav = useNavigate()

  async function create() {
    setBusy(true); setError('')
    try {
      const p = await api.createProject(name.trim())
      nav(`/p/${p.id}`)
    } catch (e) { setError(e.message); setBusy(false) }
  }

  return (
    <>
      <Crumbs items={[{ label: 'Projects', to: '/' }, { label: 'New project' }]} />
      <PageTitle title="New project" sub="Naming the engagement creates its results folder." />
      <div className="card max-w-xl p-5">
        <label className="label" htmlFor="pname">Project name</label>
        <input id="pname" className="input" autoFocus placeholder="e.g. Acme_External_PT"
               value={name}
               onChange={(e) => setName(e.target.value)}
               onKeyDown={(e) => e.key === 'Enter' && name.trim() && create()} />
        <p className="mt-2 text-xs text-faint">
          A folder is created under your results root with sub-folders per tool. Nothing is overwritten.
        </p>
        {error && <p className="mt-3 text-sm text-crit">{error}</p>}
        <div className="mt-4">
          <button className="btn-primary" disabled={!name.trim() || busy} onClick={create}>
            {busy ? 'Creating…' : 'Create project'}
          </button>
        </div>
      </div>
    </>
  )
}
