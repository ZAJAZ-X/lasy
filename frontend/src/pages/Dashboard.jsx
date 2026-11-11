import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import DeleteProjectDialog from '../components/DeleteProjectDialog'
import { Icon } from '../components/Icon'
import { PageTitle } from '../components/Layout'
import { Banner, Empty, timeAgo } from '../components/ui'

const full = (iso) => { try { return new Date(iso).toLocaleString() } catch { return iso } }
const COLS = 'sm:grid-cols-[minmax(0,1fr)_5rem_9.5rem_5.5rem]'

export default function Dashboard() {
  const [projects, setProjects] = useState(null)
  const [q, setQ] = useState('')
  const [del, setDel] = useState(null)
  const [done, setDone] = useState('')
  const load = () => api.listProjects().then(setProjects).catch(() => setProjects([]))
  useEffect(() => { load() }, [])
  const shown = useMemo(() => (projects || []).filter((p) => !q || p.name.toLowerCase().includes(q.toLowerCase())), [projects, q])

  return (
    <>
      <PageTitle title="Projects" sub="Each engagement is a project. Its scan output is saved to its own folder in your results location."
        right={<Link to="/new" className="btn-primary"><Icon name="plus" size={16} />New project</Link>} />
      {done && <div className="mb-5"><Banner kind="ok">{done} <button className="ml-2 underline" onClick={() => setDone('')}>Dismiss</button></Banner></div>}

      {projects === null ? <p className="text-sm text-mute">Loading…</p> : projects.length === 0 ? (
        <Empty mood="sleep" title="No projects yet" action={<Link to="/new" className="btn-primary">Create your first project</Link>}>
          Start by naming an engagement. That creates its results folder on your Windows drive.</Empty>
      ) : (
        <>
          {projects.length > 5 && (
            <div className="relative mb-4 max-w-xs">
              <Icon name="search" size={16} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint" />
              <input className="input !pl-9" placeholder="Search projects" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search projects" />
            </div>)}
          <div className="card overflow-hidden">
            <div className={`hidden gap-4 border-b border-line px-5 py-2.5 text-[11px] font-medium uppercase tracking-[0.09em] text-faint sm:grid ${COLS}`}>
              <span>Project</span><span className="text-right">Scans</span><span>Last activity</span><span />
            </div>
            {shown.map((p) => (
              <div key={p.id} className={`list-row hoverable grid grid-cols-[minmax(0,1fr)_auto] items-center gap-4 border-b border-line px-5 py-3.5 last:border-b-0 ${COLS}`}>
                <Link to={`/p/${p.id}`} className="min-w-0">
                  <span className="block truncate font-medium text-ink">{p.name}</span>
                  <span className="block truncate font-mono text-xs text-faint">{p.slug}</span>
                </Link>
                <span className="hidden text-right font-mono text-sm tabular-nums text-mute sm:block">{p.scan_count}</span>
                <span className="hidden text-sm text-mute sm:block" title={full(p.last_activity)}>{timeAgo(p.last_activity)}</span>
                <div className="flex justify-end gap-1.5">
                  <Link to={`/p/${p.id}`} className="btn-sub !px-2" aria-label={`Open ${p.name}`}><Icon name="chevron" size={15} /></Link>
                  <button className="btn-sub !px-2 hover:!border-crit/50 hover:!text-crit" onClick={() => setDel(p)} aria-label={`Delete ${p.name}`}><Icon name="trash" size={15} /></button>
                </div>
              </div>))}
            {shown.length === 0 && <p className="px-5 py-6 text-sm text-mute">No project matches “{q}”.</p>}
          </div>
        </>)}
      {del && <DeleteProjectDialog project={del} onClose={() => setDel(null)}
        onDeleted={(r) => { setDel(null); setDone(`Deleted “${r.name}”${r.files_deleted ? ' and its results folder.' : ' from lasy. Its folder was kept.'}`); load() }} />}
    </>
  )
}
