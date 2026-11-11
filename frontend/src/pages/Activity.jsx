import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api } from '../api'
import DeleteProjectDialog from '../components/DeleteProjectDialog'
import { Icon } from '../components/Icon'
import { Crumbs, PageTitle } from '../components/Layout'
import { formatBytes, useProject } from '../components/ui'

function TaskRow({ to, icon, title, desc }) {
  return (
    <Link to={to} className="list-row flex items-center gap-4 px-5 py-3.5">
      <span className="task-icon"><Icon name={icon} size={19} /></span>
      <span className="min-w-0 flex-1">
        <span className="block text-[15px] text-ink">{title}</span>
        <span className="block text-[13px] leading-snug text-mute">{desc}</span>
      </span>
      <Icon name="chevron" size={16} className="flex-none text-faint" />
    </Link>
  )
}

function Group({ title, children }) {
  return (
    <section className="mb-8">
      <h2 className="mb-2.5 px-1 text-[11px] font-medium uppercase tracking-[0.09em] text-faint">{title}</h2>
      <div className="card divide-y divide-line overflow-hidden">{children}</div>
    </section>
  )
}

export function Activity() {
  const { id } = useParams()
  const nav = useNavigate()
  const p = useProject(id)
  const [sum, setSum] = useState(null)
  const [del, setDel] = useState(false)
  useEffect(() => { api.projectSummary(id).then(setSum).catch(() => {}) }, [id])
  const stats = sum ? [`${sum.scans} scan${sum.scans === 1 ? '' : 's'}`, `${sum.findings} finding${sum.findings === 1 ? '' : 's'}`, `${formatBytes(sum.size_bytes)} of results`].join(' · ') : ' '
  return (
    <>
      <Crumbs items={[{ label: 'Projects', to: '/' }, { label: p?.name || '…' }]} />
      <PageTitle title={p?.name || 'Project'} sub={stats} />

      <Group title="External pentest">
        <TaskRow to={`/p/${id}/nmap`} icon="scan" title="Nmap scans" desc="Top-ports sweep, service scan, UDP baseline and full-port scans, run as pausable parallel batches." />
        <TaskRow to={`/p/${id}/subdomain`} icon="network" title="Subdomain enumeration" desc="Combines several sources, resolves each name and checks whether it answers over HTTP(S)." />
        <TaskRow to={`/p/${id}/nameserver`} icon="server" title="Nameserver lookup" desc="A domain’s authoritative nameservers, with dig." />
        <TaskRow to={`/p/${id}/hostup`} icon="pulse" title="Host up / down" desc="Which hosts in a list are reachable." />
      </Group>
      <Group title="Web app pentest">
        <TaskRow to={`/p/${id}/webapp`} icon="shield" title="Targets and tools" desc="Nmap SSL, testssl.sh, Nikto, Nuclei, ffuf, feroxbuster and dirsearch: run them all in order, or one at a time." />
        <TaskRow to={`/p/${id}/webapp/findings`} icon="list" title="All findings" desc="Every tool’s findings together, most severe first, with Excel export." />
        <TaskRow to={`/p/${id}/webapp/discovery`} icon="search" title="Content discovery intelligence" desc="ffuf, feroxbuster and dirsearch merged and ranked by what to look at first." />
      </Group>

      <section className="mt-10">
        <h2 className="mb-2.5 px-1 text-[11px] font-medium uppercase tracking-[0.09em] text-faint">Danger zone</h2>
        <div className="card flex flex-wrap items-center justify-between gap-4 px-5 py-4" style={{ borderColor: 'rgba(229,72,77,.3)' }}>
          <div>
            <p className="text-[15px] text-ink">Delete this project</p>
            <p className="text-[13px] text-mute">Removes it from lasy and, if you choose, deletes its results folder from this PC.</p>
          </div>
          <button className="btn-danger" onClick={() => setDel(true)}><Icon name="trash" size={16} />Delete project…</button>
        </div>
      </section>
      {del && p && <DeleteProjectDialog project={p} onClose={() => setDel(false)} onDeleted={() => nav('/')} />}
    </>
  )
}

export function EptMenu() {
  const { id } = useParams()
  const p = useProject(id)
  return (
    <>
      <Crumbs items={[{ label: 'Projects', to: '/' }, { label: p?.name || '…', to: `/p/${id}` }, { label: 'EPT' }]} />
      <PageTitle title="External pentest" sub="Choose a task." />
      <Group title="Tasks">
        <TaskRow to={`/p/${id}/nmap`} icon="scan" title="Nmap scans" desc="Top-ports sweep, service scan, UDP baseline and full-port scans, run as pausable parallel batches." />
        <TaskRow to={`/p/${id}/subdomain`} icon="network" title="Subdomain enumeration" desc="Combines several sources, resolves each name and checks whether it answers over HTTP(S)." />
        <TaskRow to={`/p/${id}/nameserver`} icon="server" title="Nameserver lookup" desc="A domain’s authoritative nameservers, with dig." />
        <TaskRow to={`/p/${id}/hostup`} icon="pulse" title="Host up / down" desc="Which hosts in a list are reachable." />
      </Group>
    </>
  )
}
