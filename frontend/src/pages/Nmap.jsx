import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api } from '../api'
import { Crumbs, PageTitle } from '../components/Layout'
import ScanTerminal from '../components/Term'
import TargetInput from '../components/TargetInput'
import { NmapTable } from '../components/ReportTables'
import { Banner, Empty, ProgressBar, StateBadge, useProject, usePoll } from '../components/ui'

const fmt = (iso) => { try { return new Date(iso).toLocaleString() } catch { return iso } }

function useCrumbs(id, trail) {
  const p = useProject(id)
  return [{ label: 'Projects', to: '/' }, { label: p?.name || '…', to: `/p/${id}` }, { label: 'EPT', to: `/p/${id}/ept` }, ...trail]
}

export function NmapHome() {
  const { id } = useParams()
  const nav = useNavigate()
  const crumbs = useCrumbs(id, [{ label: 'Nmap scans' }])
  const [text, setText] = useState('')
  const [cidr, setCidr] = useState(true)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [sessions, setSessions] = useState(null)
  useEffect(() => { api.nmap.list(id).then(setSessions).catch(() => setSessions([])) }, [id])

  async function create() {
    setBusy(true); setErr('')
    try { const s = await api.nmap.create(id, text, cidr); nav(`/p/${id}/nmap/${s.id}`) } catch (e) { setErr(e.message); setBusy(false) }
  }
  return (
    <>
      <Crumbs items={crumbs} />
      <PageTitle title="Nmap scans" sub="Enter your targets, then choose which scans to run. The scans run as parallel batches and can be paused and resumed." />
      <div className="grid gap-6 lg:grid-cols-5">
        <div className="card p-5 lg:col-span-3">
          <h2 className="mb-3 text-sm font-medium text-ink">New scan</h2>
          <label className="label">Targets: IP addresses, ranges (CIDR) or domains</label>
          <TargetInput value={text} onChange={setText} rows={9} placeholder={'203.0.113.10\n198.51.100.0/24\napp.example.com, mail.example.com'} />
          <label className="mt-4 flex cursor-pointer items-start gap-2.5 text-sm">
            <input type="checkbox" className="mt-1 accent-[#37B6A6]" checked={cidr} onChange={(e) => setCidr(e.target.checked)} />
            <span><span className="text-ink">Find live hosts in ranges first (recommended)</span>
              <span className="block text-xs text-faint">A /24 would otherwise be scanned as 256 hosts. IPs and domains you list are always scanned and always appear in the results table.</span></span>
          </label>
          {err && <p className="mt-3 text-sm text-crit">{err}</p>}
          <button className="btn-primary mt-5" onClick={create} disabled={busy || !text.trim()}>{busy ? 'Creating…' : 'Continue to scan options'}</button>
        </div>
        <div className="lg:col-span-2">
          <h2 className="mb-3 text-sm font-medium text-ink">Previous scans</h2>
          {sessions === null ? <p className="text-sm text-mute">Loading…</p> : sessions.length === 0
            ? <Empty title="No scans yet">Your scan sessions for this project will be listed here.</Empty>
            : <div className="space-y-2">{sessions.map((s) => (
              <Link key={s.id} to={`/p/${id}/nmap/${s.id}`} className="card block p-3.5 hover:border-line2">
                <div className="flex items-center justify-between"><span className="text-sm text-ink">{fmt(s.created_at)}</span>
                  <StateBadge state={s.running ? 'running' : s.stages_done ? 'done' : 'pending'} /></div>
                <p className="mt-1 text-xs text-mute">{s.targets.explicit} target{s.targets.explicit !== 1 ? 's' : ''}{s.targets.cidrs.length ? ` · ${s.targets.cidrs.length} range${s.targets.cidrs.length > 1 ? 's' : ''}` : ''} · {s.stages_done} of 8 stages complete</p>
              </Link>))}</div>}
        </div>
      </div>
    </>
  )
}

function StageRow({ st, nested, onToggle, onRun, onPause, link }) {
  const b = st.batches
  const active = st.state === 'running' || st.state === 'queued'
  return (
    <div className={`p-4 ${nested ? 'pl-10' : ''}`}>
      <div className="flex flex-wrap items-start gap-3">
        <div className="pt-0.5">
          {st.auto ? <span className="block w-4" /> : (
            <input type="checkbox" className="h-4 w-4 accent-[#37B6A6]" checked={st.selected} disabled={st.core}
              onChange={(e) => onToggle(st, e.target.checked)} title={st.core ? 'Core stage: always part of a full run' : 'Include in Run all'}
              aria-label={`Include ${st.label} in Run all`} />
          )}
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <h3 className="font-medium text-ink">{st.label}</h3>
            {st.core && <span className="chip">Core</span>}
            {st.key === 'udp_full' && <span className="chip border-med/40 text-med">Slow: hours to days</span>}
          </div>
          <p className="mt-0.5 text-sm text-mute">{st.desc}</p>
          <p className="mt-1.5 font-mono text-xs text-faint">{st.cmd}</p>
          {(active || b.total > 0) && (
            <div className="mt-3 max-w-md">
              <ProgressBar value={st.state === 'done' ? 1 : b.total ? b.done / b.total : 0} active={active} indeterminate={active && b.total <= 1} />
              <p className="mt-1 text-xs text-faint">{b.total} batch{b.total !== 1 ? 'es' : ''}: {b.done} done{b.running ? `, ${b.running} running` : ''}{b.interrupted ? `, ${b.interrupted} interrupted` : ''}{b.failed ? `, ${b.failed} failed` : ''}</p>
            </div>
          )}
          {st.note && <p className="mt-2 text-xs text-mute">{st.note}</p>}
          {st.error && <p className="mt-2 text-sm text-crit">{st.error}</p>}
        </div>
        <div className="flex flex-col items-end gap-2">
          <StateBadge state={st.state} />
          <div className="flex flex-wrap justify-end gap-1.5">
            {st.can_resume && <button className="btn-primary !py-1.5 !text-xs" onClick={() => onRun(st, 'resume')}>{st.resume_kind === 'retry' ? 'Retry failed batches' : 'Resume'}</button>}
            {st.can_pause && <button className="btn-sub" onClick={() => onPause()}>Pause</button>}
            {!active && <button className="btn-sub" onClick={() => onRun(st, 'fresh')}>{st.state === 'pending' ? 'Run' : 'Run again'}</button>}
            {st.has_output && <Link to={link(st)} className="btn-sub">Results</Link>}
          </div>
        </div>
      </div>
    </div>
  )
}

export function NmapSession() {
  const { id, sid } = useParams()
  const crumbs = useCrumbs(id, [{ label: 'Nmap scans', to: `/p/${id}/nmap` }, { label: 'Scan options' }])
  const [s, setS] = useState(null)
  const [err, setErr] = useState('')
  const [info, setInfo] = useState(false)
  usePoll(async () => setS(await api.nmap.get(sid)), 2000, [sid])
  const act = async (fn) => { setErr(''); try { await fn(); setS(await api.nmap.get(sid)) } catch (e) { setErr(e.message) } }
  if (!s) return <p className="text-sm text-mute">Loading…</p>

  const fg = s.stages.filter((x) => !x.bg && !x.auto)
  const bg = s.stages.filter((x) => x.bg)
  const auto = s.stages.filter((x) => x.auto)
  const canPause = s.stages.some((x) => x.can_pause)
  const canResume = !s.running && s.stages.some((x) => x.can_resume)
  const link = (st) => `/p/${id}/nmap/${sid}/stage/${st.id}`
  const t = s.targets
  const row = (st, nested) => <StageRow key={st.id} st={st} nested={nested} link={link}
    onToggle={(x, v) => act(() => api.nmap.select(x.id, v))}
    onRun={(x, mode) => act(() => api.nmap.runStage(x.id, mode))}
    onPause={() => act(() => api.nmap.pause(sid))} />

  return (
    <>
      <Crumbs items={crumbs} />
      <PageTitle title="Nmap scan options" sub={`Session started ${fmt(s.created_at)}`}
        right={<>
          <Link to={`/p/${id}/nmap/${sid}/table`} className="btn-ghost">Results table</Link>
          <Link to={`/p/${id}/nmap/${sid}/web`} className="btn-ghost">Web scans for open web ports</Link>
        </>} />
      <div className="mb-5 flex flex-wrap items-center gap-2 text-xs">
        <span className="chip">{t.explicit} IP/domain target{t.explicit !== 1 ? 's' : ''}</span>
        {t.cidrs.length > 0 && <span className="chip">{t.cidrs.join(', ')}{t.discovered !== null ? ` → ${t.discovered} live` : ' (discovery pending)'}</span>}
        {t.invalid.length > 0 && <span className="chip border-crit/40 text-crit">Ignored: {t.invalid.join(', ')}</span>}
      </div>

      <div className="card mb-5 flex flex-wrap items-center gap-3 p-4">
        <button className="btn-primary" disabled={s.running} onClick={() => act(() => api.nmap.runAll(sid))}>
          {canResume ? 'Resume and run remaining stages' : 'Run all selected stages'}</button>
        {canPause && <button className="btn-ghost" onClick={() => act(() => api.nmap.pause(sid))}>Pause all</button>}
        <p className="text-xs text-faint">Runs the checked stages in order. Background scans start alongside and keep going while you review results.</p>
        <button className="ml-auto text-xs text-brand hover:underline" onClick={() => setInfo(!info)}>{info ? 'Hide' : 'How pause and resume work'}</button>
      </div>
      {info && <div className="mb-5"><Banner kind="info" title="What pause and resume can and cannot do">
        nmap has no true pause. Pausing stops the running nmap processes safely (like Ctrl-C) and keeps everything finished so far.
        Resuming relaunches only the unfinished batches. nmap scans each batch of hosts together and only writes its results when the batch completes,
        so a pause costs the work of the batches in flight, not the whole scan. Smaller batches lose less; full scans are also split into port ranges for the same reason.
        This also covers closing your laptop: lasy marks the scan as interrupted and you resume it later. Pause is only offered on scans long enough to need it.
      </Banner></div>}
      {err && <div className="mb-4"><Banner kind="error">{err}</Banner></div>}

      {[['Scans run in this order', '', fg, false], ['Background scans', 'started alongside; slower', bg, false],
        ['Automatic follow-up', 'runs when a full scan finishes and finds new ports', auto, true]].map(([title, note, list, nested]) => (
        <section key={title} className="mb-7">
          <h2 className="mb-2.5 px-1 text-[11px] font-medium uppercase tracking-[0.09em] text-faint">{title}{note && <span className="ml-2 normal-case tracking-normal text-faint">{note}</span>}</h2>
          <div className="card divide-y divide-line overflow-hidden">{list.map((x) => row(x, nested))}</div>
        </section>))}
    </>
  )
}

export function NmapStage() {
  const { id, sid, scanId } = useParams()
  const crumbs = useCrumbs(id, [{ label: 'Nmap scans', to: `/p/${id}/nmap` }, { label: 'Scan options', to: `/p/${id}/nmap/${sid}` }, { label: 'Scan output' }])
  const [scan, setScan] = useState(null)
  const [st, setSt] = useState(null)
  usePoll(async () => {
    const [a, b] = await Promise.all([api.getScan(scanId), api.nmap.get(sid)])
    setScan(a); setSt(b.stages.find((x) => String(x.id) === String(scanId)))
  }, 1500, [scanId, sid])
  if (!scan) return <p className="text-sm text-mute">Loading…</p>
  const stateOf = (ch) => (scan.batches.find((b) => b.channel === ch)?.state) || (ch === 'discovery' ? 'done' : 'pending')
  return (
    <>
      <Crumbs items={crumbs} />
      <PageTitle title={scan.label} sub={st?.cmd}
        right={<>
          {st?.can_resume && <button className="btn-primary" onClick={() => api.nmap.runStage(scanId, 'resume')}>{st.resume_kind === 'retry' ? 'Retry failed batches' : 'Resume'}</button>}
          {st?.can_pause && <button className="btn-ghost" onClick={() => api.nmap.pause(sid)}>Pause</button>}
          <Link to={`/p/${id}/nmap/${sid}/table`} className="btn-ghost">Results table</Link>
        </>} />
      <div className="mb-3 flex flex-wrap items-center gap-4"><StateBadge state={scan.state} />
        {scan.outputs.length > 0 && <span className="text-xs text-faint">Saved: {scan.outputs.join(', ')}</span>}</div>
      {scan.error && <div className="mb-3"><Banner kind="error" title="This scan could not finish">{scan.error}</Banner></div>}
      {scan.note && <div className="mb-3"><Banner kind="info">{scan.note}</Banner></div>}
      {scan.channels.length === 0 && scan.state === 'pending'
        ? <Empty mood="sleep" title="This scan has not started">Run it from the scan options page.</Empty>
        : scan.channels.length === 0 && !['queued', 'running'].includes(scan.state)
          ? <Empty title="Nothing was scanned">{scan.note || 'No targets matched this stage.'}</Empty>
          : <ScanTerminal scanId={scan.id} channels={scan.channels} stateOf={stateOf} rows={30} />}
      {scan.batches.some((b) => b.error) && <div className="mt-3 space-y-1">
        {scan.batches.filter((b) => b.error).map((b) => <p key={b.idx} className="text-xs text-crit">{b.label}: {b.error}</p>)}</div>}
    </>
  )
}

export function NmapTablePage() {
  const { id, sid } = useParams()
  const crumbs = useCrumbs(id, [{ label: 'Nmap scans', to: `/p/${id}/nmap` }, { label: 'Scan options', to: `/p/${id}/nmap/${sid}` }, { label: 'Results table' }])
  const [t, setT] = useState(null)
  usePoll(async () => setT(await api.nmap.table(sid)), 4000, [sid], !t || t.running)
  return (
    <>
      <Crumbs items={crumbs} />
      <PageTitle title="Current results table" sub="Fills in as scans complete. Every target you entered has a row; targets with nothing found show dashes."
        right={<>
          <Link to={`/p/${id}/nmap/${sid}/web`} className="btn-ghost">Web scans for open web ports</Link>
          <a href={api.nmap.exportUrl(sid)} download className="btn-primary">Export current table to Excel</a>
        </>} />
      {!t ? <p className="text-sm text-mute">Loading…</p> : (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="chip">{t.stats.hosts} hosts</span><span className="chip">{t.stats.with_open_ports} with open ports</span>
            <span className="chip">{t.stats.open_ports} open ports</span>
            {t.running && <span className="inline-flex items-center gap-2 text-brand"><span className="dot bg-brand pulse" />Updating while scans run</span>}
          </div>
          {!t.started && <Banner kind="info">No scan has run yet, so every row shows dashes. Run a stage from the scan options page.</Banner>}
          <NmapTable rows={t.rows} />
          <p className="text-xs text-faint">Only ports reported as open are listed. UDP ports reported as open|filtered are kept in the raw nmap output but not in this table.</p>
        </div>
      )}
    </>
  )
}

export function NmapWebHandoff() {
  const { id, sid } = useParams()
  const nav = useNavigate()
  const crumbs = useCrumbs(id, [{ label: 'Nmap scans', to: `/p/${id}/nmap` }, { label: 'Scan options', to: `/p/${id}/nmap/${sid}` }, { label: 'Web scan targets' }])
  const [items, setItems] = useState(null)
  const [add, setAdd] = useState('')
  const [err, setErr] = useState('')
  useEffect(() => { api.nmap.webCandidates(sid).then((l) => setItems(l.map((x, i) => ({ ...x, k: i })))).catch(() => setItems([])) }, [sid])

  function addEntry() {
    const m = add.trim().match(/^(?:(https?):\/\/)?([^\s:/]+)(?::(\d+))?\/?$/i)
    if (!m) { setErr('Use host:port, for example app.example.com:8443'); return }
    const port = Number(m[3] || (m[1] === 'http' ? 80 : 443))
    const scheme = (m[1] || (port === 80 || port === 8080 ? 'http' : 'https')).toLowerCase()
    setItems((cur) => [...cur, { host: m[2].toLowerCase(), port, scheme, service: 'added by you', k: Date.now() }])
    setAdd(''); setErr('')
  }
  async function go() {
    try { await api.web.addTargets(id, { items: items.map(({ host, port, scheme }) => ({ host, port, scheme })), source: 'nmap' }); nav(`/p/${id}/webapp`) } catch (e) { setErr(e.message) }
  }
  return (
    <>
      <Crumbs items={crumbs} />
      <PageTitle title="Web scans for open web ports" sub="These hosts and ports were found with a web service. Remove anything that is wrong or add what is missing, then continue to the Web App PT tools." />
      {items === null ? <p className="text-sm text-mute">Loading…</p> : (
        <div className="grid gap-6 lg:grid-cols-5">
          <div className="lg:col-span-3">
            {items.length === 0 ? <Empty title="No web ports found yet">Run the TCP scans first, or add an entry manually on the right.</Empty> : (
              <div className="card overflow-hidden"><table className="w-full text-sm">
                <thead><tr className="bg-raised text-left text-xs text-mute"><th className="px-4 py-2.5 font-medium">Host / domain</th><th className="px-4 py-2.5 font-medium">Port</th><th className="px-4 py-2.5 font-medium">Scheme</th><th className="w-20 px-4 py-2.5" /></tr></thead>
                <tbody>{items.map((x) => (
                  <tr key={x.k} className="border-t border-line">
                    <td className="px-4 py-2.5 font-mono text-ink">{x.host}</td><td className="px-4 py-2.5 font-mono">{x.port}</td>
                    <td className="px-4 py-2.5">{x.scheme}</td>
                    <td className="px-4 py-2.5 text-right"><button className="btn-sub" onClick={() => setItems((c) => c.filter((y) => y.k !== x.k))} aria-label={`Remove ${x.host}:${x.port}`}>Remove</button></td>
                  </tr>))}</tbody></table></div>
            )}
          </div>
          <div className="space-y-4 lg:col-span-2">
            <div className="card p-4">
              <label className="label">Add an entry</label>
              <div className="flex gap-2"><input className="input font-mono text-[13px]" placeholder="app.example.com:8443" value={add}
                onChange={(e) => setAdd(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && addEntry()} />
                <button className="btn-ghost" onClick={addEntry} disabled={!add.trim()}>Add</button></div>
            </div>
            {err && <p className="text-sm text-crit">{err}</p>}
            <button className="btn-primary w-full" onClick={go} disabled={items.length === 0}>Continue to Web App PT ({items.length})</button>
          </div>
        </div>
      )}
    </>
  )
}
