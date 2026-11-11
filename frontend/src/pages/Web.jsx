import { useEffect, useState } from 'react'
import { Link, Navigate, useNavigate, useParams } from 'react-router-dom'
import { api } from '../api'
import { Crumbs, PageTitle } from '../components/Layout'
import ScanTerminal from '../components/Term'
import { Banner, Empty, SeverityPill, StateBadge, Tabs, useProject, usePoll } from '../components/ui'

const SEVS = ['critical', 'high', 'medium', 'low', 'info']
const ACTIONABLE = ['critical', 'high', 'medium', 'low']
const human = (n) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`)
const dur = (s) => (s == null ? '' : s < 60 ? `${s}s` : s < 3600 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`)
const when = (iso) => { try { return new Date(iso).toLocaleString() } catch { return iso || '' } }
const DIR_KINDS = ['web_ffuf', 'web_feroxbuster', 'web_dirsearch']
const ACTIVE = ['queued', 'running']

function useWebCrumbs(id, trail = []) {
  const p = useProject(id)
  return [{ label: 'Projects', to: '/' }, { label: p?.name || '…', to: `/p/${id}` }, { label: 'Web App PT', to: `/p/${id}/webapp` }, ...trail]
}

function CountPills({ counts }) {
  const items = SEVS.filter((s) => counts?.[s])
  if (!items.length) return null
  return <div className="flex flex-wrap gap-1.5">{items.map((s) => <span key={s} className="inline-flex items-center gap-1"><SeverityPill sev={s} /><span className="text-xs text-mute">{counts[s]}</span></span>)}</div>
}

// ------------------------------------------------------------------ shared tables
function FindingRow({ f, showTool }) {
  const [open, setOpen] = useState(false)
  const long = (f.evidence || '').length > 160
  return (
    <tr className="border-t border-line align-top">
      <td className="px-4 py-3"><SeverityPill sev={f.severity} /></td>
      {showTool && <td className="px-4 py-3 text-mute">{f.tool}</td>}
      <td className="px-4 py-3">
        <div className="text-ink">{f.title}</div>
        {f.evidence && <div className={`mt-1 max-w-3xl break-words font-mono text-xs leading-relaxed text-faint ${open ? '' : 'line-clamp-2'}`}>{f.evidence}</div>}
        {long && <button className="mt-1 text-xs text-brand hover:underline" onClick={() => setOpen(!open)}>{open ? 'Show less' : 'Show full evidence'}</button>}
      </td>
      <td className="px-4 py-3 font-mono text-xs text-mute">{f.target}</td>
    </tr>
  )
}

export function FindingsTable({ rows, showTool, empty }) {
  if (!rows.length) return empty || <Empty title="No findings">Nothing matches this view.</Empty>
  return (
    <div className="card overflow-x-auto">
      <table className="w-full text-sm">
        <thead><tr className="bg-raised text-left text-xs text-mute">
          <th className="w-28 px-4 py-2.5 font-medium">Severity</th>{showTool && <th className="w-36 px-4 py-2.5 font-medium">Tool</th>}
          <th className="px-4 py-2.5 font-medium">Finding and evidence</th><th className="px-4 py-2.5 font-medium">Affected</th></tr></thead>
        <tbody>{rows.map((f) => <FindingRow key={f.id} f={f} showTool={showTool} />)}</tbody>
      </table>
    </div>
  )
}

export function EndpointsTable({ eps, limit = 400 }) {
  if (!eps.length) return <Empty title="No endpoints">No endpoints match this view.</Empty>
  return (
    <div className="card overflow-x-auto">
      <table className="w-full text-sm">
        <thead><tr className="bg-raised text-left text-xs text-mute">
          <th className="w-28 px-4 py-2.5 font-medium">Priority</th><th className="px-4 py-2.5 font-medium">Endpoint</th>
          <th className="px-4 py-2.5 font-medium">Status</th><th className="px-4 py-2.5 font-medium">Size</th>
          <th className="px-4 py-2.5 font-medium">Found by</th><th className="px-4 py-2.5 font-medium">Why it matters</th></tr></thead>
        <tbody>{eps.slice(0, limit).map((e) => (
          <tr key={e.url} className={`border-t border-line align-top ${e.noise ? 'opacity-50' : ''}`}>
            <td className="px-4 py-3"><SeverityPill sev={e.noise ? 'info' : e.priority} /><div className="mt-1 text-center text-[11px] text-faint">score {e.score}</div></td>
            <td className="px-4 py-3 font-mono text-xs text-ink"><div>{e.path}</div><div className="text-faint">{e.origin}</div>{e.redirect && <div className="text-faint">→ {e.redirect}</div>}</td>
            <td className="px-4 py-3 font-mono">{e.status}</td><td className="px-4 py-3 font-mono text-xs text-mute">{human(e.size)}</td>
            <td className="px-4 py-3 text-xs text-mute">{e.tools.join(', ')}</td>
            <td className="max-w-md px-4 py-3 text-xs leading-relaxed text-mute">{e.reasons.length ? e.reasons.slice(0, 3).map((r, i) => <div key={i}>{r}</div>) : '-'}</td>
          </tr>))}</tbody>
      </table>
      {eps.length > limit && <p className="border-t border-line px-4 py-2 text-xs text-faint">Showing the top {limit} of {eps.length}. Use search or filters to narrow down.</p>}
    </div>
  )
}

// ------------------------------------------------------------------ dashboard
function Targets({ id }) {
  const [list, setList] = useState([])
  const [text, setText] = useState('')
  const [err, setErr] = useState('')
  const load = () => api.web.targets(id).then(setList).catch(() => {})
  useEffect(() => { load() }, [id]) // eslint-disable-line
  async function add() {
    setErr('')
    try { const r = await api.web.addTargets(id, { text }); setList(r.targets); setText(''); if (r.invalid.length) setErr(`Could not read: ${r.invalid.join(', ')}`) } catch (e) { setErr(e.message) }
  }
  return (
    <div className="card p-5">
      <h2 className="mb-1 text-sm font-medium text-ink">Targets</h2>
      <p className="mb-4 text-xs text-faint">Every tool runs against each target in turn. TLS tools skip plain HTTP targets.</p>
      {list.length === 0 ? <p className="mb-4 text-sm text-mute">No targets yet. Add some below, or send them from the nmap results.</p> : (
        <div className="mb-4 divide-y divide-line rounded-md border border-line">
          {list.map((t) => (
            <div key={t.id} className="flex items-center gap-3 px-3 py-2">
              <span className="min-w-0 flex-1 truncate font-mono text-[13px] text-ink">{t.host}:{t.port}</span>
              <select className="rounded border border-line bg-raised px-1.5 py-1 text-xs text-mute" value={t.scheme} aria-label="Scheme"
                onChange={(e) => api.web.setScheme(t.id, e.target.value).then(load)}><option>https</option><option>http</option></select>
              {t.source === 'nmap' && <span className="chip">from nmap</span>}
              <button className="btn-sub" onClick={() => api.web.delTarget(t.id).then(load)} aria-label={`Remove ${t.host}:${t.port}`}>Remove</button>
            </div>))}
        </div>)}
      <label className="label">Add targets</label>
      <textarea className="input font-mono text-[13px]" rows={3} value={text} onChange={(e) => setText(e.target.value)} spellCheck={false}
        placeholder={'app.example.com:443\nhttps://portal.example.com:8443\n203.0.113.10 8080'} />
      {err && <p className="mt-2 text-sm text-crit">{err}</p>}
      <button className="btn-ghost mt-3" onClick={add} disabled={!text.trim()}>Add targets</button>
    </div>
  )
}

function DirSetup({ id }) {
  const [dir, setDir] = useState(null)
  const [cfg, setCfg] = useState(null)
  const [exts, setExts] = useState('')
  const [saved, setSaved] = useState(false)
  const [err, setErr] = useState('')
  const apply = (d) => { setDir(d); setCfg(d.config); setExts(d.config.extensions.join(', ')) }
  useEffect(() => { api.web.dirconfig(id).then(apply).catch((e) => setErr(e.message)) }, [id])
  if (err) return <div className="card p-5"><Banner kind="error">{err}</Banner></div>
  if (!dir || !cfg) return null
  const sel = dir.wordlists.find((w) => w.path === cfg.wordlist)
  const mult = 1 + exts.split(',').map((e) => e.trim()).filter(Boolean).length
  const tierColor = { Quick: 'text-ok', Standard: 'text-med', Deep: 'text-high' }
  async function save() {
    setErr('')
    try { const out = await api.web.saveDirconfig(id, { ...cfg, extensions: exts.split(',') }); setCfg(out); setSaved(true); setTimeout(() => setSaved(false), 1500) } catch (e) { setErr(e.message) }
  }
  return (
    <div className="card p-5">
      <h2 className="mb-1 text-sm font-medium text-ink">Directory discovery setup</h2>
      <p className="mb-4 text-xs text-faint">Used by ffuf, feroxbuster and dirsearch. Pick the kind of application and lasy suggests wordlists of sensible size.</p>
      {!dir.seclists && <div className="mb-4"><Banner kind="warn" title="SecLists not found">Install it with <span className="font-mono">sudo apt install seclists</span>, or enter a wordlist path below.</Banner></div>}
      <div className="grid gap-4 md:grid-cols-[minmax(0,1fr)_minmax(0,1.7fr)_minmax(0,0.6fr)]">
        <div><label className="label">Application type</label>
          <select className="input" value={cfg.profile} onChange={(e) => api.web.dirconfig(id, e.target.value).then(apply)}>
            {dir.profiles.map((p) => <option key={p.key} value={p.key}>{p.label}</option>)}</select></div>
        <div><label className="label">File extensions to try</label>
          <input className="input font-mono text-[13px]" value={exts} onChange={(e) => setExts(e.target.value)} placeholder="php, txt, bak" /></div>
        <div><label className="label">Threads</label>
          <input type="number" min="1" max="200" className="input" value={cfg.threads} onChange={(e) => setCfg({ ...cfg, threads: Number(e.target.value) })} /></div>
      </div>
      <label className="label mt-5">Wordlist</label>
      <div className="space-y-1.5">
        {dir.wordlists.map((w) => (
          <label key={w.path} className={`flex cursor-pointer items-start gap-3 rounded-md border px-3 py-2 ${cfg.wordlist === w.path ? 'border-brand/60 bg-brand/5' : 'border-line'}`}>
            <input type="radio" className="mt-1 accent-[#37B6A6]" checked={cfg.wordlist === w.path} onChange={() => setCfg({ ...cfg, wordlist: w.path })} />
            <span className="min-w-0 flex-1"><span className="font-mono text-[13px] text-ink">{w.name}</span><span className={`ml-2 text-xs ${tierColor[w.tier]}`}>{w.tier}</span>
              <span className="block text-xs text-faint">{w.note} · {w.lines.toLocaleString()} entries · ~{(w.lines * mult).toLocaleString()} requests per target · {w.eta}</span></span>
          </label>))}
        {dir.wordlists.length === 0 && <p className="text-sm text-mute">No suggested wordlists were found for this type.</p>}
      </div>
      <label className="label mt-4">Or use your own wordlist path</label>
      <input className="input font-mono text-[13px]" value={sel ? '' : cfg.wordlist} placeholder="/path/to/wordlist.txt" onChange={(e) => setCfg({ ...cfg, wordlist: e.target.value })} />
      <div className="mt-4 flex items-center gap-3"><button className="btn-ghost" onClick={save}>Save setup</button>{saved && <span className="text-xs text-ok">Saved</span>}</div>
    </div>
  )
}

const RUN_STATE = { waiting: ['bg-faint', 'Waiting'], running: ['bg-brand pulse', 'Running'], done: ['bg-ok', 'Completed'], failed: ['bg-crit', 'Failed'], skipped: ['bg-med', 'Skipped'], canceled: ['bg-faint', 'Stopped'] }

function ToolRow({ t, pos, total, runItem, locked, onToggle, onMove, onRun }) {
  const sc = t.scan
  const running = sc && ACTIVE.includes(sc.state)
  const issues = (sc?.result_json?.targets || []).filter((x) => x.status === 'error').length
  const [dot, runLabel] = runItem ? RUN_STATE[runItem.state] || ['bg-faint', runItem.state] : []
  return (
    <div className={`p-4 ${t.enabled ? '' : 'opacity-70'}`}>
      <div className="flex flex-wrap items-start gap-4">
        <div className="flex flex-col items-center gap-1 pt-0.5">
          <button className="btn-sub !px-1.5 !py-0.5" disabled={pos === 0 || locked} onClick={() => onMove(t.key, -1)} aria-label={`Move ${t.label} earlier`}>▲</button>
          <span className="font-mono text-xs text-faint">{pos + 1}</span>
          <button className="btn-sub !px-1.5 !py-0.5" disabled={pos === total - 1 || locked} onClick={() => onMove(t.key, 1)} aria-label={`Move ${t.label} later`}>▼</button>
        </div>
        <label className="flex cursor-pointer items-center pt-1" title="Include in the full run">
          <input type="checkbox" className="h-4 w-4 accent-[#37B6A6]" checked={t.enabled} disabled={locked} onChange={(e) => onToggle(t.key, e.target.checked)} aria-label={`Include ${t.label} in the full run`} />
        </label>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-3"><h3 className="font-medium text-ink">{t.label}</h3>
            {!t.available && <span className="chip border-high/40 text-high">Not installed</span>}
            {issues > 0 && <span className="chip border-med/40 text-med">{issues} target{issues > 1 ? 's' : ''} could not be scanned</span>}</div>
          <p className="text-sm text-mute">{t.desc}</p>
          {!t.available && <p className="mt-1 font-mono text-xs text-faint">{t.install}</p>}
          {sc?.error && <p className="mt-1 text-sm text-crit">{sc.error}</p>}
          {runItem?.note && runItem.state !== 'done' && t.available && <p className="mt-1 text-xs text-med">{runItem.note}</p>}
          {sc && !running && <div className="mt-2 flex flex-wrap items-center gap-3"><CountPills counts={t.counts} />
            {sc.state === 'done' && !Object.keys(t.counts).length && <span className="text-xs text-faint">No findings</span>}
            <span className="text-xs text-faint">{when(sc.finished_at)}{sc.duration != null ? ` · took ${dur(sc.duration)}` : ''}</span></div>}
        </div>
        <div className="flex flex-col items-end gap-2">
          <div className="flex items-center gap-3">
            {runItem && <span className="inline-flex items-center gap-1.5 text-xs text-mute"><span className={`dot ${dot}`} />{runLabel}</span>}
            {(sc || !runItem) && <StateBadge state={sc ? sc.state : 'pending'} />}
          </div>
          <div className="flex gap-1.5">
            <button className="btn-sub" disabled={running || locked || !t.available} onClick={() => onRun(t.key)}
              title={locked ? 'A full run is in progress. Stop it first.' : ''}>{sc ? 'Run again' : 'Run'}</button>
            {sc && <Link to={`/p/${sc.project_id}/webapp/tool/${sc.id}`} className="btn-primary !px-3 !py-1.5 !text-xs">Open results</Link>}
          </div>
        </div>
      </div>
    </div>
  )
}

export function WebDashboard() {
  const { id } = useParams()
  const nav = useNavigate()
  const crumbs = useWebCrumbs(id)
  const [data, setData] = useState(null)
  const [err, setErr] = useState('')
  usePoll(async () => setData(await api.web.tools(id)), 2000, [id])
  const act = async (fn) => { setErr(''); try { await fn(); setData(await api.web.tools(id)) } catch (e) { setErr(e.message) } }
  if (!data) return <p className="text-sm text-mute">Loading…</p>

  const tools = data.tools
  const ra = data.run_all
  const active = data.run_all_active
  const anyRunning = tools.some((t) => t.scan && ACTIVE.includes(t.scan.state))
  const selected = tools.filter((t) => t.enabled)
  const savePlan = (order, enabled) => act(() => api.web.savePlan(id, { order, enabled }))
  const move = (key, d) => { const o = tools.map((t) => t.key); const i = o.indexOf(key); const j = i + d; if (j < 0 || j >= o.length) return; [o[i], o[j]] = [o[j], o[i]]; savePlan(o, Object.fromEntries(tools.map((t) => [t.key, t.enabled]))) }
  const toggle = (key, on) => savePlan(tools.map((t) => t.key), Object.fromEntries(tools.map((t) => [t.key, t.key === key ? on : t.enabled])))
  async function runOne(key) {
    setErr('')
    try { const s = await api.web.run(id, key); nav(`/p/${id}/webapp/tool/${s.id}`) } catch (e) { setErr(e.message) }
  }
  const counts = ra?.result_json?.counts || {}
  const finished = ra && !['running', 'queued'].includes(ra.state)

  return (
    <>
      <Crumbs items={crumbs} />
      <PageTitle title="Web App Pentest" sub="Add your web targets, then run every tool in order with one button, or run any tool on its own."
        right={<><Link to={`/p/${id}/webapp/discovery`} className="btn-ghost">Content discovery intelligence</Link><Link to={`/p/${id}/webapp/findings`} className="btn-ghost">All findings</Link></>} />
      <div className="grid gap-6 xl:grid-cols-2"><Targets id={id} /><DirSetup id={id} /></div>

      <div className="card mb-4 mt-8 p-5">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div><h2 className="text-sm font-medium text-ink">Run all in order</h2>
            <p className="mt-1 max-w-2xl text-sm text-mute">Runs the checked tools one after another, in the order shown, on every target. Use the arrows to change the order and the checkboxes to leave a tool out. A tool that is missing or cannot run is skipped and the run continues.</p></div>
          <div className="flex items-center gap-2">
            {(active || anyRunning) && <button className="btn-danger" onClick={() => act(() => api.web.stop(id))}>Stop</button>}
            <button className="btn-primary" disabled={active || anyRunning || selected.length === 0}
              onClick={() => act(() => api.web.runAll(id, selected.map((t) => t.key)))}>Run {selected.length} selected tool{selected.length !== 1 ? 's' : ''} in order</button>
          </div>
        </div>
        {finished && (
          <div className="mt-4"><Banner kind={counts.failed ? 'warn' : 'ok'} title={`Last full run ${ra.state === 'canceled' ? 'was stopped' : 'finished'}`}>
            {[['done', 'completed'], ['skipped', 'skipped'], ['failed', 'failed'], ['canceled', 'stopped']].filter(([k]) => counts[k]).map(([k, l]) => `${counts[k]} ${l}`).join(' · ') || 'Nothing ran'}
            {counts.skipped || counts.failed ? '. See the notes under each tool below.' : '.'}
          </Banner></div>)}
      </div>
      {err && <div className="mb-4"><Banner kind="error">{err}</Banner></div>}

      <h2 className="mb-3 text-sm font-medium text-ink">Tools <span className="font-normal text-faint">(run any one on its own with its Run button)</span></h2>
      <div className="card divide-y divide-line overflow-hidden">
        {tools.map((t, i) => <ToolRow key={t.key} t={t} pos={i} total={tools.length} runItem={ra?.items?.[t.key] && (active || ra.state === 'running' ? ra.items[t.key] : (ra.items[t.key].state === 'skipped' ? ra.items[t.key] : null))}
          locked={active} onToggle={toggle} onMove={move} onRun={runOne} />)}
      </div>
    </>
  )
}

// ------------------------------------------------------------------ single tool results
const TARGET_STATUS = { ok: ['bg-ok', 'Scanned'], skipped: ['bg-med', 'Skipped'], error: ['bg-crit', 'Could not scan'] }

export function ToolPage() {
  const { id, scanId } = useParams()
  const nav = useNavigate()
  const [scan, setScan] = useState(null)
  const [rows, setRows] = useState([])
  const [hist, setHist] = useState([])
  const [tab, setTab] = useState(null)
  const [sev, setSev] = useState('actionable')
  const [q, setQ] = useState('')
  const [pri, setPri] = useState('interesting')
  const [chan, setChan] = useState(null)
  const [err, setErr] = useState('')
  const [gone, setGone] = useState(false)
  const crumbs = useWebCrumbs(id, [{ label: scan?.label || 'Tool results' }])
  const running = scan && ACTIVE.includes(scan.state)
  const tool = scan ? scan.kind.replace('web_', '') : ''
  const isDir = scan && DIR_KINDS.includes(scan.kind)

  useEffect(() => { setScan(null); setRows([]); setTab(null); setGone(false); setErr('') }, [scanId])
  usePoll(async () => { try { setScan(await api.getScan(scanId)) } catch (e) { if (!scan) setGone(true) } }, 1500, [scanId], !scan || running)
  usePoll(async () => { if (scan) setRows(await api.scanFindings(scanId)) }, 3000, [scanId, scan?.state], !!running)
  useEffect(() => { if (tool) api.web.history(id, tool).then(setHist).catch(() => {}) }, [id, tool, scan?.state])
  useEffect(() => { if (scan && tab === null) setTab(ACTIVE.includes(scan.state) ? 'terminal' : scan.state === 'failed' ? 'targets' : 'findings') }, [scan]) // eslint-disable-line
  const wasRunning = useState({ v: false })[0]
  useEffect(() => { if (running) wasRunning.v = true; else if (wasRunning.v && scan?.state === 'done') { wasRunning.v = false; setTab('findings') } }, [running, scan?.state]) // eslint-disable-line

  if (gone) return <><Crumbs items={crumbs} /><Empty title="This scan no longer exists" action={<Link to={`/p/${id}/webapp`} className="btn-primary">Back to Web App PT</Link>}>It may have been removed, or the backend data was reset.</Empty></>
  if (!scan) return <p className="text-sm text-mute">Loading…</p>

  const res = scan.result_json || {}
  const targets = res.targets || []
  const bad = targets.filter((t) => t.status === 'error')
  const counts = Object.fromEntries(SEVS.map((s) => [s, rows.filter((r) => r.severity === s).length]))
  const shown = rows.filter((r) => (sev === 'actionable' ? ACTIONABLE.includes(r.severity) : sev === 'all' ? true : r.severity === sev)
    && (!q || `${r.title} ${r.target} ${r.evidence}`.toLowerCase().includes(q.toLowerCase())))
  const eps = (res.endpoints || []).filter((e) => (pri === 'all' ? true : pri === 'noise' ? e.noise : pri === 'interesting' ? !e.noise && (e.priority === 'high' || e.priority === 'medium') : !e.noise && e.priority === pri)
    && (!q || `${e.path} ${e.origin}`.toLowerCase().includes(q.toLowerCase())))

  async function again() { setErr(''); try { const s = await api.web.run(id, tool); nav(`/p/${id}/webapp/tool/${s.id}`) } catch (e) { setErr(e.message) } }
  const tabs = [{ id: 'findings', label: isDir ? 'Look at these first' : 'Findings', count: rows.length },
    ...(isDir ? [{ id: 'endpoints', label: 'All endpoints', count: res.total_endpoints }] : []),
    { id: 'targets', label: 'Targets and files', count: targets.length || undefined }, { id: 'terminal', label: 'Terminal output' }]

  const emptyFindings = running ? <Empty mood="wait" title="Waiting for results">Findings appear as each target finishes. Switch to Terminal output to watch the tool live.</Empty>
    : scan.state === 'failed' ? <Empty title="No results">This run failed before producing findings. The reason is shown above.</Empty>
      : scan.state === 'canceled' && !rows.length ? <Empty title="Stopped before any result">The run was stopped before a target finished.</Empty>
        : bad.length ? <Empty title="No findings, but not every target was scanned">{bad.length} target{bad.length > 1 ? 's' : ''} could not be scanned, so “no findings” does not cover {bad.length > 1 ? 'them' : 'it'}. See Targets and files.</Empty>
          : rows.length && !shown.length ? <Empty title="Nothing in this view">Try another severity filter or clear the search.</Empty>
            : <Empty title="Nothing was flagged">The tool completed on {targets.length || 'all'} target{targets.length === 1 ? '' : 's'} and reported no findings. The terminal output holds the raw results.</Empty>

  return (
    <>
      <Crumbs items={crumbs} />
      <PageTitle title={scan.label} sub={`Started ${when(scan.started_at || scan.created_at)}${scan.duration != null ? ` · took ${dur(scan.duration)}` : ''}`}
        right={<>
          {running && <button className="btn-danger" onClick={() => api.cancelScan(scan.id)}>Stop</button>}
          {!running && <button className="btn-ghost" onClick={again}>Run again</button>}
          {rows.length > 0 && <a className="btn-primary" href={api.scanFindingsExportUrl(scan.id)} download>Download Excel</a>}
        </>} />
      <div className="mb-4 flex flex-wrap items-center gap-4">
        <StateBadge state={scan.state} />
        {hist.length > 1 && <label className="flex items-center gap-2 text-xs text-mute">Run history
          <select className="rounded border border-line bg-raised px-2 py-1 text-xs text-ink" value={scan.id} onChange={(e) => nav(`/p/${id}/webapp/tool/${e.target.value}`)}>
            {hist.map((h, i) => <option key={h.id} value={h.id}>{i === 0 ? 'Latest' : `Run ${hist.length - i}`} · {when(h.created_at)} · {h.state}</option>)}</select></label>}
      </div>
      <div className="mb-4 space-y-2">
        {scan.error && <Banner kind="error" title="This run did not complete">{scan.error}</Banner>}
        {err && <Banner kind="error">{err}</Banner>}
        {(res.warnings || []).map((w, i) => <Banner key={i} kind="warn">{w}</Banner>)}
      </div>

      <div className="mb-5 grid grid-cols-2 gap-3 sm:grid-cols-5">
        {SEVS.map((s) => <button key={s} onClick={() => { setSev(s); setTab('findings') }} className={`card p-3 text-left ${sev === s ? 'border-brand' : ''}`}>
          <SeverityPill sev={s} /><div className="mt-2 font-mono text-2xl text-ink">{counts[s]}</div></button>)}
      </div>

      <Tabs tabs={tabs} value={tab || 'findings'} onChange={setTab} />
      <div className="pt-4">
        {tab === 'findings' && (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-1.5">
              {[['actionable', `Needs attention ${ACTIONABLE.reduce((a, s) => a + counts[s], 0)}`], ...SEVS.filter((s) => counts[s]).map((s) => [s, `${s[0].toUpperCase() + s.slice(1)} ${counts[s]}`]), ['all', `Everything ${rows.length}`]]
                .map(([k, l]) => <button key={k} onClick={() => setSev(k)} className={`chip ${sev === k ? 'border-brand text-ink' : ''}`}>{l}</button>)}
              <input className="input ml-auto !w-60 !py-1.5 text-xs" placeholder="Search findings" value={q} onChange={(e) => setQ(e.target.value)} />
            </div>
            <FindingsTable rows={shown} empty={emptyFindings} />
          </div>)}
        {tab === 'endpoints' && (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-1.5">
              {[['interesting', 'Look at first'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low'], ['noise', 'Likely noise'], ['all', 'Everything']]
                .map(([k, l]) => <button key={k} onClick={() => setPri(k)} className={`chip ${pri === k ? 'border-brand text-ink' : ''}`}>{l}</button>)}
              <input className="input ml-auto !w-60 !py-1.5 text-xs" placeholder="Search path" value={q} onChange={(e) => setQ(e.target.value)} />
            </div>
            <EndpointsTable eps={eps} />
          </div>)}
        {tab === 'targets' && (
          <div className="space-y-5">
            {targets.length === 0 ? <Empty title={running ? 'No target has finished yet' : 'No target was scanned'}>{scan.error || 'Per-target results appear here as the scan progresses.'}</Empty> : (
              <div className="card overflow-x-auto"><table className="w-full text-sm">
                <thead><tr className="bg-raised text-left text-xs text-mute"><th className="px-4 py-2.5 font-medium">Target</th><th className="px-4 py-2.5 font-medium">Result</th><th className="px-4 py-2.5 font-medium">Details</th><th className="px-4 py-2.5 font-medium">Time</th><th className="w-28 px-4 py-2.5" /></tr></thead>
                <tbody>{targets.map((t, i) => { const [dot, label] = TARGET_STATUS[t.status] || ['bg-faint', t.status]; return (
                  <tr key={t.target} className="border-t border-line align-top">
                    <td className="px-4 py-3 font-mono text-[13px] text-ink">{t.target}</td>
                    <td className="px-4 py-3"><span className="inline-flex items-center gap-2 text-xs text-mute"><span className={`dot ${dot}`} />{label}</span></td>
                    <td className="max-w-lg px-4 py-3 text-xs text-mute">{t.note || (t.status === 'ok' ? `${t.count} ${isDir ? 'endpoints' : 'findings'}` : '')}</td>
                    <td className="px-4 py-3 font-mono text-xs text-faint">{t.seconds != null ? dur(t.seconds) : ''}</td>
                    <td className="px-4 py-3 text-right"><button className="btn-sub" onClick={() => { setChan(`t${i + 1}`); setTab('terminal') }}>View terminal</button></td>
                  </tr>) })}</tbody></table></div>)}
            <div className="card p-4"><h3 className="mb-2 text-sm font-medium text-ink">Saved files</h3>
              {scan.outputs.length ? <><ul className="space-y-1 font-mono text-xs text-mute">{scan.outputs.map((o) => <li key={o}>{o}</li>)}</ul>
                <p className="mt-3 text-xs text-faint">In your project folder, under webapt{res.folder ? ` / ${res.folder}` : ''}.</p></> : <p className="text-sm text-mute">No files have been written yet.</p>}</div>
          </div>)}
        {tab === 'terminal' && (scan.channels.length === 0
          ? <Empty title={running ? 'Starting…' : 'No terminal output'}>{scan.error || 'This run did not start a tool.'}</Empty>
          : <ScanTerminal scanId={scan.id} channels={scan.channels} initial={chan} rows={30} />)}
      </div>
    </>
  )
}

export function RedirectTool() {
  const { id, scanId } = useParams()
  return <Navigate to={`/p/${id}/webapp/tool/${scanId}`} replace />
}

// ------------------------------------------------------------------ project-wide views
export function WebAllFindings() {
  const { id } = useParams()
  const crumbs = useWebCrumbs(id, [{ label: 'All findings' }])
  const [data, setData] = useState(null)
  const [sev, setSev] = useState('all')
  const [tool, setTool] = useState('all')
  const [q, setQ] = useState('')
  useEffect(() => { api.web.findings(id).then(setData).catch(() => setData({ findings: [], counts: {} })) }, [id])
  if (!data) return <p className="text-sm text-mute">Loading…</p>
  const tools = [...new Set(data.findings.map((f) => f.tool))]
  const shown = data.findings.filter((f) => (sev === 'all' || f.severity === sev) && (tool === 'all' || f.tool === tool)
    && (!q || `${f.title} ${f.target} ${f.evidence}`.toLowerCase().includes(q.toLowerCase())))
  return (
    <>
      <Crumbs items={crumbs} />
      <PageTitle title="All findings" sub="Combined results from the latest run of every tool, most severe first."
        right={data.findings.length > 0 && <a className="btn-primary" href={api.web.findingsExportUrl(id)} download>Download Excel</a>} />
      <div className="mb-5 grid grid-cols-2 gap-3 sm:grid-cols-5">
        {SEVS.map((s) => <button key={s} onClick={() => setSev(sev === s ? 'all' : s)} className={`card p-3 text-left ${sev === s ? 'border-brand' : ''}`}>
          <SeverityPill sev={s} /><div className="mt-2 font-mono text-2xl text-ink">{data.counts[s] || 0}</div></button>)}
      </div>
      <div className="mb-4 flex flex-wrap items-center gap-1.5">
        {tools.length > 1 && <><button onClick={() => setTool('all')} className={`chip ${tool === 'all' ? 'border-brand text-ink' : ''}`}>All tools</button>
          {tools.map((t) => <button key={t} onClick={() => setTool(t)} className={`chip ${tool === t ? 'border-brand text-ink' : ''}`}>{t}</button>)}</>}
        <input className="input ml-auto !w-60 !py-1.5 text-xs" placeholder="Search findings" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      <FindingsTable rows={shown} showTool empty={<Empty mood="sleep" title="No findings yet">Run one or more tools from the Web App PT page. Results from every tool are combined here.</Empty>} />
    </>
  )
}

export function WebDiscovery() {
  const { id } = useParams()
  const crumbs = useWebCrumbs(id, [{ label: 'Content discovery' }])
  const [data, setData] = useState(null)
  const [pri, setPri] = useState('interesting')
  const [q, setQ] = useState('')
  useEffect(() => { api.web.discovery(id).then(setData).catch(() => setData({ endpoints: [], counts: {}, tools: [], noise: 0 })) }, [id])
  if (!data) return <p className="text-sm text-mute">Loading…</p>
  const filt = data.endpoints.filter((e) => {
    if (q && !(`${e.path} ${e.origin}`).toLowerCase().includes(q.toLowerCase())) return false
    if (pri === 'interesting') return !e.noise && (e.priority === 'high' || e.priority === 'medium')
    if (pri === 'noise') return e.noise
    if (pri === 'all') return true
    return e.priority === pri && !e.noise
  })
  const c = data.counts
  return (
    <>
      <Crumbs items={crumbs} />
      <PageTitle title="Content discovery intelligence" sub={data.tools.length ? `Merged from ${data.tools.join(', ')}. Endpoints found by several tools rank higher.` : 'Run ffuf, feroxbuster or dirsearch first.'} />
      {data.endpoints.length === 0 ? <Empty mood="sleep" title="Nothing to analyse yet">Run at least one directory discovery tool from the Web App PT page.</Empty> : (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            {[['interesting', `Look at first · ${(c.high || 0) + (c.medium || 0)}`], ['high', `High · ${c.high || 0}`], ['medium', `Medium · ${c.medium || 0}`], ['low', `Low · ${c.low || 0}`], ['noise', `Likely noise · ${data.noise}`], ['all', 'Everything']]
              .map(([k, l]) => <button key={k} onClick={() => setPri(k)} className={`chip ${pri === k ? 'border-brand text-ink' : ''}`}>{l}</button>)}
            <input className="input ml-auto !w-56 !py-1.5 text-xs" placeholder="Search path or host" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          <EndpointsTable eps={filt} />
        </div>)}
    </>
  )
}
