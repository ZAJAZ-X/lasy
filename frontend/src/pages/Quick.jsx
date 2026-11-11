import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { api } from '../api'
import { Crumbs, PageTitle } from '../components/Layout'
import ScanTerminal from '../components/Term'
import TargetInput from '../components/TargetInput'
import { HostTable, NameserverTable, SubdomainTable } from '../components/ReportTables'
import { Banner, Empty, StateBadge, Tabs, useProject, usePoll } from '../components/ui'

const RUNNING = ['queued', 'running']

/** Shared page for the small tools: input -> live terminal -> report table -> Excel. */
function Workbench({ kind, title, sub, label, inputLabel, placeholder, runLabel, only, onRun, extra, renderResult, resultCount, emptyHint }) {
  const { id } = useParams()
  const project = useProject(id)
  const [text, setText] = useState('')
  const [scan, setScan] = useState(null)
  const [tab, setTab] = useState('result')
  const [error, setError] = useState('')
  const running = scan && RUNNING.includes(scan.state)

  useEffect(() => {
    api.listScans(id, kind).then((l) => { if (l[0]) { setScan(l[0]); setTab(l[0].state === 'done' ? 'result' : 'terminal') } }).catch(() => {})
  }, [id, kind])
  usePoll(async () => { if (scan) setScan(await api.getScan(scan.id)) }, 1200, [scan?.id], !!running)
  useEffect(() => { if (scan && !running && scan.state === 'done') setTab('result') }, [running, scan?.state]) // eslint-disable-line

  async function start() {
    setError('')
    try { const s = await onRun(id, text); setScan(s); setTab('terminal') } catch (e) { setError(e.message) }
  }
  const tabs = [{ id: 'result', label: 'Results' }, ...(extra?.tabs || []), { id: 'terminal', label: 'Terminal output' }]
  const rows = scan?.result_json?.rows || []

  return (
    <>
      <Crumbs items={[{ label: 'Projects', to: '/' }, { label: project?.name || '…', to: `/p/${id}` }, { label: 'EPT', to: `/p/${id}/ept` }, { label }]} />
      <PageTitle title={title} sub={sub} />
      <div className="card mb-6 p-4">
        <label className="label">{inputLabel}</label>
        <TargetInput value={text} onChange={setText} placeholder={placeholder} disabled={running} rows={4} only={only} />
        {extra?.options}
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <button className="btn-primary" onClick={start} disabled={running || !text.trim()}>{running ? 'Running…' : runLabel}</button>
          {running && <button className="btn-ghost" onClick={() => api.cancelScan(scan.id)}>Stop</button>}
        </div>
        {error && <p className="mt-3 text-sm text-crit">{error}</p>}
      </div>

      {!scan ? <Empty mood="sleep" title="No results yet">Enter your targets above and run the check. Results and live output appear here.</Empty> : (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-4"><StateBadge state={scan.state} />
              {scan.outputs?.length > 0 && <span className="text-xs text-faint">Saved: {scan.outputs.slice(0, 3).join(', ')}{scan.outputs.length > 3 ? ` +${scan.outputs.length - 3} more` : ''}</span>}
            </div>
            {scan.state === 'done' && rows.length > 0 && <a className="btn-primary" href={api.exportScanUrl(scan.id)} download>Download Excel</a>}
          </div>
          {scan.error && <Banner kind="error" title="This scan could not finish">{scan.error}</Banner>}
          <Tabs tabs={tabs} value={tab} onChange={setTab} />
          {tab === 'terminal' && <ScanTerminal scanId={scan.id} channels={scan.channels} rows={26} />}
          {tab === 'result' && (
            running ? <Empty mood="wait" title="Scan in progress">The table appears when the scan finishes. Switch to Terminal output to watch it live.</Empty>
              : rows.length === 0 ? <Empty title="No results">{emptyHint ? emptyHint(scan) : scan.state === 'done' ? 'The scan finished without producing any rows.' : 'The scan did not produce results.'}</Empty>
                : <>{resultCount && <p className="mb-2 text-sm text-mute">{resultCount(scan.result_json)}</p>}{renderResult(scan.result_json)}</>
          )}
          {extra?.render && tab !== 'result' && tab !== 'terminal' && extra.render(tab, scan)}
        </div>
      )}
    </>
  )
}

export function NameserverPage() {
  return <Workbench kind="nameserver" label="Nameserver lookup" title="Nameserver lookup"
    sub="Finds a domain’s authoritative nameservers with dig. The full dig output is shown in the terminal tab."
    inputLabel="Domains" placeholder={'example.com\nclient.org'} runLabel="Look up nameservers" only={['domain', 'url']}
    onRun={(id, t) => api.runNameserver(id, t)} renderResult={(r) => <NameserverTable rows={r.rows} />} />
}

export function HostUpPage() {
  return <Workbench kind="hostup" label="Host up / down" title="Host up / down"
    sub="Runs a ping sweep with nmap -sn. Every IP or domain you enter gets a row; ranges list only the hosts that respond."
    inputLabel="Hosts, IP addresses or ranges" placeholder={'192.168.1.10\nexample.com\n10.0.0.0/24'} runLabel="Check hosts"
    onRun={(id, t) => api.runHostup(id, t)} renderResult={(r) => <HostTable rows={r.rows} />}
    resultCount={(r) => `${r.rows.filter((x) => x.status === 'Up').length} of ${r.rows.length} hosts are up.`} />
}

const SUB_TOOLS = [
  { key: 'subfinder', label: 'subfinder', note: 'Passive sources' },
  { key: 'knockpy', label: 'knockpy', note: 'Recon and brute force (best effort)' },
  { key: 'amass', label: 'amass', note: 'Passive OSINT sources' },
  { key: 'assetfinder', label: 'assetfinder', note: 'Certificate and search sources' },
  { key: 'crtsh', label: 'crt.sh', note: 'Certificate transparency (built in)' },
]

function SubResult({ r }) {
  const [hide, setHide] = useState(false)
  const wild = r.rows.filter((x) => x.wildcard)
  const rows = hide ? r.rows.filter((x) => !x.wildcard) : r.rows
  return (
    <div className="space-y-3">
      {wild.length > 0 && (
        <Banner kind="warn" title="Wildcard DNS detected">
          {Object.entries(r.wildcards || {}).map(([d, ip]) => <span key={d} className="block">Any name under {d} resolves to {ip}, so subdomains with that IP may not be real hosts.</span>)}
          <label className="mt-2 flex cursor-pointer items-center gap-2 text-sm text-ink">
            <input type="checkbox" className="accent-[#37B6A6]" checked={hide} onChange={(e) => setHide(e.target.checked)} />
            Hide the {wild.length} name{wild.length > 1 ? 's' : ''} that only resolve through the wildcard record
          </label>
        </Banner>
      )}
      <SubdomainTable rows={rows} />
    </div>
  )
}

export function SubdomainPage() {
  const [tools, setTools] = useState(SUB_TOOLS.map((t) => t.key))
  const [avail, setAvail] = useState({})
  useEffect(() => { api.health().then((h) => setAvail(Object.fromEntries(h.tools.map((t) => [t.key, t.found])))).catch(() => {}) }, [])
  const toggle = (k) => setTools((cur) => (cur.includes(k) ? cur.filter((x) => x !== k) : [...cur, k]))

  const options = (
    <div className="mt-4">
      <span className="label">Sources</span>
      <div className="flex flex-wrap gap-2">
        {SUB_TOOLS.map((t) => {
          const missing = t.key !== 'crtsh' && avail[t.key] === false
          return (
            <label key={t.key} className={`flex cursor-pointer items-start gap-2 rounded-md border px-3 py-2 text-sm ${tools.includes(t.key) ? 'border-brand/60 bg-brand/5' : 'border-line'}`}>
              <input type="checkbox" className="mt-1 accent-[#37B6A6]" checked={tools.includes(t.key)} onChange={() => toggle(t.key)} />
              <span><span className="text-ink">{t.label}</span>{missing && <span className="ml-2 text-xs text-high">not installed</span>}
                <span className="block text-xs text-faint">{t.note}</span></span>
            </label>
          )
        })}
      </div>
      <p className="mt-2 text-xs text-faint">A source that is missing or fails only contributes less; it never stops the run.</p>
    </div>
  )

  const SummaryTable = ({ r }) => (
    <div className="space-y-5">
      <div className="card overflow-hidden">
        <table className="w-full text-sm">
          <thead><tr className="bg-raised text-left text-xs text-mute">
            <th className="px-4 py-2.5 font-medium">Source</th><th className="px-4 py-2.5 font-medium">Status</th>
            <th className="px-4 py-2.5 font-medium">Subdomains found</th><th className="px-4 py-2.5 font-medium">Found only by this source</th></tr></thead>
          <tbody>
            {Object.entries(r.summary).map(([k, s]) => (
              <tr key={k} className="border-t border-line">
                <td className="px-4 py-2.5 text-ink">{r.labels[k] || k}</td>
                <td className="px-4 py-2.5"><span className={s.state === 'ok' ? 'text-ok' : s.state === 'missing' ? 'text-high' : 'text-crit'}>
                  {s.state === 'ok' ? 'Completed' : s.state === 'missing' ? 'Not installed' : 'Failed'}</span>
                  {s.note && <span className="ml-2 text-xs text-faint">{s.note}</span>}</td>
                <td className="px-4 py-2.5 font-mono">{s.found}</td><td className="px-4 py-2.5 font-mono">{s.unique}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="grid gap-3 md:grid-cols-2">
        {Object.entries(r.unique).map(([k, names]) => (
          <details key={k} className="card p-3" open={names.length > 0 && names.length <= 12}>
            <summary className="cursor-pointer text-sm text-ink">Only found by {r.labels[k] || k} <span className="text-faint">({names.length})</span></summary>
            <div className="mt-2 max-h-56 overflow-auto font-mono text-xs leading-relaxed text-mute">
              {names.length ? names.map((n) => <div key={n}>{n}</div>) : <span className="text-faint">Nothing unique.</span>}
            </div>
          </details>
        ))}
      </div>
    </div>
  )

  return <Workbench kind="subdomain" label="Subdomain enumeration" title="Subdomain enumeration"
    sub="Runs several sources in parallel, merges the results, resolves every name to an IP and checks whether it answers over HTTP(S)."
    inputLabel="Root domains" placeholder={'example.com'} runLabel="Enumerate subdomains" only={['domain', 'url']}
    onRun={(id, t) => api.runSubdomain(id, t, tools)}
    extra={{ options, tabs: [{ id: 'bytool', label: 'By source' }], render: (tab, scan) => (tab === 'bytool' && scan.result_json ? <SummaryTable r={scan.result_json} /> : null) }}
    renderResult={(r) => <SubResult r={r} />}
    emptyHint={() => 'No subdomain was found. Open the By source tab to see whether each tool ran, was not installed, or failed.'}
    resultCount={(r) => `${r.rows.length} unique subdomains · ${r.rows.filter((x) => x.ip).length} resolved · ${r.rows.filter((x) => x.accessible === 'yes').length} reachable over HTTP(S).`} />
}
