import { useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api } from '../api'
import { Crumbs, PageTitle } from '../components/Layout'
import { Banner, Switch, useUi } from '../components/ui'

const GROUPS = ['General', 'External pentest', 'Web App PT', 'System']
const SYSTEM = { id: 'system', group: 'System', label: 'System checks', blurb: 'Which tools are installed, and whether nmap can scan without a password.', fields: [] }

function Field({ f, value, onChange }) {
  const v = value ?? ''
  if (f.kind === 'bool') {
    return (
      <div className="flex items-start justify-between gap-6">
        <div className="min-w-0"><p className="text-sm text-ink">{f.label}</p>{f.hint && <p className="mt-0.5 text-xs leading-relaxed text-faint">{f.hint}</p>}</div>
        <Switch checked={v === '1'} onChange={(on) => onChange(on ? '1' : '0')} label={f.label} />
      </div>
    )
  }
  let input
  if (f.kind === 'select') input = <select className="input !w-56" value={v} onChange={(e) => onChange(e.target.value)}>{f.options.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
  else if (f.kind === 'int') input = <input className="input !w-44 font-mono text-[13px]" inputMode="numeric" value={v} placeholder={f.blank ? 'Default' : ''} onChange={(e) => onChange(e.target.value.replace(/[^\d]/g, ''))} />
  else input = <input className="input font-mono text-[13px]" value={v} spellCheck={false} placeholder={f.kind === 'args' ? 'Optional' : ''} onChange={(e) => onChange(e.target.value)} />
  return <div><label className="label">{f.label}</label>{input}{f.hint && <p className="mt-1 text-xs text-faint">{f.hint}</p>}</div>
}

function SystemChecks({ health, priv, onCheck }) {
  return (
    <div className="space-y-6">
      <div>
        <h3 className="mb-1 text-sm font-medium text-ink">Scanning without a password</h3>
        <p className="mb-3 text-xs text-faint">Checks that nmap can run SYN and UDP scans without sudo.</p>
        <button className="btn-ghost" onClick={onCheck} disabled={priv?.loading}>{priv?.loading ? 'Checking…' : 'Run check'}</button>
        {priv && !priv.loading && <div className="mt-3">{priv.ok ? <Banner kind="ok">nmap can use raw sockets without sudo.</Banner>
          : <Banner kind="error" title="Raw sockets are not available">{priv.detail}{priv.fix && <span className="mt-2 block break-all font-mono text-xs text-ink">{priv.fix}</span>}</Banner>}</div>}
      </div>
      <div>
        <h3 className="mb-3 text-sm font-medium text-ink">Installed tools</h3>
        <ul className="space-y-3">{(health?.tools || []).map((t) => (
          <li key={t.key} className="text-sm"><div className="flex items-center justify-between"><span className="font-mono text-mute">{t.key}</span>
            <span className={`inline-flex items-center gap-2 text-xs ${t.found ? 'text-ok' : 'text-high'}`}><span className={`dot ${t.found ? 'bg-ok' : 'bg-high'}`} />{t.found ? 'found' : 'missing'}</span></div>
            {!t.found && <p className="mt-0.5 break-all font-mono text-xs text-faint">{t.install}</p>}</li>))}</ul>
        {health && !health.seclists && <p className="mt-3 text-xs text-med">SecLists not found. Run: sudo apt install seclists</p>}
        <p className="mt-3 text-xs text-faint">You can also run <span className="font-mono">lasy doctor</span> in the terminal.</p>
      </div>
    </div>
  )
}

export default function Settings() {
  const { setPrefs } = useUi()
  const [params, setParams] = useSearchParams()
  const [schema, setSchema] = useState(null)
  const [values, setValues] = useState(null)
  const [saved, setSaved] = useState(null)
  const [health, setHealth] = useState(null)
  const [priv, setPriv] = useState(null)
  const [preview, setPreview] = useState({})
  const [msg, setMsg] = useState({ kind: '', text: '' })
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    api.settingsSchema().then((s) => setSchema(s.categories)).catch(() => setSchema([]))
    api.getSettings().then((v) => { setValues(v); setSaved(v) }).catch(() => { setValues({}); setSaved({}) })
    api.health().then(setHealth).catch(() => {})
  }, [])
  useEffect(() => {   // live "command that will run", using the values as typed (saved or not)
    if (!values) return undefined
    const t = setTimeout(() => api.previewSettings(values).then(setPreview).catch(() => {}), 250)
    return () => clearTimeout(t)
  }, [values])

  const cats = useMemo(() => [...(schema || []), SYSTEM], [schema])
  const current = cats.find((c) => c.id === params.get('section')) || cats[0]
  const dirtyIn = (c) => c.fields.some((f) => (values?.[f.key] ?? '') !== (saved?.[f.key] ?? ''))
  const dirty = cats.some(dirtyIn)

  async function save() {
    setBusy(true); setMsg({ kind: '', text: '' })
    try {
      const out = await api.putSettings(values)
      setValues(out); setSaved(out)
      setPrefs({ mascot: out.ui_mascot === '1', size: out.ui_text_size || 'large', style: out.ui_style || 'glass' })
      setMsg({ kind: 'ok', text: 'Settings saved.' })
    } catch (e) { setMsg({ kind: 'error', text: e.message }) }
    setBusy(false)
  }
  async function checkPriv() { setPriv({ loading: true }); try { setPriv(await api.healthNmap()) } catch (e) { setPriv({ ok: false, detail: e.message }) } }
  const resettable = current.fields.filter((f) => !f.computed)
  const resetSection = () => setValues({ ...values, ...Object.fromEntries(resettable.map((f) => [f.key, f.default])) })

  if (!schema || !values) return <p className="text-sm text-mute">Loading…</p>
  return (
    <>
      <Crumbs items={[{ label: 'Projects', to: '/' }, { label: 'Settings' }]} />
      <PageTitle title="Settings" sub="These apply to every project. Pick a category on the left." />
      <div className="grid gap-6 md:grid-cols-[14.5rem_minmax(0,1fr)]">
        <nav aria-label="Settings categories" className="md:sticky md:top-6 md:self-start">
          {GROUPS.map((g) => (
            <div key={g} className="mb-4">
              <p className="mb-1.5 px-2 text-[11px] font-medium uppercase tracking-wider text-faint">{g}</p>
              <div className="flex flex-wrap gap-1 md:block md:space-y-0.5">
                {cats.filter((c) => c.group === g).map((c) => (
                  <button key={c.id} onClick={() => setParams({ section: c.id })}
                    className={`flex w-full items-center justify-between rounded-md px-2.5 py-1.5 text-left text-sm ${current.id === c.id ? 'bg-brand/10 text-ink' : 'text-mute hover:bg-raised hover:text-ink'}`}>
                    <span>{c.label}</span>{dirtyIn(c) && <span className="dot bg-med" title="Unsaved changes" />}
                  </button>))}
              </div>
            </div>))}
        </nav>

        <section className="card min-w-0 p-5">
          <div className="mb-5 flex flex-wrap items-start justify-between gap-3 border-b border-line pb-4">
            <div><h2 className="text-base font-medium text-ink">{current.label}</h2><p className="mt-0.5 text-sm text-mute">{current.blurb}</p></div>
            {resettable.length > 0 && <button className="btn-sub" onClick={resetSection}>Reset this section to defaults</button>}
          </div>
          {current.id === 'system' ? <SystemChecks health={health} priv={priv} onCheck={checkPriv} /> : (
            <div className="space-y-5">
              {current.fields.map((f) => <Field key={f.key} f={f} value={values[f.key]} onChange={(v) => setValues({ ...values, [f.key]: v })} />)}
              {preview[current.id] && (
                <div className="rounded-md border border-black bg-[#0c0c0c] p-3">
                  <p className="mb-1 text-[11px] uppercase tracking-wider text-faint">Command that will run</p>
                  <p className="break-all font-mono text-[12.5px] leading-relaxed text-[#cccccc]"><span className="text-[#16c60c]">$</span> {preview[current.id]}</p>
                </div>)}
            </div>)}
          {current.id !== 'system' && (
            <div className="mt-6 flex flex-wrap items-center gap-3 border-t border-line pt-4">
              <button className="btn-primary" onClick={save} disabled={busy || !dirty}>{busy ? 'Saving…' : 'Save settings'}</button>
              {dirty && <span className="text-xs text-med">You have unsaved changes{cats.filter(dirtyIn).length > 1 ? ' in more than one category' : ''}.</span>}
              {msg.text && <span className={`text-sm ${msg.kind === 'ok' ? 'text-ok' : 'text-crit'}`}>{msg.text}</span>}
            </div>)}
        </section>
      </div>
    </>
  )
}
