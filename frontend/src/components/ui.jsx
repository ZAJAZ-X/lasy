import { createContext, useContext, useEffect, useRef, useState } from 'react'
import { api } from '../api'
import { SlothScene } from './Mascot'

export const UiContext = createContext({ mascot: true, size: 'large', setPrefs: () => {} })
export const useUi = () => useContext(UiContext)

/** Calls fn now and every `ms` while `enabled`. fn should set state. */
export function usePoll(fn, ms, deps = [], enabled = true) {
  const ref = useRef(fn)
  ref.current = fn
  useEffect(() => {
    let live = true
    const tick = () => { if (live) Promise.resolve(ref.current()).catch(() => {}) }
    tick()
    if (!enabled) return () => { live = false }
    const t = setInterval(tick, ms)
    return () => { live = false; clearInterval(t) }
    // eslint-disable-next-line
  }, [...deps, enabled, ms])
}

export function useProject(id) {
  const [p, setP] = useState(null)
  useEffect(() => { api.getProject(id).then(setP).catch(() => {}) }, [id])
  return p
}

const STATES = {
  pending: ['bg-faint', 'Not started'], queued: ['bg-med', 'Queued'], running: ['bg-brand pulse', 'Running'],
  paused: ['bg-low', 'Paused'], interrupted: ['bg-high', 'Interrupted'], done: ['bg-ok', 'Completed'],
  failed: ['bg-crit', 'Failed'], canceled: ['bg-faint', 'Stopped'],
}
export function StateBadge({ state }) {
  const [dot, label] = STATES[state] || ['bg-faint', state]
  return <span className="inline-flex items-center gap-2 whitespace-nowrap text-xs text-mute"><span className={`dot ${dot}`} />{label}</span>
}

const SEV = {
  critical: 'bg-crit text-white', high: 'bg-high text-white', medium: 'bg-med text-black',
  low: 'bg-low text-white', info: 'bg-line2 text-ink',
}
export function SeverityPill({ sev }) {
  return <span className={`inline-block min-w-[4.5rem] rounded px-2 py-0.5 text-center text-xs font-semibold ${SEV[sev] || SEV.info}`}>{sev ? sev[0].toUpperCase() + sev.slice(1) : '-'}</span>
}

export function Banner({ kind = 'info', title, children }) {
  const tone = { info: 'border-low/40 bg-low/10', warn: 'border-med/40 bg-med/10', error: 'border-crit/40 bg-crit/10', ok: 'border-ok/40 bg-ok/10' }[kind]
  return (
    <div className={`rounded-md border px-3.5 py-2.5 text-sm ${tone}`}>
      {title && <div className="font-medium text-ink">{title}</div>}
      <div className="text-mute">{children}</div>
    </div>
  )
}

const MOOD_LINE = { wait: 'Lasy is on it. Grab a coffee.', sleep: 'Lasy is napping until there is something to do.' }

/** mood="wait" | "sleep" adds the sloth (if enabled in Settings). Use it on at most one card per screen. */
export function Empty({ title, children, action, mood }) {
  const { mascot } = useUi()
  return (
    <div className="card grid place-items-center p-10 text-center">
      <div className="max-w-md">
        {mood && mascot && <SlothScene mood={mood} />}
        <p className="text-ink">{title}</p>
        {children && <p className="mt-1 text-sm text-mute">{children}</p>}
        {mood && mascot && <p className="mt-2 text-xs text-faint">{MOOD_LINE[mood]}</p>}
        {action && <div className="mt-4">{action}</div>}
      </div>
    </div>
  )
}

export function ProgressBar({ value = 0, active = false, indeterminate = false }) {
  return (
    <div className="relative h-1.5 w-full overflow-hidden rounded bg-line">
      {indeterminate
        ? <div className="indeterminate absolute inset-y-0 left-0 w-1/3 rounded bg-brand" />
        : <div className={`h-full rounded ${active ? 'bg-brand' : 'bg-ok'}`} style={{ width: `${Math.round(value * 100)}%` }} />}
    </div>
  )
}

export function Tabs({ tabs, value, onChange }) {
  return (
    <div className="seg" role="tablist">
      {tabs.map((t) => (
        <button key={t.id} role="tab" aria-selected={value === t.id} onClick={() => onChange(t.id)} className={`seg-btn ${value === t.id ? 'seg-on' : ''}`}>
          {t.label}{t.count !== undefined && <span className="seg-count">{t.count}</span>}
        </button>
      ))}
    </div>
  )
}

/** Dialog: closes on Escape or a click outside. Put the primary field first so it gets focus. */
export function Modal({ title, onClose, children, width }) {
  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', onKey)
    const prev = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => { document.removeEventListener('keydown', onKey); document.body.style.overflow = prev }
  }, [onClose])
  return (
    <div className="modal-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose() }}>
      <div className="card modal p-6" role="dialog" aria-modal="true" aria-label={title} style={width ? { maxWidth: width } : undefined}>{children}</div>
    </div>
  )
}

export function Switch({ checked, onChange, label }) {
  return <button type="button" role="switch" aria-checked={checked} aria-label={label} onClick={() => onChange(!checked)} className="switch" />
}

export function timeAgo(iso) {
  const t = new Date(iso).getTime()
  if (!t) return ''
  const s = Math.max(0, Math.round((Date.now() - t) / 1000))
  if (s < 60) return 'just now'
  const units = [[60, 'minute'], [3600, 'hour'], [86400, 'day'], [604800, 'week'], [2592000, 'month']]
  let out = ['year', Math.round(s / 31536000)]
  for (let i = 0; i < units.length; i += 1) {
    const next = units[i + 1]
    if (!next || s < next[0]) { out = [units[i][1], Math.floor(s / units[i][0])]; break }
  }
  return `${out[1]} ${out[0]}${out[1] === 1 ? '' : 's'} ago`
}

export function formatBytes(n) {
  if (!n) return '0 B'
  const u = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)))
  return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${u[i]}`
}
