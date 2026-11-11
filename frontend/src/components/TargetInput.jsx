import { useEffect, useState } from 'react'
import { api } from '../api'

const KIND = { ip: 'IP', cidr: 'range', domain: 'domain', url: 'domain' }

/** Textarea that classifies pasted targets live (IPs, CIDR ranges, domains, URLs). */
export default function TargetInput({ value, onChange, placeholder, disabled, rows = 6, only }) {
  const [items, setItems] = useState([])
  useEffect(() => {
    if (!value.trim()) { setItems([]); return }
    const t = setTimeout(() => api.previewTargets(value).then((r) => setItems(r.items)).catch(() => {}), 250)
    return () => clearTimeout(t)
  }, [value])
  const ok = items.filter((i) => i.kind !== 'unknown' && (!only || only.includes(i.kind)))
  const bad = items.filter((i) => i.kind === 'unknown' || (only && !only.includes(i.kind)))
  const count = (k) => ok.filter((i) => KIND[i.kind] === k).length
  return (
    <div>
      <textarea className="input font-mono text-[13px] leading-relaxed" rows={rows} value={value} disabled={disabled}
        placeholder={placeholder} onChange={(e) => onChange(e.target.value)} spellCheck={false} />
      <div className="mt-2 flex flex-wrap items-center gap-1.5 text-xs">
        {!value.trim() && <span className="text-faint">Paste or type targets. New lines, commas, spaces and semicolons all work.</span>}
        {count('IP') > 0 && <span className="chip">{count('IP')} IP address{count('IP') > 1 ? 'es' : ''}</span>}
        {count('range') > 0 && <span className="chip">{count('range')} range{count('range') > 1 ? 's' : ''}</span>}
        {count('domain') > 0 && <span className="chip">{count('domain')} domain{count('domain') > 1 ? 's' : ''}</span>}
        {bad.length > 0 && <span className="chip border-crit/40 text-crit" title={bad.map((b) => b.raw).join(', ')}>
          {bad.length} not usable: {bad.slice(0, 3).map((b) => b.raw).join(', ')}{bad.length > 3 ? '…' : ''}</span>}
      </div>
    </div>
  )
}
