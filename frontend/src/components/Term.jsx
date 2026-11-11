import { forwardRef, useEffect, useImperativeHandle, useRef, useState } from 'react'
import { Terminal } from '@xterm/xterm'
import { wsUrl } from '../api'

// Windows Terminal "Campbell" palette: what a Kali WSL window really looks like.
const THEME = {
  background: '#0c0c0c', foreground: '#cccccc', cursor: '#cccccc', cursorAccent: '#0c0c0c',
  selectionBackground: 'rgba(255,255,255,0.28)',
  black: '#0c0c0c', red: '#c50f1f', green: '#13a10e', yellow: '#c19c00', blue: '#0037da',
  magenta: '#881798', cyan: '#3a96dd', white: '#cccccc',
  brightBlack: '#767676', brightRed: '#e74856', brightGreen: '#16c60c', brightYellow: '#f9f1a5',
  brightBlue: '#3b78ff', brightMagenta: '#b4009e', brightCyan: '#61d6d6', brightWhite: '#f2f2f2',
}
const FONT = '"Cascadia Mono","Cascadia Code",Consolas,"Liberation Mono","DejaVu Sans Mono",monospace'

const XTerm = forwardRef(function XTerm({ scanId, channel, fontSize, rows }, ref) {
  const host = useRef(null)
  const term = useRef(null)
  useImperativeHandle(ref, () => ({
    copyAll() {
      const t = term.current
      if (!t) return ''
      t.selectAll(); const text = t.getSelection(); t.clearSelection()
      return text
    },
  }))
  useEffect(() => {
    const t = new Terminal({
      cols: 120, rows, fontFamily: FONT, fontSize, theme: THEME, scrollback: 30000,
      cursorStyle: 'block', cursorBlink: true, cursorInactiveStyle: 'block',
      disableStdin: true, drawBoldTextInBrightColors: true, lineHeight: 1.12,
    })
    t.open(host.current)
    term.current = t
    let ws, retry, closed = false, first = true
    const connect = () => {   // reconnects if the backend restarts; the replay is resent, so clear first
      ws = new WebSocket(wsUrl(scanId, channel))
      ws.onopen = () => { first = true; t.reset() }
      ws.onmessage = (e) => {   // follow new output unless you have scrolled up to read earlier lines
        const b = t.buffer.active
        const follow = first || b.viewportY >= b.baseY - 1
        first = false
        t.write(e.data, () => { if (follow) t.scrollToBottom() })
      }
      ws.onclose = () => { if (!closed) retry = setTimeout(connect, 2500) }
    }
    connect()
    return () => { closed = true; clearTimeout(retry); if (ws) ws.close(); t.dispose(); term.current = null }
    // eslint-disable-next-line
  }, [scanId, channel, rows])
  useEffect(() => { if (term.current) term.current.options.fontSize = fontSize }, [fontSize])
  return <div className="kali-frame"><div ref={host} /></div>
})

const DOT = { done: 'bg-ok', running: 'bg-brand pulse', failed: 'bg-crit', interrupted: 'bg-high', pending: 'bg-faint' }

/** Terminal with one tab per channel (batch, target or tool) plus font size and copy. */
export default function ScanTerminal({ scanId, channels, stateOf, rows = 30, initial }) {
  const list = channels && channels.length ? channels : [{ id: 'main', label: 'Output' }]
  const [chan, setChan] = useState(initial || list[0].id)
  useEffect(() => { if (initial) setChan(initial) }, [initial])
  const [size, setSize] = useState(13)
  const [copied, setCopied] = useState(false)
  const ref = useRef(null)
  const current = list.find((c) => c.id === chan) ? chan : list[0].id

  async function copy() {
    const text = ref.current?.copyAll() || ''
    try { await navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1400) } catch {}
  }

  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap gap-1.5">
          {list.length > 1 && list.map((c) => (
            <button key={c.id} onClick={() => setChan(c.id)}
              className={`inline-flex items-center gap-2 rounded border px-2.5 py-1 text-xs ${current === c.id ? 'border-brand bg-brand/10 text-ink' : 'border-line text-mute hover:text-ink'}`}>
              {stateOf && <span className={`dot ${DOT[stateOf(c.id)] || 'bg-faint'}`} />}{c.label}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-1.5">
          <button className="btn-sub" onClick={() => setSize((s) => Math.max(10, s - 1))} aria-label="Smaller text">A−</button>
          <button className="btn-sub" onClick={() => setSize((s) => Math.min(22, s + 1))} aria-label="Larger text">A+</button>
          <button className="btn-sub" onClick={copy}>{copied ? 'Copied' : 'Copy output'}</button>
        </div>
      </div>
      <XTerm ref={ref} key={`${scanId}-${current}`} scanId={scanId} channel={current} fontSize={size} rows={rows} />
    </div>
  )
}
