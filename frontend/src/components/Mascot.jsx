import { useEffect, useId, useState } from 'react'

/** Lasy the sloth. One character, drawn in the app's teal. Purely decorative (aria-hidden). */
export function Sloth({ sleep = false, branch = false, className = '', style }) {
  const id = useId().replace(/:/g, '')
  const eyes = sleep
    ? <path d="M47.6 50.5q4.4 3.4 8.8 0M63.6 50.5q4.4 3.4 8.8 0" stroke="#D7F6F0" strokeWidth="1.7" fill="none" strokeLinecap="round" />
    : <g className="sloth-eyes"><circle cx="52" cy="50" r="2.1" fill="#D7F6F0" /><circle cx="68" cy="50" r="2.1" fill="#D7F6F0" />
      <path d="M49.9 50a2.1 2.1 0 0 1 4.2 0z" fill="#0E3A35" /><path d="M65.9 50a2.1 2.1 0 0 1 4.2 0z" fill="#0E3A35" /></g>
  const hand = (x) => (
    <g key={x}><ellipse cx={x} cy="14" rx="6.2" ry="4.8" fill="#2A8A7E" />
      <path d={`M${x - 3.6} 17.6v4.4M${x} 18.6v4.8M${x + 3.6} 17.6v4.4`} stroke="#0E3A35" strokeWidth="1.8" strokeLinecap="round" /></g>
  )
  return (
    <svg viewBox="0 0 120 112" className={className} style={style} aria-hidden="true" focusable="false">
      <defs>
        <radialGradient id={`g${id}`}><stop offset="0" stopColor="#37B6A6" stopOpacity=".2" /><stop offset="1" stopColor="#37B6A6" stopOpacity="0" /></radialGradient>
        <linearGradient id={`f${id}`} x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#46C9B6" /><stop offset="1" stopColor="#2A8A7E" /></linearGradient>
        <linearGradient id={`h${id}`} x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#5BD8C5" /><stop offset="1" stopColor="#37B6A6" /></linearGradient>
      </defs>
      {branch && <rect x="2" y="10" width="116" height="8" rx="4" fill="#273040" />}
      <g className="sloth-sway">
        <circle cx="60" cy="62" r="58" fill={`url(#g${id})`} />
        <path d="M46 58C30 52 24 34 24 15" stroke="#2A8A7E" strokeWidth="7" fill="none" strokeLinecap="round" />
        <path d="M74 58C90 52 96 34 96 15" stroke="#2A8A7E" strokeWidth="7" fill="none" strokeLinecap="round" />
        {hand(24)}{hand(96)}
        <ellipse cx="60" cy="74" rx="24" ry="28" fill={`url(#f${id})`} stroke="#1E6F66" strokeWidth="1.2" />
        <ellipse cx="60" cy="82" rx="13" ry="16" fill="#BFEFE7" opacity=".16" />
        <ellipse cx="47" cy="99" rx="7.5" ry="6" fill="#2A8A7E" stroke="#1E6F66" strokeWidth="1" /><ellipse cx="73" cy="99" rx="7.5" ry="6" fill="#2A8A7E" stroke="#1E6F66" strokeWidth="1" />
        <ellipse cx="60" cy="48" rx="25" ry="19.5" fill={`url(#h${id})`} stroke="#1E6F66" strokeWidth="1.2" />
        <path d="M53 30.5q3.2-5 7-.8q3.8-4.6 7 .8" stroke="#1E6F66" strokeWidth="1.5" fill="none" strokeLinecap="round" />
        <ellipse cx="60" cy="50" rx="18.5" ry="13.5" fill="#D7F6F0" />
        <ellipse cx="52" cy="50" rx="6.4" ry="4.4" transform="rotate(-18 52 50)" fill="#0E3A35" /><ellipse cx="68" cy="50" rx="6.4" ry="4.4" transform="rotate(18 68 50)" fill="#0E3A35" />
        {eyes}
        <ellipse cx="60" cy="55.5" rx="2.7" ry="1.9" fill="#0E3A35" />
        <path d="M54.8 58q5.2 4.2 10.4 0" stroke="#0E3A35" strokeWidth="1.4" fill="none" strokeLinecap="round" />
        {sleep && <g stroke="#37B6A6" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round"><path d="M88 30h8l-8 9h8" /><path d="M101 16h5.5l-5.5 6.5h5.5" opacity=".7" /></g>}
      </g>
    </svg>
  )
}

/** Just the face, for the header wordmark. Drawn separately so it stays clear at about 30 px. */
export function SlothFace({ className = '', style }) {
  const id = useId().replace(/:/g, '')
  return (
    <svg viewBox="0 0 32 32" className={className} style={style} aria-hidden="true" focusable="false">
      <defs><linearGradient id={`h${id}`} x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#5BD8C5" /><stop offset="1" stopColor="#37B6A6" /></linearGradient></defs>
      <ellipse cx="16" cy="17" rx="14" ry="12" fill={`url(#h${id})`} stroke="#1E6F66" strokeWidth=".9" />
      <path d="M11 6.6q2.4-3.2 5-.6q2.6-3 5 .6" stroke="#1E6F66" strokeWidth="1.2" fill="none" strokeLinecap="round" />
      <ellipse cx="16" cy="17.6" rx="10.4" ry="8.2" fill="#D7F6F0" />
      <ellipse cx="11.4" cy="17" rx="3.7" ry="2.6" transform="rotate(-18 11.4 17)" fill="#0E3A35" />
      <ellipse cx="20.6" cy="17" rx="3.7" ry="2.6" transform="rotate(18 20.6 17)" fill="#0E3A35" />
      <circle cx="11.7" cy="17" r="1.25" fill="#D7F6F0" /><circle cx="20.3" cy="17" r="1.25" fill="#D7F6F0" />
      <path d="M10.45 17a1.25 1.25 0 0 1 2.5 0z" fill="#0E3A35" /><path d="M19.05 17a1.25 1.25 0 0 1 2.5 0z" fill="#0E3A35" />
      <ellipse cx="16" cy="20.4" rx="1.7" ry="1.15" fill="#0E3A35" />
      <path d="M13.4 22.5q2.6 2.2 5.2 0" stroke="#0E3A35" strokeWidth="1.1" fill="none" strokeLinecap="round" />
    </svg>
  )
}

/** Small scene for empty and waiting cards: the sloth hanging from a short branch. */
export function SlothScene({ mood = 'wait' }) {
  return (
    <div className="mb-3 flex justify-center" aria-hidden="true">
      <Sloth sleep={mood === 'sleep'} branch style={{ width: '6.5rem', height: 'auto' }} />
    </div>
  )
}

const LINES = ['Doing the boring parts so you don’t have to.', 'Warming up the scanners…', 'Teaching the sloth to type…']

/** Start screen: the sloth hangs from the loading bar and slowly inches along it. */
export function Splash({ done, mascot = true }) {
  const [p, setP] = useState(6)
  const [line, setLine] = useState(0)
  useEffect(() => {
    const t = setInterval(() => setP((v) => (v < 88 ? v + (90 - v) * 0.07 : v)), 120)
    const l = setInterval(() => setLine((n) => (n + 1) % LINES.length), 1700)
    return () => { clearInterval(t); clearInterval(l) }
  }, [])
  useEffect(() => { if (done) setP(100) }, [done])
  return (
    <div className="grid min-h-screen place-items-center bg-bg px-6">
      <div className="w-full max-w-[34rem] text-center">
        <div className="relative mx-auto" style={{ height: mascot ? '7.4rem' : '1.4rem' }}>
          <div className="absolute inset-x-0 top-[1.1rem] h-2.5 overflow-hidden rounded-full bg-line">
            <div className="h-full rounded-full transition-[width] duration-500 ease-out" style={{ width: `${p}%`, background: 'linear-gradient(90deg,#2A8A7E,#3FD0BC)' }} />
          </div>
          {mascot && (
            <div className="absolute top-[0.55rem] transition-[left] duration-500 ease-out" style={{ left: `clamp(0rem, calc(${p}% - 3.5rem), calc(100% - 7rem))`, width: '7rem' }}>
              <Sloth style={{ width: '7rem', height: 'auto' }} />
            </div>
          )}
        </div>
        <p className="mt-3 text-base text-ink">{mascot ? 'Waking up lasy…' : 'Starting lasy…'}</p>
        {mascot && <p className="mt-1 h-5 text-sm text-mute">{LINES[line]}</p>}
      </div>
    </div>
  )
}
