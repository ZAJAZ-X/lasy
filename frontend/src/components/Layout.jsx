import { useEffect, useState } from 'react'
import { Link, Outlet, useLocation, useMatch, useNavigate } from 'react-router-dom'
import { Icon } from './Icon'
import { SlothFace } from './Mascot'
import { useProject, useUi } from './ui'

function ConnectionBanner() {
  const [down, setDown] = useState(false)
  useEffect(() => {
    let fails = 0
    const t = setInterval(async () => {
      try { const r = await fetch('/api/health'); if (!r.ok) throw new Error(); fails = 0; setDown(false) } catch { fails += 1; if (fails >= 2) setDown(true) }
    }, 4000)
    return () => clearInterval(t)
  }, [])
  if (!down) return null
  return (
    <div role="alert" className="border-b border-crit/40 bg-crit/10 px-5 py-2 text-center text-sm text-ink">
      Lost connection to lasy. Start it again by typing <span className="font-mono">lasy</span> in Kali. Your results are saved, and interrupted scans can be resumed.
    </div>
  )
}

/** The lasy wordmark. The face follows the "Show the lasy mascot" setting. */
export function Brand({ link = true, tag = true, compact = false }) {
  const { mascot } = useUi()
  const Wrap = link ? Link : 'div'
  return (
    <Wrap {...(link ? { to: '/', 'aria-label': 'lasy home' } : {})} className="flex items-center gap-2.5">
      <span className="grid h-7 w-7 flex-none place-items-center rounded-lg bg-brand/15 font-mono text-sm font-semibold text-brand">{'>'}</span>
      {!compact && <span className="font-mono text-[16.33px] font-semibold tracking-tight text-ink">lasy</span>}
      {!compact && mascot && <SlothFace style={{ width: '1.9rem', height: '1.9rem', flex: 'none' }} />}
      {!compact && tag && <span className="hidden text-xs text-faint sm:inline">recon and scanning console</span>}
    </Wrap>
  )
}

function NavItem({ to, icon, label, active, rail, onClick }) {
  return (
    <Link to={to} onClick={onClick} data-active={active} title={rail ? label : undefined} aria-current={active ? 'page' : undefined}
      className={`nav-item ${rail ? 'justify-center !px-0' : ''}`}>
      <Icon name={icon} size={18} className="flex-none" />
      {!rail && <span className="truncate">{label}</span>}
    </Link>
  )
}

function NavGroup({ label, rail, children }) {
  return (
    <div className="mt-5">
      {!rail ? <p className="mb-1.5 px-3 text-[11px] font-medium uppercase tracking-[0.09em] text-faint">{label}</p> : <div className="mx-3 mb-2 border-t border-line" />}
      <div className="space-y-0.5">{children}</div>
    </div>
  )
}

function Sidebar({ rail, setRail, open, onClose }) {
  const { pathname } = useLocation()
  const m = useMatch({ path: '/p/:id', end: false })
  const id = m?.params.id
  const project = useProject(id)
  const p = id ? `/p/${id}` : ''
  const is = (...prefixes) => prefixes.some((x) => pathname === x || pathname.startsWith(x + '/'))
  const webMain = id && is(`${p}/webapp`) && !is(`${p}/webapp/findings`, `${p}/webapp/discovery`)
  const item = (to, icon, label, active) => <NavItem key={to} to={to} icon={icon} label={label} active={active} rail={rail} onClick={onClose} />

  return (
    <>
      {open && <div className="fixed inset-0 z-30 bg-black/50 nav:hidden" onClick={onClose} aria-hidden="true" />}
      <aside aria-label="Main navigation"
        className={`sidebar fixed inset-y-0 left-0 z-40 flex flex-col px-3 py-4 transition-transform duration-200 nav:translate-x-0 ${open ? 'translate-x-0' : '-translate-x-full'} ${rail ? 'w-[15rem] nav:w-[4.75rem]' : 'w-[15rem] nav:w-[13.5rem]'}`}>
        <div className={`mb-2 px-1.5 ${rail ? 'nav:flex nav:justify-center' : ''}`}><Brand tag={false} compact={rail} /></div>
        <nav className="min-h-0 flex-1 overflow-y-auto pb-3">
          <NavGroup label="Workspace" rail={rail}>
            {item('/', 'projects', 'Projects', pathname === '/' || pathname === '/new')}
            {item('/settings', 'sliders', 'Settings', is('/settings'))}
          </NavGroup>
          {id && (
            <>
              <div className={`mt-6 ${rail ? 'mx-1 text-center' : 'px-3'}`}>
                {!rail && <p className="text-[11px] font-medium uppercase tracking-[0.09em] text-faint">Project</p>}
                <p className={`mt-0.5 truncate font-medium text-ink ${rail ? 'text-[10px]' : 'text-[15px]'}`} title={project?.name}>{rail ? (project?.name || '·').slice(0, 5) : (project?.name || '…')}</p>
              </div>
              <div className="mt-2 space-y-0.5">{item(p, 'overview', 'Overview', pathname === p || pathname === `${p}/ept`)}</div>
              <NavGroup label="External pentest" rail={rail}>
                {item(`${p}/nmap`, 'scan', 'Nmap scans', is(`${p}/nmap`))}
                {item(`${p}/subdomain`, 'network', 'Subdomains', is(`${p}/subdomain`))}
                {item(`${p}/nameserver`, 'server', 'Nameserver', is(`${p}/nameserver`))}
                {item(`${p}/hostup`, 'pulse', 'Host up / down', is(`${p}/hostup`))}
              </NavGroup>
              <NavGroup label="Web app pentest" rail={rail}>
                {item(`${p}/webapp`, 'shield', 'Targets and tools', webMain)}
                {item(`${p}/webapp/findings`, 'list', 'All findings', is(`${p}/webapp/findings`))}
                {item(`${p}/webapp/discovery`, 'search', 'Content discovery', is(`${p}/webapp/discovery`))}
              </NavGroup>
            </>
          )}
        </nav>
        <button onClick={() => setRail(!rail)} className="nav-item hidden nav:flex" aria-label={rail ? 'Expand sidebar' : 'Collapse sidebar'} title={rail ? 'Expand sidebar' : 'Collapse sidebar'}>
          <Icon name={rail ? 'expand' : 'collapse'} size={18} className="flex-none" />{!rail && <span>Collapse</span>}
        </button>
      </aside>
    </>
  )
}

export function Chrome() {
  const [open, setOpen] = useState(false)
  const [rail, setRailState] = useState(() => localStorage.getItem('lasy_rail') === '1')
  const setRail = (v) => { setRailState(v); try { localStorage.setItem('lasy_rail', v ? '1' : '0') } catch { /* ignore */ } }
  const { pathname } = useLocation()
  useEffect(() => { setOpen(false) }, [pathname])
  return (
    <div className="min-h-screen">
      <Sidebar rail={rail} setRail={setRail} open={open} onClose={() => setOpen(false)} />
      <div className={`transition-[padding] duration-200 ${rail ? 'nav:pl-[4.75rem]' : 'nav:pl-[13.5rem]'}`}>
        <div className="sidebar sticky top-0 z-20 flex items-center justify-between border-b border-line px-4 py-2.5 nav:hidden" style={{ borderRight: 0 }}>
          <Brand tag={false} />
          <button className="btn-sub !px-2.5" onClick={() => setOpen(true)} aria-label="Open menu"><Icon name="menu" size={18} /></button>
        </div>
        <ConnectionBanner />
        <main className="mx-auto max-w-[76rem] px-5 py-7 nav:px-8 nav:py-9"><Outlet /></main>
      </div>
    </div>
  )
}

export function Crumbs({ items }) {
  const nav = useNavigate()
  return (
    <div className="mb-5 flex flex-wrap items-center gap-2.5">
      <button onClick={() => nav(-1)} className="btn-sub !px-2" aria-label="Go back"><Icon name="back" size={15} /></button>
      <nav aria-label="Breadcrumb" className="flex flex-wrap items-center gap-1.5 text-[13px] text-mute">
        {items.map((it, i) => (
          <span key={i} className="flex items-center gap-1.5">
            {i > 0 && <span className="text-faint">/</span>}
            {it.to ? <Link to={it.to} className="hover:text-ink">{it.label}</Link> : <span className="text-ink">{it.label}</span>}
          </span>
        ))}
      </nav>
    </div>
  )
}

export function PageTitle({ title, sub, right }) {
  return (
    <div className="mb-7 flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        <h1 className="text-[1.65rem] font-semibold leading-tight tracking-tight text-ink">{title}</h1>
        {sub && <p className="mt-1.5 max-w-3xl text-sm leading-relaxed text-mute">{sub}</p>}
      </div>
      {right && <div className="flex flex-wrap items-center gap-2">{right}</div>}
    </div>
  )
}
