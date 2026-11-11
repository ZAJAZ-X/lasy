import { Component, useEffect, useState } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { api } from './api'
import { Chrome } from './components/Layout'
import Dashboard from './pages/Dashboard'
import NewProject from './pages/NewProject'
import { Activity, EptMenu } from './pages/Activity'
import { NameserverPage, HostUpPage, SubdomainPage } from './pages/Quick'
import { NmapHome, NmapSession, NmapStage, NmapTablePage, NmapWebHandoff } from './pages/Nmap'
import { WebDashboard, ToolPage, RedirectTool, WebAllFindings, WebDiscovery } from './pages/Web'
import Settings from './pages/Settings'
import Setup from './pages/Setup'
import { Splash } from './components/Mascot'
import { UiContext, useUi } from './components/ui'

function readPrefs() {
  try { return { mascot: true, size: 'large', style: 'glass', ...JSON.parse(localStorage.getItem('lasy_ui') || '{}') } } catch { return { mascot: true, size: 'large', style: 'glass' } }
}

// Blocks the app until the results folder has been confirmed on first run. Shows the start screen while loading.
function RequireSetup({ children }) {
  const { mascot, setPrefs } = useUi()
  const [state, setState] = useState('loading')
  const [minDone, setMinDone] = useState(() => sessionStorage.getItem('lasy_splash') === '1')
  useEffect(() => {
    api.getSetup().then((s) => { if (s.ui) setPrefs({ mascot: s.ui.mascot, size: s.ui.size, style: s.ui.style || 'glass' }); setState(s.complete ? 'ok' : 'needsetup') }).catch(() => setState('ok'))
  }, []) // eslint-disable-line
  useEffect(() => {   // first load of a browser session: let the start screen be seen briefly
    if (minDone) return undefined
    const t = setTimeout(() => { sessionStorage.setItem('lasy_splash', '1'); setMinDone(true) }, 1100)
    return () => clearTimeout(t)
  }, [minDone])
  if (state === 'loading' || !minDone) return <Splash done={state !== 'loading'} mascot={mascot} />
  if (state === 'needsetup') return <Navigate to="/setup" replace />
  return children
}

class ErrorBoundary extends Component {
  state = { error: null }
  static getDerivedStateFromError(error) { return { error } }
  render() {
    if (!this.state.error) return this.props.children
    return (
      <div className="grid min-h-screen place-items-center px-5">
        <div className="card max-w-md p-8 text-center">
          <p className="text-ink">Something went wrong showing this page.</p>
          <p className="mt-2 text-sm text-mute">Your scans and results are safe. Reload the page, or go back to your projects.</p>
          <div className="mt-5 flex justify-center gap-2">
            <button className="btn-primary" onClick={() => window.location.reload()}>Reload</button>
            <a href="/" className="btn-ghost">Projects</a>
          </div>
          <p className="mt-4 break-words font-mono text-xs text-faint">{String(this.state.error?.message || this.state.error)}</p>
        </div>
      </div>
    )
  }
}

function NotFound() {
  return <div className="card p-8 text-center"><p className="text-ink">That page doesn’t exist.</p><a href="/" className="btn-primary mt-4">Back to projects</a></div>
}

export default function App() {
  const [prefs, setPrefsState] = useState(readPrefs)
  const setPrefs = (p) => setPrefsState((cur) => {
    const next = { ...cur, ...p }
    try { localStorage.setItem('lasy_ui', JSON.stringify(next)) } catch {}
    document.documentElement.dataset.size = next.size
    document.documentElement.dataset.style = next.style || 'glass'
    return next
  })
  return (
    <UiContext.Provider value={{ ...prefs, setPrefs }}><ErrorBoundary><Routes>
      <Route path="/setup" element={<Setup />} />
      <Route element={<RequireSetup><Chrome /></RequireSetup>}>
        <Route index element={<Dashboard />} />
        <Route path="new" element={<NewProject />} />
        <Route path="settings" element={<Settings />} />
        <Route path="p/:id" element={<Activity />} />
        <Route path="p/:id/ept" element={<EptMenu />} />
        <Route path="p/:id/nmap" element={<NmapHome />} />
        <Route path="p/:id/nmap/:sid" element={<NmapSession />} />
        <Route path="p/:id/nmap/:sid/stage/:scanId" element={<NmapStage />} />
        <Route path="p/:id/nmap/:sid/table" element={<NmapTablePage />} />
        <Route path="p/:id/nmap/:sid/web" element={<NmapWebHandoff />} />
        <Route path="p/:id/subdomain" element={<SubdomainPage />} />
        <Route path="p/:id/nameserver" element={<NameserverPage />} />
        <Route path="p/:id/hostup" element={<HostUpPage />} />
        <Route path="p/:id/webapp" element={<WebDashboard />} />
        <Route path="p/:id/webapp/tool/:scanId" element={<ToolPage />} />
        <Route path="p/:id/webapp/scan/:scanId" element={<RedirectTool />} />
        <Route path="p/:id/webapp/scan/:scanId/findings" element={<RedirectTool />} />
        <Route path="p/:id/webapp/findings" element={<WebAllFindings />} />
        <Route path="p/:id/webapp/discovery" element={<WebDiscovery />} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes></ErrorBoundary></UiContext.Provider>
  )
}
