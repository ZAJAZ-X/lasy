// Same-origin relative URLs: the backend serves this UI in production.
async function req(path, { method = 'GET', body } = {}) {
  let res
  try {
    res = await fetch(`/api${path}`, {
      method,
      headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    })
  } catch {
    throw new Error("Can't reach the lasy backend. Make sure it is running: type lasy in your Kali terminal.")
  }
  if (!res.ok) {
    let detail = res.statusText
    try { const j = await res.json(); detail = typeof j.detail === 'string' ? j.detail : JSON.stringify(j.detail) } catch {}
    throw new Error(detail)
  }
  return res.json()
}
const post = (p, b = {}) => req(p, { method: 'POST', body: b })

export const api = {
  health: () => req('/health'),
  healthNmap: () => req('/health/nmap'),
  getSetup: () => req('/setup'),
  saveSetup: (results_root) => post('/setup', { results_root }),
  getSettings: () => req('/settings'),
  putSettings: (values) => req('/settings', { method: 'PUT', body: { values } }),
  settingsSchema: () => req('/settings/schema'),
  previewSettings: (values) => post('/settings/preview', { values }),
  previewTargets: (text) => post('/targets/preview', { text }),

  listProjects: () => req('/projects'),
  createProject: (name) => post('/projects', { name }),
  getProject: (id) => req(`/projects/${id}`),
  projectSummary: (id) => req(`/projects/${id}/summary`),
  deleteProject: (id, confirm_name, delete_files) => post(`/projects/${id}/delete`, { confirm_name, delete_files }),

  getScan: (id, full = false) => req(`/scans/${id}${full ? '?full=1' : ''}`),
  listScans: (pid, kind) => req(`/projects/${pid}/scans${kind ? `?kind=${kind}` : ''}`),
  pauseScan: (id) => post(`/scans/${id}/pause`),
  cancelScan: (id) => post(`/scans/${id}/cancel`),
  scanFindings: (id) => req(`/scans/${id}/findings`),
  exportScanUrl: (id) => `/api/scans/${id}/export`,
  scanFindingsExportUrl: (id) => `/api/scans/${id}/findings/export`,

  runNameserver: (pid, targets) => post(`/projects/${pid}/nameserver`, { targets }),
  runHostup: (pid, targets) => post(`/projects/${pid}/hostup`, { targets }),
  runSubdomain: (pid, targets, tools) => post(`/projects/${pid}/subdomain`, { targets, tools }),

  nmap: {
    create: (pid, targets, cidr_discovery) => post(`/projects/${pid}/nmap/sessions`, { targets, cidr_discovery }),
    list: (pid) => req(`/projects/${pid}/nmap/sessions`),
    get: (sid) => req(`/nmap/sessions/${sid}`),
    select: (id, selected) => req(`/nmap/stages/${id}/select`, { method: 'PUT', body: { selected } }),
    runStage: (id, mode = 'fresh') => post(`/nmap/stages/${id}/run`, { mode }),
    runAll: (sid) => post(`/nmap/sessions/${sid}/run-all`),
    pause: (sid) => post(`/nmap/sessions/${sid}/pause`),
    table: (sid) => req(`/nmap/sessions/${sid}/table`),
    exportUrl: (sid) => `/api/nmap/sessions/${sid}/export`,
    webCandidates: (sid) => req(`/nmap/sessions/${sid}/web-candidates`),
  },
  web: {
    targets: (pid) => req(`/projects/${pid}/web/targets`),
    addTargets: (pid, body) => post(`/projects/${pid}/web/targets`, body),
    setScheme: (tid, scheme) => req(`/web/targets/${tid}`, { method: 'PATCH', body: { scheme } }),
    delTarget: (tid) => req(`/web/targets/${tid}`, { method: 'DELETE' }),
    dirconfig: (pid, profile) => req(`/projects/${pid}/web/dirconfig${profile ? `?profile=${profile}` : ''}`),
    saveDirconfig: (pid, cfg) => req(`/projects/${pid}/web/dirconfig`, { method: 'PUT', body: cfg }),
    tools: (pid) => req(`/projects/${pid}/web/tools`),
    run: (pid, tool) => post(`/projects/${pid}/web/run`, { tool }),
    runAll: (pid, tools) => post(`/projects/${pid}/web/run-all`, { tools }),
    savePlan: (pid, plan) => req(`/projects/${pid}/web/plan`, { method: 'PUT', body: plan }),
    history: (pid, tool) => req(`/projects/${pid}/web/tools/${tool}/history`),
    stop: (pid) => post(`/projects/${pid}/web/stop`),
    findings: (pid) => req(`/projects/${pid}/web/findings`),
    findingsExportUrl: (pid) => `/api/projects/${pid}/web/findings/export`,
    discovery: (pid) => req(`/projects/${pid}/web/discovery`),
  },
}

export function wsUrl(sid, channel = 'main') {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  return `${proto}://${location.host}/api/ws/scans/${sid}?channel=${encodeURIComponent(channel)}`
}
