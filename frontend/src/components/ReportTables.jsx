// Tables rendered like the reference report tables (and the Excel export).
const dash = (v) => (v === null || v === undefined || v === '' ? '-' : v)

export function NmapTable({ rows }) {
  const lines = []
  let n = 0
  rows.forEach((h, hi) => {
    const ports = h.ports.length ? h.ports : [null]
    const firstBand = n % 2 === 0
    ports.forEach((p, pi) => { lines.push({ h, hi, p, pi, span: ports.length, band: n % 2 === 0, firstBand }); n++ })
  })
  return (
    <div className="report-wrap">
      <table className="report">
        <thead><tr>
          <th className="c" style={{ width: 70 }}>Sl No.</th><th>Host/IP Address</th><th>Open Port</th>
          <th>Service Detection</th><th>Server Type/Version</th>
        </tr></thead>
        <tbody>
          {lines.map((l, i) => (
            <tr key={i}>
              {l.pi === 0 && <>
                <td rowSpan={l.span} className={`c ${l.firstBand ? 'band' : ''}`}><b>{l.hi + 1}</b></td>
                <td rowSpan={l.span} className={l.firstBand ? 'band' : ''}>{l.h.host}</td>
              </>}
              <td className={l.band ? 'band' : ''}>{dash(l.p?.port)}</td>
              <td className={l.band ? 'band' : ''}>{dash(l.p?.service)}</td>
              <td className={l.band ? 'band' : ''}>{dash(l.p?.version)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function SubdomainTable({ rows }) {
  return (
    <div className="report-wrap">
      <table className="report">
        <thead><tr><th className="c" style={{ width: 70 }}>Sl. No</th><th>Domain</th><th>IP Address</th><th>Accessibility</th></tr></thead>
        <tbody>
          {rows.map((r, i) => {
            const b = i % 2 === 0 ? 'band' : ''
            return (
              <tr key={r.domain}>
                <td className={`c ${b}`}><b>{i + 1}</b></td><td className={b}>{r.domain}</td><td className={b}>{dash(r.ip)}</td>
                <td className={b}>
                  {r.accessible === 'yes' ? <><span className="yes">Yes</span>{r.redirect ? `, redirects to ${r.redirect}` : ''}</>
                    : r.accessible === 'no' ? 'No' : '-'}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

export function NameserverTable({ rows }) {
  const multi = new Set(rows.map((r) => r.domain)).size > 1
  return (
    <div className="report-wrap" style={{ maxWidth: multi ? 760 : 520 }}>
      <table className="report">
        <thead><tr><th className="c" style={{ width: 70 }}>Sl. No</th>{multi && <th>Domain</th>}<th>Nameserver</th></tr></thead>
        <tbody>
          {rows.map((r, i) => {
            const b = i % 2 === 0 ? 'band' : ''
            return <tr key={i}><td className={`c ${b}`}><b>{i + 1}</b></td>{multi && <td className={b}>{r.domain}</td>}<td className={b}>{dash(r.nameserver)}</td></tr>
          })}
        </tbody>
      </table>
    </div>
  )
}

export function HostTable({ rows }) {
  return (
    <div className="report-wrap" style={{ maxWidth: 620 }}>
      <table className="report">
        <thead><tr><th className="c" style={{ width: 70 }}>Sl. No</th><th>Host/IP Address</th><th style={{ width: 120 }}>Status</th></tr></thead>
        <tbody>
          {rows.map((r, i) => {
            const b = i % 2 === 0 ? 'band' : ''
            return <tr key={i}><td className={`c ${b}`}><b>{i + 1}</b></td><td className={b}>{dash(r.host)}</td><td className={b}>{dash(r.status)}</td></tr>
          })}
        </tbody>
      </table>
    </div>
  )
}
