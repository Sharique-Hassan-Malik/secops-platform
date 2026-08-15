const fmtTime = iso => {
  if (!iso) return ''
  const d = new Date(iso)
  return [d.getHours(), d.getMinutes(), d.getSeconds()]
    .map(n => String(n).padStart(2, '0'))
    .join(':')
}

const statusColor = code => {
  if (!code) return '#8b949e'
  if (code >= 500) return '#f85149'
  if (code >= 400) return '#e3b341'
  return '#3fb950'
}

export default function EventStream({ events, newIds }) {
  return (
    <div className="panel">
      <div className="panel-title">Event Stream</div>
      {events.length === 0
        ? <div className="no-data">Waiting for events…</div>
        : (
          <div className="event-table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Source</th>
                  <th>IP</th>
                  <th>Method</th>
                  <th>Path</th>
                  <th>Status</th>
                  <th>Sev</th>
                </tr>
              </thead>
              <tbody>
                {events.map(e => (
                  <tr key={e.id} className={newIds.has(e.id) ? 'new-event' : ''}>
                    <td className="mono">{fmtTime(e.timestamp)}</td>
                    <td>{e.source_type}</td>
                    <td className="mono" style={{ color: '#58a6ff' }}>{e.source_ip}</td>
                    <td>{e.method || '—'}</td>
                    <td className="path" title={e.path}>{e.path || '—'}</td>
                    <td className="mono" style={{ color: statusColor(e.status_code) }}>
                      {e.status_code ?? '—'}
                    </td>
                    <td>
                      <span className={`dot ${e.severity}`} />
                      {e.severity}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      }
    </div>
  )
}
