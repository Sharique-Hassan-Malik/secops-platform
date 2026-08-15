const fmtTime = iso => {
  if (!iso) return ''
  const d = new Date(iso)
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

export default function AlertPanel({ alerts, onAcknowledge }) {
  const openCount = alerts.filter(a => a.status === 'open').length

  return (
    <div className="panel">
      <div className="panel-title">
        Alerts&nbsp;
        <span style={{ color: '#f85149' }}>{openCount} open</span>
      </div>
      {alerts.length === 0
        ? <div className="no-data">No alerts</div>
        : (
          <div className="alert-list">
            {alerts.map(a => (
              <div
                key={a.id}
                className={`alert-item ${a.severity} ${a.status !== 'open' ? 'acknowledged' : ''}`}
              >
                <div className="alert-header">
                  <span className="alert-rule">{a.rule_name}</span>
                  <span className={`sev-badge ${a.severity}`}>{a.severity}</span>
                </div>
                <div className="alert-desc">{a.description}</div>
                <div className="alert-meta">
                  <span className="alert-ip">{a.source_ip}</span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span className="alert-time">{fmtTime(a.created_at)}</span>
                    {a.status === 'open' && (
                      <button className="ack-btn" onClick={() => onAcknowledge(a.id)}>ACK</button>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )
      }
    </div>
  )
}
