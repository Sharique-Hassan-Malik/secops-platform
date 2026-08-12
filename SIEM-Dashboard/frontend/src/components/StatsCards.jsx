export default function StatsCards({ stats }) {
  const cards = [
    { label: 'Total Events',    value: stats?.total_events    ?? '—', cls: 'accent' },
    { label: 'Last 24 Hours',   value: stats?.events_24h      ?? '—', cls: '' },
    { label: 'Open Alerts',     value: stats?.open_alerts     ?? '—', cls: 'high' },
    { label: 'Critical Alerts', value: stats?.critical_alerts ?? '—', cls: 'critical' },
  ]
  return (
    <div className="stats-row">
      {cards.map(c => (
        <div key={c.label} className="stat-card">
          <div className="stat-label">{c.label}</div>
          <div className={`stat-value ${c.cls}`}>
            {typeof c.value === 'number' ? c.value.toLocaleString() : c.value}
          </div>
        </div>
      ))}
    </div>
  )
}
