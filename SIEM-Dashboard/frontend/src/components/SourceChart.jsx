import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

const COLORS = {
  apache:   '#58a6ff',
  nginx:    '#3fb950',
  syslog:   '#e3b341',
  firewall: '#f85149',
}

export default function SourceChart({ data }) {
  const entries = Object.entries(data).map(([name, count]) => ({ name, count }))
  return (
    <div className="panel">
      <div className="panel-title">Events by Source</div>
      {entries.length === 0
        ? <div className="no-data">No data yet</div>
        : (
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={entries} margin={{ top: 4, right: 8, bottom: 0, left: -20 }}>
              <XAxis dataKey="name" tick={{ fill: '#8b949e', fontSize: 11 }} />
              <YAxis tick={{ fill: '#8b949e', fontSize: 10 }} />
              <Tooltip
                contentStyle={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 6 }}
                itemStyle={{ color: '#e6edf3' }}
              />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {entries.map(entry => (
                  <Cell key={entry.name} fill={COLORS[entry.name] || '#8b949e'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )
      }
    </div>
  )
}
