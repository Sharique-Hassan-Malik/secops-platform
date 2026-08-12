import {
  Area, AreaChart, CartesianGrid, ResponsiveContainer,
  Tooltip, XAxis, YAxis,
} from 'recharts'

const fmtHour = iso => {
  if (!iso) return ''
  const d = new Date(iso)
  return `${String(d.getHours()).padStart(2, '0')}:00`
}

export default function TimelineChart({ data }) {
  return (
    <div className="panel">
      <div className="panel-title">Events — Last 24 Hours</div>
      {data.length === 0
        ? <div className="no-data">No data yet</div>
        : (
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: -20 }}>
              <defs>
                <linearGradient id="grad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#58a6ff" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#58a6ff" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#30363d" />
              <XAxis
                dataKey="hour"
                tickFormatter={fmtHour}
                tick={{ fill: '#8b949e', fontSize: 10 }}
              />
              <YAxis tick={{ fill: '#8b949e', fontSize: 10 }} />
              <Tooltip
                contentStyle={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 6 }}
                labelFormatter={fmtHour}
                itemStyle={{ color: '#e6edf3' }}
              />
              <Area
                type="monotone"
                dataKey="count"
                stroke="#58a6ff"
                fill="url(#grad)"
                strokeWidth={2}
                dot={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        )
      }
    </div>
  )
}
