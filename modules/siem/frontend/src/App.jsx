import { useEffect, useRef, useState } from 'react'
import AlertPanel   from './components/AlertPanel.jsx'
import EventStream  from './components/EventStream.jsx'
import Header       from './components/Header.jsx'
import SourceChart  from './components/SourceChart.jsx'
import StatsCards   from './components/StatsCards.jsx'
import TimelineChart from './components/TimelineChart.jsx'

export default function App() {
  const [events,      setEvents]      = useState([])
  const [alerts,      setAlerts]      = useState([])
  const [stats,       setStats]       = useState(null)
  const [wsConnected, setWsConnected] = useState(false)
  const newIds = useRef(new Set())
  const [, forceRender] = useState(0)

  const fetchStats = () =>
    fetch('/api/stats').then(r => r.json()).then(setStats).catch(() => {})

  useEffect(() => {
    fetch('/api/events?limit=100').then(r => r.json())
      .then(d => setEvents(d.events || [])).catch(() => {})
    fetch('/api/alerts?limit=50').then(r => r.json())
      .then(d => setAlerts(Array.isArray(d) ? d : [])).catch(() => {})
    fetchStats()
  }, [])

  useEffect(() => {
    const id = setInterval(fetchStats, 30_000)
    return () => clearInterval(id)
  }, [])

  useEffect(() => {
    const ws = new WebSocket(`ws://${window.location.host}/ws`)
    ws.onopen  = () => setWsConnected(true)
    ws.onclose = () => setWsConnected(false)
    ws.onerror = () => setWsConnected(false)

    ws.onmessage = e => {
      const msg = JSON.parse(e.data)
      if (msg.type === 'event') {
        setEvents(prev => [msg.data, ...prev].slice(0, 200))
        newIds.current.add(msg.data.id)
        forceRender(n => n + 1)
        setTimeout(() => {
          newIds.current.delete(msg.data.id)
          forceRender(n => n + 1)
        }, 2000)
      } else if (msg.type === 'alert') {
        setAlerts(prev => [msg.data, ...prev].slice(0, 100))
      }
    }
    return () => ws.close()
  }, [])

  const acknowledgeAlert = async id => {
    await fetch(`/api/alerts/${id}`, {
      method:  'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ status: 'acknowledged' }),
    })
    setAlerts(prev => prev.map(a => a.id === id ? { ...a, status: 'acknowledged' } : a))
  }

  return (
    <div className="app">
      <Header wsConnected={wsConnected} />
      <main className="dashboard">
        <StatsCards stats={stats} />
        <div className="charts-row">
          <TimelineChart data={stats?.timeline || []} />
          <SourceChart   data={stats?.by_source || {}} />
        </div>
        <div className="lower-row">
          <AlertPanel  alerts={alerts} onAcknowledge={acknowledgeAlert} />
          <EventStream events={events} newIds={newIds.current} />
        </div>
      </main>
    </div>
  )
}
