export default function Header({ wsConnected }) {
  return (
    <header className="header">
      <div className="header-title">
        <span>⬡</span>SIEM Dashboard
      </div>
      <div className="ws-badge">
        <div className={`ws-dot ${wsConnected ? 'live' : ''}`} />
        {wsConnected ? 'Live' : 'Connecting…'}
      </div>
    </header>
  )
}
