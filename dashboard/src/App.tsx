import Header from './components/Header';
import AuditForm from './components/AuditForm';
import LiveAudit from './components/LiveAudit';
import Report from './components/Report';
import AuditHistory from './components/AuditHistory';
import { useAudit } from './hooks/useAudit';

export default function App() {
  const {
    view,
    repoUrl,
    loading,
    error,
    layers,
    result,
    elapsed,
    logs,
    stats,
    history,
    submitAudit,
    reset,
    viewReport,
  } = useAudit();

  return (
    <div className="min-h-screen bg-bg">
      <Header stats={stats} onLogoClick={reset} />

      <main>
        {view === 'home' && (
          <>
            <AuditForm
              onSubmit={submitAudit}
              loading={loading}
              error={error}
              stats={stats}
            />
            <AuditHistory history={history} onSelect={viewReport} />
          </>
        )}

        {view === 'scanning' && (
          <LiveAudit repoUrl={repoUrl} layers={layers} elapsed={elapsed} logs={logs} />
        )}

        {view === 'report' && result && (
          <Report result={result} onNewAudit={reset} />
        )}
      </main>

      <footer style={{ padding: '48px 0', textAlign: 'center' }}>
        <p className="font-mono" style={{ fontSize: '13px', color: '#52525b' }}>
          CodeScope by Ephemeral.ai
        </p>
        <p className="font-mono" style={{ fontSize: '12px', color: '#52525b', marginTop: '4px' }}>
          Your code is destroyed after every scan.
        </p>
      </footer>
    </div>
  );
}
