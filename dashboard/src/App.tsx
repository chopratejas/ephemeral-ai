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

      <footer className="border-t border-border py-6 mt-8">
        <div className="max-w-7xl mx-auto px-6 flex items-center justify-between text-xs font-mono text-text-muted">
          <span>CodeScope / Ephemeral.ai</span>
          <span>Infrastructure destroyed after every scan</span>
        </div>
      </footer>
    </div>
  );
}
