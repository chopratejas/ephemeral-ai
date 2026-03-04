import type { AuditHistoryEntry } from '../types';

interface AuditHistoryProps {
  history: AuditHistoryEntry[];
  onSelect: (entry: AuditHistoryEntry) => void;
}

function timeAgo(dateStr: string): string {
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const diff = now - then;

  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return `${seconds}s ago`;

  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;

  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function riskColor(score: number): string {
  if (score >= 70) return '#ef4444';
  if (score >= 50) return '#f59e0b';
  if (score >= 30) return '#eab308';
  if (score >= 15) return '#3b82f6';
  return '#22c55e';
}

export default function AuditHistory({ history, onSelect }: AuditHistoryProps) {
  if (history.length === 0) return null;

  const hasLanguage = history.some((e) => !!e.language);
  const hasFramework = history.some((e) => !!e.framework);

  // Build grid template based on available columns
  const baseCols = '1fr 60px 80px';
  const langCol = hasLanguage ? ' 80px' : '';
  const fwCol = hasFramework ? ' 90px' : '';
  const endCols = ' 70px 60px 70px';
  const gridCols = baseCols + langCol + fwCol + endCols;

  return (
    <div className="max-w-3xl mx-auto px-6 pb-20">
      <div
        className="overflow-hidden"
        style={{
          border: '1px solid #1e1e2e',
          borderRadius: '12px',
          background: '#12121a',
        }}
      >
        <div style={{ padding: '12px 16px', borderBottom: '1px solid #1e1e2e' }}>
          <span
            className="font-semibold uppercase tracking-wider"
            style={{ fontSize: '11px', color: '#71717a', letterSpacing: '0.08em' }}
          >
            Recent Audits
          </span>
        </div>

        {/* Table header */}
        <div
          className="hidden sm:grid gap-2 font-mono uppercase tracking-wider"
          style={{
            gridTemplateColumns: gridCols,
            padding: '8px 16px',
            borderBottom: '1px solid #1e1e2e',
            fontSize: '10px',
            color: '#52525b',
            letterSpacing: '0.06em',
          }}
        >
          <span>Repository</span>
          <span style={{ textAlign: 'right' }}>Risk</span>
          <span style={{ textAlign: 'right' }}>Findings</span>
          {hasLanguage && <span style={{ textAlign: 'right' }}>Lang</span>}
          {hasFramework && <span style={{ textAlign: 'right' }}>Framework</span>}
          <span style={{ textAlign: 'right' }}>Duration</span>
          <span style={{ textAlign: 'right' }}>Cost</span>
          <span style={{ textAlign: 'right' }}>When</span>
        </div>

        {/* Rows */}
        {history.map((entry, idx) => (
          <button
            key={entry.task_id}
            onClick={() => onSelect(entry)}
            className="w-full text-left transition-colors hover:bg-surface-hover"
            style={{
              borderBottom: idx < history.length - 1 ? '1px solid #1e1e2e' : 'none',
            }}
          >
            {/* Desktop row */}
            <div
              className="hidden sm:grid gap-2 items-center"
              style={{ gridTemplateColumns: gridCols, padding: '10px 16px' }}
            >
              <span className="text-sm font-mono truncate" style={{ color: '#e4e4e7' }}>
                {entry.repo_name}
              </span>
              <span
                className="text-xs font-mono font-semibold"
                style={{ textAlign: 'right', color: riskColor(entry.risk_score) }}
              >
                {entry.risk_score}
              </span>
              <span className="text-xs font-mono" style={{ textAlign: 'right', color: '#71717a' }}>
                {entry.total_findings}
              </span>
              {hasLanguage && (
                <span className="text-xs font-mono truncate" style={{ textAlign: 'right', color: '#52525b' }}>
                  {entry.language || '--'}
                </span>
              )}
              {hasFramework && (
                <span className="text-xs font-mono truncate" style={{ textAlign: 'right', color: '#52525b' }}>
                  {entry.framework || '--'}
                </span>
              )}
              <span className="text-xs font-mono" style={{ textAlign: 'right', color: '#52525b' }}>
                {entry.duration_seconds.toFixed(1)}s
              </span>
              <span className="text-xs font-mono" style={{ textAlign: 'right', color: '#22c55e' }}>
                ${entry.cost_usd.toFixed(3)}
              </span>
              <span className="text-xs font-mono" style={{ textAlign: 'right', color: '#52525b' }}>
                {timeAgo(entry.completed_at)}
              </span>
            </div>
            {/* Mobile row */}
            <div className="sm:hidden" style={{ padding: '12px 16px' }}>
              <div className="flex items-center justify-between mb-1">
                <span className="text-sm font-mono truncate" style={{ color: '#e4e4e7' }}>{entry.repo_name}</span>
                <span
                  className="text-xs font-mono font-semibold"
                  style={{ color: riskColor(entry.risk_score) }}
                >
                  {entry.risk_score}
                </span>
              </div>
              <div className="flex items-center gap-3 text-xs font-mono flex-wrap" style={{ color: '#52525b' }}>
                <span>{entry.total_findings} findings</span>
                {entry.language && <span>{entry.language}</span>}
                {entry.framework && <span>{entry.framework}</span>}
                <span>{entry.duration_seconds.toFixed(1)}s</span>
                <span style={{ color: '#22c55e' }}>${entry.cost_usd.toFixed(3)}</span>
                <span>{timeAgo(entry.completed_at)}</span>
              </div>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}
