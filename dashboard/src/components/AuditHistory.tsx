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
  if (score >= 70) return 'text-accent-red';
  if (score >= 50) return 'text-accent-orange';
  if (score >= 30) return 'text-yellow-400';
  if (score >= 15) return 'text-accent-blue';
  return 'text-accent-green';
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
    <div className="max-w-5xl mx-auto px-6 pb-20">
      <div className="border border-border rounded-lg bg-surface overflow-hidden">
        <div className="px-4 py-3 border-b border-border">
          <span className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
            Global Audit Feed
          </span>
        </div>

        {/* Table header */}
        <div
          className="hidden sm:grid gap-2 px-4 py-2 border-b border-border text-xs font-mono text-text-muted uppercase tracking-wider"
          style={{ gridTemplateColumns: gridCols }}
        >
          <span>Repository</span>
          <span className="text-right">Risk</span>
          <span className="text-right">Findings</span>
          {hasLanguage && <span className="text-right">Lang</span>}
          {hasFramework && <span className="text-right">Framework</span>}
          <span className="text-right">Duration</span>
          <span className="text-right">Cost</span>
          <span className="text-right">When</span>
        </div>

        {/* Rows */}
        {history.map((entry, idx) => (
          <button
            key={entry.task_id}
            onClick={() => onSelect(entry)}
            className={`w-full text-left hover:bg-surface-hover transition-colors ${
              idx < history.length - 1 ? 'border-b border-border' : ''
            }`}
          >
            {/* Desktop row */}
            <div
              className="hidden sm:grid gap-2 items-center px-4 py-2.5"
              style={{ gridTemplateColumns: gridCols }}
            >
              <span className="text-sm font-mono text-text-primary truncate">
                {entry.repo_name}
              </span>
              <span className={`text-xs font-mono text-right font-semibold ${riskColor(entry.risk_score)}`}>
                {entry.risk_score}
              </span>
              <span className="text-xs font-mono text-text-secondary text-right">
                {entry.total_findings}
              </span>
              {hasLanguage && (
                <span className="text-xs font-mono text-text-muted text-right truncate">
                  {entry.language || '--'}
                </span>
              )}
              {hasFramework && (
                <span className="text-xs font-mono text-text-muted text-right truncate">
                  {entry.framework || '--'}
                </span>
              )}
              <span className="text-xs font-mono text-text-muted text-right">
                {entry.duration_seconds.toFixed(1)}s
              </span>
              <span className="text-xs font-mono text-accent-green text-right">
                ${entry.cost_usd.toFixed(3)}
              </span>
              <span className="text-xs font-mono text-text-muted text-right">
                {timeAgo(entry.completed_at)}
              </span>
            </div>
            {/* Mobile row */}
            <div className="sm:hidden px-4 py-3">
              <div className="flex items-center justify-between mb-1">
                <span className="text-sm font-mono text-text-primary truncate">{entry.repo_name}</span>
                <span className={`text-xs font-mono font-semibold ${riskColor(entry.risk_score)}`}>
                  {entry.risk_score}
                </span>
              </div>
              <div className="flex items-center gap-3 text-xs font-mono text-text-muted flex-wrap">
                <span>{entry.total_findings} findings</span>
                {entry.language && <span>{entry.language}</span>}
                {entry.framework && <span>{entry.framework}</span>}
                <span>{entry.duration_seconds.toFixed(1)}s</span>
                <span className="text-accent-green">${entry.cost_usd.toFixed(3)}</span>
                <span>{timeAgo(entry.completed_at)}</span>
              </div>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}
