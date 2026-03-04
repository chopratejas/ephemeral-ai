import type { ScanLayer } from '../types';

interface LiveAuditProps {
  repoUrl: string;
  layers: ScanLayer[];
  elapsed: number;
}

function StatusIcon({ status }: { status: ScanLayer['status'] }) {
  switch (status) {
    case 'pending':
      return <span className="text-text-muted text-sm leading-none">&#9675;</span>;
    case 'running':
      return <span className="text-accent-purple text-sm leading-none animate-pulse-dot">&#9673;</span>;
    case 'done':
      return <span className="text-accent-green text-sm leading-none">&#9679;</span>;
    case 'error':
      return <span className="text-accent-red text-sm leading-none">&#10005;</span>;
    default:
      return null;
  }
}

function extractRepoName(url: string): string {
  return url.replace(/^https?:\/\/github\.com\//, '').replace(/\.git$/, '').replace(/\/$/, '');
}

export default function LiveAudit({ repoUrl, layers, elapsed }: LiveAuditProps) {
  const repoName = extractRepoName(repoUrl);
  const completedLayers = layers.filter((l) => l.status === 'done').length;
  const totalFindings = layers.reduce((sum, l) => sum + l.findings, 0);
  const isRunning = layers.some((l) => l.status === 'running');

  return (
    <div className="max-w-5xl mx-auto px-6 pt-16 pb-20 animate-fade-in">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-2 mb-1">
          <h2 className="text-lg font-semibold text-text-primary">Auditing</h2>
          <span className="font-mono text-accent-purple text-sm">{repoName}</span>
        </div>
        <div className="flex items-center gap-3 text-xs font-mono text-text-secondary">
          <span>branch: main</span>
          <span className="text-border">|</span>
          <span>language: Python</span>
          <span className="text-border">|</span>
          <span className="flex items-center gap-1.5">
            droplet:
            <span className={`w-1.5 h-1.5 rounded-full ${isRunning ? 'bg-accent-green' : 'bg-text-muted'}`} />
            <span className={isRunning ? 'text-accent-green' : ''}>
              {isRunning ? 'active' : 'pending'}
            </span>
          </span>
        </div>
      </div>

      {/* Progress bar */}
      <div className="mb-6">
        <div className="h-1 bg-border rounded-full overflow-hidden">
          <div
            className="h-full bg-accent-purple rounded-full transition-all duration-500 ease-out"
            style={{ width: `${(completedLayers / layers.length) * 100}%` }}
          />
        </div>
      </div>

      {/* Layers */}
      <div className="border border-border rounded-lg bg-surface overflow-hidden mb-6 stagger-children">
        {layers.map((layer, idx) => (
          <div
            key={layer.id}
            className={`flex items-center gap-3 px-4 py-3 ${
              idx < layers.length - 1 ? 'border-b border-border' : ''
            } ${layer.status === 'running' ? 'bg-accent-purple/5' : ''}`}
          >
            <StatusIcon status={layer.status} />

            <span className="text-xs font-mono text-text-muted w-6 shrink-0">
              {layer.id}
            </span>

            <span
              className={`text-sm flex-1 ${
                layer.status === 'done'
                  ? 'text-text-primary'
                  : layer.status === 'running'
                    ? 'text-text-primary'
                    : 'text-text-muted'
              }`}
            >
              {layer.name}
            </span>

            <span className="text-xs font-mono text-text-secondary w-24 text-right">
              {layer.status === 'done' && (
                <>
                  {layer.findings} {layer.findings === 1 ? 'finding' : 'findings'}
                </>
              )}
              {layer.status === 'running' && (
                <span className="text-accent-purple">analyzing...</span>
              )}
            </span>

            <span className="text-xs font-mono text-text-muted w-12 text-right">
              {layer.duration !== null ? `${layer.duration.toFixed(1)}s` : '--'}
            </span>
          </div>
        ))}
      </div>

      {/* Bottom info */}
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-xs font-mono text-text-secondary">
        <span>
          provisioning: <span className="text-text-primary">0.0s</span>{' '}
          <span className="text-text-muted">(warm pool)</span>
        </span>
        <span>
          elapsed: <span className="text-text-primary">{elapsed.toFixed(1)}s</span>
        </span>
        <span>
          findings: <span className="text-text-primary">{totalFindings}</span>
        </span>
        <span>
          cost: <span className="text-accent-green">$0.009</span>
        </span>
        <span>
          droplet: <span className="text-text-muted">143.110.152.148</span>
        </span>
      </div>
    </div>
  );
}
