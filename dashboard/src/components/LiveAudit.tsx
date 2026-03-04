import { useRef, useEffect } from 'react';
import type { ScanLayer } from '../types';

interface LiveAuditProps {
  repoUrl: string;
  layers: ScanLayer[];
  elapsed: number;
  logs: string[];
}

function StatusIcon({ status }: { status: ScanLayer['status'] }) {
  switch (status) {
    case 'pending':
      return <span className="text-text-muted text-base leading-none">&#9675;</span>;
    case 'running':
      return <span className="text-accent-purple text-base leading-none animate-pulse-dot">&#9673;</span>;
    case 'done':
      return <span className="text-accent-green text-base leading-none">&#9679;</span>;
    case 'error':
      return <span className="text-accent-red text-base leading-none">&#10005;</span>;
    default:
      return null;
  }
}

function extractRepoName(url: string): string {
  return url.replace(/^https?:\/\/github\.com\//, '').replace(/\.git$/, '').replace(/\/$/, '');
}

export default function LiveAudit({ repoUrl, layers, elapsed, logs }: LiveAuditProps) {
  const repoName = extractRepoName(repoUrl);
  const completedLayers = layers.filter((l) => l.status === 'done').length;
  const isRunning = layers.some((l) => l.status === 'running');
  const logEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll logs
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  return (
    <div className="max-w-5xl mx-auto px-6 pt-12 pb-20 animate-fade-in">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-2">
          <h2 className="text-xl font-semibold text-text-primary">Auditing</h2>
          <span className="font-mono text-accent-purple">{repoName}</span>
        </div>
        <div className="flex items-center gap-3 text-sm font-mono text-text-secondary">
          <span>branch: main</span>
          <span className="text-border">|</span>
          <span className="flex items-center gap-1.5">
            droplet:
            <span className={`w-2 h-2 rounded-full ${isRunning ? 'bg-accent-green' : 'bg-text-muted'}`} />
            <span className={isRunning ? 'text-accent-green' : ''}>
              {isRunning ? 'active' : 'booting...'}
            </span>
          </span>
          <span className="text-border">|</span>
          <span>elapsed: <span className="text-text-primary">{elapsed.toFixed(1)}s</span></span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Layers */}
        <div>
          {/* Progress bar */}
          <div className="mb-4">
            <div className="h-1.5 bg-border rounded-full overflow-hidden">
              <div
                className="h-full bg-accent-purple rounded-full transition-all duration-500 ease-out"
                style={{ width: `${(completedLayers / layers.length) * 100}%` }}
              />
            </div>
          </div>

          <div className="border border-border rounded-lg bg-surface overflow-hidden">
            {layers.map((layer, idx) => (
              <div
                key={layer.id}
                className={`flex items-center gap-3 px-4 py-3.5 ${
                  idx < layers.length - 1 ? 'border-b border-border' : ''
                } ${layer.status === 'running' ? 'bg-accent-purple/5' : ''}`}
              >
                <StatusIcon status={layer.status} />

                <span className="text-sm font-mono text-text-muted w-6 shrink-0">
                  {layer.id}
                </span>

                <span
                  className={`flex-1 ${
                    layer.status === 'done'
                      ? 'text-text-primary'
                      : layer.status === 'running'
                        ? 'text-text-primary'
                        : 'text-text-muted'
                  }`}
                >
                  {layer.name}
                </span>

                <span className="text-sm font-mono text-text-secondary w-28 text-right">
                  {layer.status === 'done' && (
                    <>{layer.findings} {layer.findings === 1 ? 'finding' : 'findings'}</>
                  )}
                  {layer.status === 'running' && (
                    <span className="text-accent-purple">analyzing...</span>
                  )}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Right: Live Log Stream */}
        <div>
          <div className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-3">
            Live Output
          </div>
          <div className="border border-border rounded-lg bg-[#08080d] overflow-hidden">
            <div className="h-[340px] overflow-y-auto p-4 font-mono text-sm leading-relaxed">
              {logs.length === 0 && (
                <div className="text-text-muted">
                  Waiting for Droplet to boot and start scanning...
                </div>
              )}
              {logs.map((line, i) => {
                const isLayer = line.includes('[Layer ');
                const isComplete = line.includes('complete') || line.includes('Complete');
                const isError = line.includes('ERROR') || line.includes('error');
                const isFindings = line.includes('findings');

                let color = 'text-text-muted';
                if (isLayer) color = 'text-accent-purple';
                if (isComplete) color = 'text-accent-green';
                if (isError) color = 'text-accent-red';
                if (isFindings) color = 'text-text-primary';

                return (
                  <div key={i} className={`${color} py-0.5`}>
                    {line}
                  </div>
                );
              })}
              <div ref={logEndRef} />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
