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
      return (
        <span
          className="inline-block rounded-full"
          style={{ width: '8px', height: '8px', background: '#52525b' }}
        />
      );
    case 'running':
      return (
        <span
          className="inline-block rounded-full animate-pulse-dot"
          style={{ width: '8px', height: '8px', background: '#8b5cf6' }}
        />
      );
    case 'done':
      return (
        <span
          className="inline-block rounded-full"
          style={{ width: '8px', height: '8px', background: '#22c55e' }}
        />
      );
    case 'error':
      return (
        <span
          className="inline-block rounded-full"
          style={{ width: '8px', height: '8px', background: '#ef4444' }}
        />
      );
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
    <div className="max-w-5xl mx-auto px-6 animate-fade-in" style={{ paddingTop: '64px', paddingBottom: '80px' }}>
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-baseline gap-3 mb-3">
          <h2
            className="font-semibold"
            style={{ fontSize: '24px', color: '#e4e4e7', letterSpacing: '-0.02em' }}
          >
            Auditing
          </h2>
          <span
            className="font-mono"
            style={{ fontSize: '18px', color: '#8b5cf6' }}
          >
            {repoName}
          </span>
        </div>
        <div className="flex items-center gap-3 text-sm font-mono" style={{ color: '#71717a' }}>
          <span>branch: main</span>
          <span style={{ color: '#1e1e2e' }}>|</span>
          <span className="flex items-center gap-1.5">
            droplet:
            <span
              className="inline-block rounded-full"
              style={{
                width: '6px',
                height: '6px',
                background: isRunning ? '#22c55e' : '#52525b',
              }}
            />
            <span style={{ color: isRunning ? '#22c55e' : '#71717a' }}>
              {isRunning ? 'active' : 'booting...'}
            </span>
          </span>
          <span style={{ color: '#1e1e2e' }}>|</span>
          <span>
            elapsed: <span style={{ color: '#e4e4e7' }}>{elapsed.toFixed(1)}s</span>
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Left: Layers */}
        <div>
          {/* Progress bar */}
          <div className="mb-5">
            <div className="overflow-hidden" style={{ height: '4px', background: '#1e1e2e', borderRadius: '2px' }}>
              <div
                className="transition-all duration-500 ease-out"
                style={{
                  height: '100%',
                  width: `${(completedLayers / layers.length) * 100}%`,
                  background: '#8b5cf6',
                  borderRadius: '2px',
                }}
              />
            </div>
          </div>

          <div
            className="overflow-hidden"
            style={{
              border: '1px solid #1e1e2e',
              borderRadius: '12px',
              background: '#12121a',
            }}
          >
            {layers.map((layer, idx) => (
              <div
                key={layer.id}
                className="flex items-center gap-3 transition-colors"
                style={{
                  padding: '14px 16px',
                  borderBottom: idx < layers.length - 1 ? '1px solid #1e1e2e' : 'none',
                  background: layer.status === 'running' ? 'rgba(139, 92, 246, 0.04)' : 'transparent',
                }}
              >
                <StatusIcon status={layer.status} />

                <span className="text-sm font-mono shrink-0" style={{ width: '20px', color: '#52525b' }}>
                  {layer.id}
                </span>

                <span
                  className="flex-1"
                  style={{
                    fontSize: '14px',
                    color: layer.status === 'pending' ? '#52525b' : '#e4e4e7',
                  }}
                >
                  {layer.name}
                </span>

                <span className="text-sm font-mono" style={{ width: '110px', textAlign: 'right' }}>
                  {layer.status === 'done' && (
                    <span style={{ color: '#71717a' }}>
                      {layer.findings} {layer.findings === 1 ? 'finding' : 'findings'}
                    </span>
                  )}
                  {layer.status === 'running' && (
                    <span style={{ color: '#8b5cf6' }}>analyzing...</span>
                  )}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Right: Live Log Stream */}
        <div>
          <div
            className="font-semibold uppercase tracking-wider mb-3"
            style={{ fontSize: '11px', color: '#71717a', letterSpacing: '0.08em' }}
          >
            Live Output
          </div>
          <div
            className="overflow-hidden"
            style={{
              border: '1px solid #1e1e2e',
              borderRadius: '12px',
              background: '#08080d',
            }}
          >
            <div
              className="overflow-y-auto p-5 font-mono text-sm leading-relaxed"
              style={{ height: '400px' }}
            >
              {logs.length === 0 && (
                <div style={{ color: '#52525b' }}>
                  Waiting for droplet to boot and start scanning...
                </div>
              )}
              {logs.map((line, i) => {
                const isLayer = line.includes('[Layer ');
                const isComplete = line.includes('complete') || line.includes('Complete');
                const isError = line.includes('ERROR') || line.includes('error');
                const isFindings = line.includes('findings');

                let color = '#52525b';
                if (isLayer) color = '#8b5cf6';
                if (isComplete) color = '#22c55e';
                if (isError) color = '#ef4444';
                if (isFindings) color = '#e4e4e7';

                return (
                  <div key={i} style={{ color, padding: '2px 0' }}>
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
