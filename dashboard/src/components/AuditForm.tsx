import { useState, type FormEvent } from 'react';
import type { PlatformStats } from '../types';
import StatsBar from './StatsBar';

interface AuditFormProps {
  onSubmit: (url: string) => void;
  loading: boolean;
  error: string | null;
  stats: PlatformStats;
}

const SCAN_CAPABILITIES = [
  'OWASP Top 10',
  'AI Code Patterns',
  'Prompt Injection',
  'Supply Chain',
  'Secrets',
  'License Compliance',
  'Dependency CVEs',
];

function ArrowIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M3 8h10M9 4l4 4-4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  );
}

export default function AuditForm({ onSubmit, loading, error, stats }: AuditFormProps) {
  const [url, setUrl] = useState('');

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;

    let normalized = url.trim();
    // Auto-prefix github.com URLs
    if (/^[\w-]+\/[\w.-]+$/.test(normalized)) {
      normalized = `https://github.com/${normalized}`;
    }
    if (!normalized.startsWith('http')) {
      normalized = `https://${normalized}`;
    }

    onSubmit(normalized);
  };

  return (
    <div className="animate-fade-in">
      <div className="max-w-5xl mx-auto px-6 pt-24 pb-16">
        {/* Hero text */}
        <div className="mb-10">
          <h1 className="text-3xl sm:text-5xl font-bold text-text-primary tracking-tight mb-3">
            Find vulnerabilities
            <br />
            <span className="text-accent-purple">before they find you.</span>
          </h1>
          <p className="text-lg text-text-secondary leading-relaxed max-w-xl">
            Paste any GitHub repo. 7 security layers. 3 AI models.
            48+ vulnerability patterns including AI-generated code flaws.
            Your code is destroyed after every scan.
          </p>
        </div>

        {/* Audit input */}
        <form onSubmit={handleSubmit} className="mb-6">
          <div className="flex gap-3">
            <div className="flex-1 relative">
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://github.com/owner/repo"
                spellCheck={false}
                autoFocus
                className="w-full h-12 px-4 bg-surface border border-border rounded-lg text-sm font-mono text-text-primary placeholder:text-text-muted focus:border-accent-purple/50 focus:ring-1 focus:ring-accent-purple/20 transition-colors"
              />
            </div>
            <button
              type="submit"
              disabled={loading || !url.trim()}
              className="h-12 px-6 bg-accent-purple hover:bg-accent-purple/90 disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-medium rounded-lg transition-colors flex items-center gap-2 shrink-0"
            >
              <span>Audit</span>
              <ArrowIcon />
            </button>
          </div>
        </form>

        {/* Error */}
        {error && (
          <div className="mb-6 px-4 py-3 bg-accent-red/10 border border-accent-red/20 rounded-lg text-sm text-accent-red font-mono">
            {error}
          </div>
        )}

        {/* Scan capabilities */}
        <div className="flex flex-wrap gap-2 mb-10">
          {SCAN_CAPABILITIES.map((cap) => (
            <span
              key={cap}
              className="px-2.5 py-1 bg-surface border border-border rounded text-xs font-mono text-text-secondary"
            >
              {cap}
            </span>
          ))}
        </div>

        {/* Cost line */}
        <p className="text-sm text-text-muted mb-8 font-mono">
          $0.01 per audit &middot; Code destroyed after scan &middot; No data retained
        </p>

        {/* Platform stats */}
        <StatsBar stats={stats} />
      </div>

      {/* Architecture diagram */}
      <div className="max-w-5xl mx-auto px-6 pb-20">
        <div className="border border-border rounded-lg p-6 bg-surface/50">
          <h3 className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-4">
            How it works
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 text-center">
            {[
              { step: '01', label: 'Provision', desc: 'Ephemeral droplet from warm pool' },
              { step: '02', label: 'Clone', desc: 'Shallow clone into isolated VM' },
              { step: '03', label: 'Scan', desc: '7 security layers in parallel' },
              { step: '04', label: 'Destroy', desc: 'Droplet terminated, data erased' },
            ].map((item, i) => (
              <div key={item.step} className="flex sm:flex-col items-center sm:items-center gap-3 sm:gap-2">
                <div className="flex items-center gap-3 sm:flex-col sm:gap-2">
                  <span className="text-xs font-mono text-accent-purple">{item.step}</span>
                  <span className="text-sm font-medium text-text-primary">{item.label}</span>
                </div>
                <span className="text-sm text-text-muted leading-tight hidden sm:block">{item.desc}</span>
                {i < 3 && (
                  <span className="text-text-muted text-xs hidden sm:block absolute-none">
                    {/* Arrow rendered via layout */}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
