import { useState, type FormEvent } from 'react';
import type { PlatformStats } from '../types';

interface AuditFormProps {
  onSubmit: (url: string) => void;
  loading: boolean;
  error: string | null;
  stats: PlatformStats;
}

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
    <div>
      {/* ─── Hero Section ─── */}
      <section className="max-w-3xl mx-auto px-6 pt-[120px] pb-[80px]">
        <div className="stagger">
          {/* Headline */}
          <h1
            className="animate-fade-up"
            style={{
              fontSize: 'clamp(2.5rem, 5vw, 3.5rem)',
              fontWeight: 700,
              letterSpacing: '-0.03em',
              lineHeight: 1.1,
              color: '#e4e4e7',
            }}
          >
            Find vulnerabilities
            <br />
            before they find you.
          </h1>

          {/* Subtitle */}
          <p
            className="animate-fade-up delay-100 mt-6 max-w-lg"
            style={{
              fontSize: '1.125rem',
              lineHeight: 1.7,
              color: '#71717a',
            }}
          >
            Paste any GitHub repo. 7 security layers. 3 AI models.
            Your code is destroyed after every scan.
          </p>

          {/* Input + Button */}
          <form onSubmit={handleSubmit} className="animate-fade-up delay-200 mt-10">
            <div className="flex gap-3">
              <div className="flex-1 relative">
                <input
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="github.com/owner/repo"
                  spellCheck={false}
                  autoFocus
                  className="w-full font-mono text-text-primary placeholder:text-text-muted transition-all duration-200"
                  style={{
                    height: '56px',
                    fontSize: '15px',
                    background: '#12121a',
                    border: '1px solid #1e1e2e',
                    borderRadius: '12px',
                    padding: '0 20px',
                  }}
                  onFocus={(e) => {
                    e.currentTarget.style.borderColor = '#8b5cf6';
                    e.currentTarget.style.boxShadow = '0 0 0 3px rgba(139, 92, 246, 0.1)';
                  }}
                  onBlur={(e) => {
                    e.currentTarget.style.borderColor = '#1e1e2e';
                    e.currentTarget.style.boxShadow = 'none';
                  }}
                />
              </div>
              <button
                type="submit"
                disabled={loading || !url.trim()}
                className="shrink-0 text-white font-semibold flex items-center gap-2 disabled:opacity-40 disabled:cursor-not-allowed transition-all duration-200 active:scale-[0.98]"
                style={{
                  height: '56px',
                  padding: '0 32px',
                  background: '#8b5cf6',
                  borderRadius: '12px',
                  fontSize: '15px',
                  border: 'none',
                  cursor: loading || !url.trim() ? 'not-allowed' : 'pointer',
                }}
                onMouseEnter={(e) => {
                  if (!loading && url.trim()) {
                    e.currentTarget.style.background = '#7c3aed';
                  }
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = '#8b5cf6';
                }}
              >
                <span>Audit</span>
                <ArrowIcon />
              </button>
            </div>
          </form>

          {/* Error */}
          {error && (
            <div
              className="animate-fade-up mt-4 px-4 py-3 text-sm font-mono"
              style={{
                background: 'rgba(239, 68, 68, 0.08)',
                border: '1px solid rgba(239, 68, 68, 0.15)',
                borderRadius: '12px',
                color: '#ef4444',
              }}
            >
              {error}
            </div>
          )}

          {/* Stats line */}
          <div
            className="animate-fade-up delay-300 mt-8 flex items-center gap-2 font-mono"
            style={{ fontSize: '14px', color: '#52525b' }}
          >
            <span>
              <span style={{ color: '#71717a' }}>{stats?.total_tasks ?? 0}</span> repos scanned
            </span>
            <span style={{ color: '#1e1e2e' }}>&middot;</span>
            <span>48+ checks</span>
            <span style={{ color: '#1e1e2e' }}>&middot;</span>
            <span>3 AI models</span>
          </div>
        </div>
      </section>

      {/* ─── How It Works ─── */}
      <section className="max-w-3xl mx-auto px-6 pb-[120px]">
        <div className="animate-slide-up delay-400">
          <h2
            className="mb-10 font-semibold"
            style={{
              fontSize: '13px',
              letterSpacing: '0.08em',
              textTransform: 'uppercase' as const,
              color: '#52525b',
            }}
          >
            How it works
          </h2>

          <div className="space-y-8">
            {[
              {
                step: '01',
                title: 'Paste a GitHub URL',
                desc: 'Any public repository. We support Python, JavaScript, TypeScript, Go, Rust, and more.',
              },
              {
                step: '02',
                title: 'We clone, install, and run your code in an isolated VM',
                desc: 'An ephemeral droplet spins up in under 2 seconds. Full environment: dependencies, runtime, everything.',
              },
              {
                step: '03',
                title: '7 parallel security layers find real vulnerabilities',
                desc: 'SAST, SCA, secrets detection, license compliance, AI code safety, supply chain analysis, and multi-model synthesis with exploit scenarios.',
              },
            ].map((item) => (
              <div key={item.step} className="flex gap-6">
                <span
                  className="shrink-0 font-mono"
                  style={{ fontSize: '13px', color: '#8b5cf6', paddingTop: '2px' }}
                >
                  {item.step}
                </span>
                <div>
                  <p
                    className="font-medium"
                    style={{ fontSize: '16px', color: '#e4e4e7', lineHeight: 1.5 }}
                  >
                    {item.title}
                  </p>
                  <p
                    className="mt-1"
                    style={{ fontSize: '14px', color: '#52525b', lineHeight: 1.6 }}
                  >
                    {item.desc}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}
