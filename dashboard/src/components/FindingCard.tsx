import { useState } from 'react';
import type { Finding } from '../types';
import SeverityBadge from './SeverityBadge';

interface FindingCardProps {
  finding: Finding;
  auditTaskId?: string;
  repoUrl?: string;
}


function ChevronIcon({ expanded }: { expanded: boolean }) {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 16 16"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={`transition-transform duration-200 ${expanded ? 'rotate-90' : ''}`}
    >
      <path d="M6 4l4 4-4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  );
}

function WrenchIcon() {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 16 16"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <path
        d="M10.5 2.5a3.5 3.5 0 0 0-3.28 4.72L3 11.44V13h1.56l4.22-4.22A3.5 3.5 0 1 0 10.5 2.5z"
        stroke="currentColor"
        strokeWidth="1.2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function LockIcon() {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 16 16"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <rect x="3" y="7" width="10" height="7" rx="1.5" stroke="currentColor" strokeWidth="1.2"/>
      <path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/>
    </svg>
  );
}

function DiffView({ finding }: { finding: Finding }) {
  const beforeCode = finding.description;
  const afterCode = finding.fix_code || finding.fix;

  return (
    <div className="mt-3 border border-border rounded-lg overflow-hidden">
      <div className="px-3 py-2 border-b border-border bg-[#0a0a0f]">
        <span className="text-xs font-mono text-text-muted">
          {finding.file}{finding.line > 0 ? `:${finding.line}` : ''}
        </span>
      </div>

      {/* Removed (before) */}
      <div className="border-b border-border">
        <div className="px-3 py-1.5 bg-accent-red/5 border-b border-accent-red/10">
          <span className="text-2xs font-mono font-semibold text-accent-red uppercase tracking-wider">
            Vulnerable Code
          </span>
        </div>
        <pre className="px-3 py-2.5 bg-accent-red/[0.03] text-sm font-mono text-text-secondary leading-relaxed whitespace-pre-wrap overflow-x-auto">
          <code>
            {beforeCode.split('\n').map((line, i) => (
              <div key={i} className="flex">
                <span className="select-none text-accent-red/40 mr-3 shrink-0">-</span>
                <span>{line}</span>
              </div>
            ))}
          </code>
        </pre>
      </div>

      {/* Added (after) */}
      <div>
        <div className="px-3 py-1.5 bg-accent-green/5 border-b border-accent-green/10">
          <span className="text-2xs font-mono font-semibold text-accent-green uppercase tracking-wider">
            Suggested Fix
          </span>
        </div>
        <pre className="px-3 py-2.5 bg-accent-green/[0.03] text-sm font-mono text-text-secondary leading-relaxed whitespace-pre-wrap overflow-x-auto">
          <code>
            {afterCode.split('\n').map((line, i) => (
              <div key={i} className="flex">
                <span className="select-none text-accent-green/40 mr-3 shrink-0">+</span>
                <span>{line}</span>
              </div>
            ))}
          </code>
        </pre>
      </div>

      {/* Create PR */}
      <div className="px-3 py-2.5 border-t border-border bg-[#0a0a0f] flex items-center justify-end gap-2">
        <span className="text-xs text-text-muted font-mono">
          Fix is applied, built, and tested on the Droplet
        </span>
        <button
          disabled
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono rounded border border-border bg-surface text-text-muted cursor-not-allowed opacity-50"
          title="Connect GitHub to create PRs (coming soon)"
        >
          <LockIcon />
          Create PR
        </button>
      </div>
    </div>
  );
}

export default function FindingCard({ finding, auditTaskId, repoUrl: _repoUrl }: FindingCardProps) {
  const [expanded, setExpanded] = useState(false);
  const [showFix, setShowFix] = useState(false);
  const [fixStatus, setFixStatus] = useState<'idle' | 'fixing' | 'done' | 'error'>('idle');
  const [fixMessage, setFixMessage] = useState('');

  const hasFix = !!(finding.fix || finding.fix_code);

  const handleFix = async () => {
    if (!auditTaskId) return;
    setFixStatus('fixing');
    setFixMessage('Applying fix on Droplet...');
    setShowFix(true);
    if (!expanded) setExpanded(true);

    try {
      const API = import.meta.env.VITE_API_URL || 'https://ephemeral-ai-dgdbw.ondigitalocean.app';
      const resp = await fetch(`${API}/api/v1/findings/fix`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          audit_task_id: auditTaskId,
          finding: {
            file: finding.file,
            line: finding.line,
            title: finding.title,
            description: finding.description,
            fix: finding.fix,
            fix_code: finding.fix_code,
            severity: finding.severity,
          },
        }),
      });

      if (!resp.ok) {
        const err = await resp.text();
        setFixStatus('error');
        setFixMessage(`Fix failed: ${err}`);
        return;
      }

      const data = await resp.json();
      setFixMessage(`Fix in progress (task: ${data.fix_task_id?.slice(0, 8)}). Building and testing...`);

      // Poll for completion
      const fixTaskId = data.fix_task_id;
      const poll = setInterval(async () => {
        try {
          const statusResp = await fetch(`${API}/api/v1/tasks/${fixTaskId}`);
          const statusData = await statusResp.json();
          if (statusData.status === 'completed') {
            clearInterval(poll);
            setFixStatus('done');
            setFixMessage('Fix applied, built, and committed on the Droplet.');
          } else if (statusData.status === 'failed') {
            clearInterval(poll);
            setFixStatus('error');
            setFixMessage(statusData.error || 'Fix failed');
          }
        } catch {
          // keep polling
        }
      }, 3000);
    } catch (e) {
      setFixStatus('error');
      setFixMessage(`Error: ${e}`);
    }
  };

  return (
    <div
      className="border border-border rounded-lg bg-surface overflow-hidden"
    >
      <div className="flex items-start">
        <button
          onClick={() => setExpanded(!expanded)}
          className="flex-1 flex items-start gap-3 px-4 py-3.5 text-left hover:bg-surface-hover transition-colors"
        >
          <span className="mt-0.5 text-text-muted">
            <ChevronIcon expanded={expanded} />
          </span>

          <SeverityBadge severity={finding.severity} size="md" />

          <div className="flex-1 min-w-0">
            <span className="text-sm text-text-primary">{finding.title}</span>
            {finding.file && (
              <div className="mt-1">
                <span
                  className="inline-block text-xs font-mono px-1.5 py-0.5 rounded"
                  style={{ color: '#71717a', background: 'rgba(30, 30, 46, 0.6)' }}
                >
                  {finding.file}
                  {finding.line > 0 && `:${finding.line}`}
                </span>
              </div>
            )}
          </div>

          <div className="flex items-center gap-2 shrink-0">
            {finding.owasp && (
              <span className="text-xs font-mono text-accent-orange px-1.5 py-0.5 bg-accent-orange/10 border border-accent-orange/20 rounded">
                {finding.owasp}
              </span>
            )}
            {finding.cwe && (
              <span className="text-xs font-mono text-text-muted px-1.5 py-0.5 bg-surface border border-border rounded">
                {finding.cwe}
              </span>
            )}
          </div>
        </button>

        {hasFix && (
          <button
            onClick={(e) => {
              e.stopPropagation();
              if (fixStatus === 'idle' && auditTaskId) {
                handleFix();
              } else {
                setShowFix(!showFix);
                if (!expanded && !showFix) setExpanded(true);
              }
            }}
            disabled={fixStatus === 'fixing'}
            className={`shrink-0 flex items-center gap-1.5 px-3 py-3.5 text-xs font-mono transition-colors ${
              fixStatus === 'fixing'
                ? 'text-accent-teal bg-accent-teal/10 animate-pulse'
                : fixStatus === 'done'
                  ? 'text-accent-green bg-accent-green/10'
                  : showFix
                    ? 'text-accent-teal bg-accent-teal/10'
                    : 'text-text-muted hover:text-accent-teal hover:bg-accent-teal/5'
            }`}
            title={fixStatus === 'fixing' ? 'Fixing...' : fixStatus === 'done' ? 'Fix applied' : 'Fix on Droplet'}
          >
            <WrenchIcon />
            <span className="hidden sm:inline">
              {fixStatus === 'fixing' ? 'Fixing...' : fixStatus === 'done' ? 'Fixed' : 'Fix'}
            </span>
          </button>
        )}
      </div>

      <div
        className="overflow-hidden transition-all duration-300 ease-in-out"
        style={{
          maxHeight: expanded ? '2000px' : '0',
          opacity: expanded ? 1 : 0,
        }}
      >
        <div className="px-4 pb-4 pt-0 ml-[22px] border-t border-border">
          <div className="pt-3 space-y-3">
            <p className="text-sm text-text-secondary" style={{ lineHeight: 1.8 }}>
              {finding.description}
            </p>

            {!showFix && finding.fix && (
              <div
                className="px-4 py-3 rounded"
                style={{
                  background: 'rgba(34, 197, 94, 0.04)',
                  border: '1px solid rgba(34, 197, 94, 0.1)',
                }}
              >
                <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: '#22c55e' }}>
                  Suggested Fix
                </span>
                <p className="text-sm text-text-secondary mt-1.5" style={{ lineHeight: 1.7 }}>
                  {finding.fix}
                </p>
                {finding.fix_code && (
                  <pre
                    className="mt-2 px-3 py-2.5 rounded text-sm font-mono overflow-x-auto whitespace-pre-wrap"
                    style={{
                      background: '#0a0a0f',
                      border: '1px solid #1e1e2e',
                      color: '#a5f3fc',
                      lineHeight: 1.6,
                    }}
                  >
                    <code>{finding.fix_code}</code>
                  </pre>
                )}
              </div>
            )}

            {fixMessage && (
              <div
                className="px-4 py-2.5 text-sm font-mono"
                style={{
                  background: fixStatus === 'done' ? 'rgba(34,197,94,0.06)' :
                              fixStatus === 'error' ? 'rgba(239,68,68,0.06)' :
                              'rgba(20,184,166,0.06)',
                  color: fixStatus === 'done' ? '#22c55e' :
                         fixStatus === 'error' ? '#ef4444' :
                         '#14b8a6',
                  borderTop: '1px solid rgba(30,30,46,0.5)',
                }}
              >
                {fixMessage}
              </div>
            )}
            {showFix && <DiffView finding={finding} />}

            {(finding.owasp || finding.cwe) && (
              <div className="flex items-center gap-3 text-xs font-mono text-text-muted pt-1">
                {finding.owasp && <span>OWASP {finding.owasp}</span>}
                {finding.cwe && <span>{finding.cwe}</span>}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
