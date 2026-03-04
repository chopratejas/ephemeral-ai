import { useState } from 'react';
import type { Finding } from '../types';
import SeverityBadge from './SeverityBadge';

interface FindingCardProps {
  finding: Finding;
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

export default function FindingCard({ finding }: FindingCardProps) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="border border-border rounded-lg bg-surface overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-start gap-3 px-4 py-3 text-left hover:bg-surface-hover transition-colors"
      >
        <span className="mt-0.5 text-text-muted">
          <ChevronIcon expanded={expanded} />
        </span>

        <SeverityBadge severity={finding.severity} />

        <div className="flex-1 min-w-0">
          <span className="text-sm text-text-primary">{finding.title}</span>
          {finding.file && (
            <span className="ml-2 text-xs font-mono text-text-muted">
              {finding.file}
              {finding.line > 0 && `:${finding.line}`}
            </span>
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

      {expanded && (
        <div className="px-4 pb-4 pt-0 ml-[22px] border-t border-border">
          <div className="pt-3 space-y-3">
            <p className="text-sm text-text-secondary leading-relaxed">
              {finding.description}
            </p>

            <div className="flex items-start gap-2 px-3 py-2.5 bg-accent-green/5 border border-accent-green/10 rounded">
              <span className="text-accent-green text-xs mt-0.5 shrink-0">&rsaquo;</span>
              <div>
                <span className="text-xs font-semibold text-accent-green uppercase tracking-wider">
                  Suggested Fix
                </span>
                <p className="text-sm text-text-secondary mt-1 leading-relaxed">
                  {finding.fix}
                </p>
              </div>
            </div>

            {(finding.owasp || finding.cwe) && (
              <div className="flex items-center gap-3 text-xs font-mono text-text-muted pt-1">
                {finding.owasp && <span>OWASP {finding.owasp}</span>}
                {finding.cwe && <span>{finding.cwe}</span>}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
