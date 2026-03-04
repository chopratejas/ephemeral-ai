import type { Severity } from '../types';

interface SeverityBadgeProps {
  severity: Severity;
  size?: 'sm' | 'md';
}

const config: Record<Severity, { label: string; bg: string; text: string; border: string }> = {
  critical: {
    label: 'CRIT',
    bg: 'bg-accent-red/10',
    text: 'text-accent-red',
    border: 'border-accent-red/20',
  },
  high: {
    label: 'HIGH',
    bg: 'bg-accent-orange/10',
    text: 'text-accent-orange',
    border: 'border-accent-orange/20',
  },
  medium: {
    label: 'MED',
    bg: 'bg-yellow-500/10',
    text: 'text-yellow-400',
    border: 'border-yellow-500/20',
  },
  low: {
    label: 'LOW',
    bg: 'bg-accent-blue/10',
    text: 'text-accent-blue',
    border: 'border-accent-blue/20',
  },
  info: {
    label: 'INFO',
    bg: 'bg-text-secondary/10',
    text: 'text-text-secondary',
    border: 'border-text-secondary/20',
  },
};

export default function SeverityBadge({ severity, size = 'sm' }: SeverityBadgeProps) {
  const c = config[severity];
  const sizeClasses = size === 'sm' ? 'text-xs px-1.5 py-0.5' : 'text-xs px-2 py-1';

  return (
    <span
      className={`inline-flex items-center font-mono font-semibold rounded border ${c.bg} ${c.text} ${c.border} ${sizeClasses}`}
    >
      {c.label}
    </span>
  );
}

export function SeverityCount({ severity, count }: { severity: Severity; count: number }) {
  const c = config[severity];

  return (
    <div className={`flex flex-col items-center justify-center px-4 py-3 rounded-lg border ${c.bg} ${c.border} min-w-[64px]`}>
      <span className={`text-xl font-bold font-mono ${c.text}`}>{count}</span>
      <span className={`text-xs font-mono font-semibold ${c.text} opacity-70 mt-0.5`}>
        {c.label}
      </span>
    </div>
  );
}
