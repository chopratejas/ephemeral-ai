import type { PlatformStats } from '../types';

interface StatsBarProps {
  stats: PlatformStats;
}

export default function StatsBar({ stats }: StatsBarProps) {
  return (
    <div className="flex flex-wrap items-center justify-center gap-x-6 gap-y-1 text-xs font-mono text-text-secondary">
      <span>
        <span className="text-text-primary">{stats.total_tasks.toLocaleString()}</span> repos audited
      </span>
      <span className="text-border">|</span>
      <span>
        <span className="text-text-primary">{stats.total_findings.toLocaleString()}</span> findings
      </span>
      <span className="text-border">|</span>
      <span>
        <span className="text-accent-green">${stats.total_cost_usd.toFixed(2)}</span> total cost
      </span>
    </div>
  );
}
