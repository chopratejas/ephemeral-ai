import type { PlatformStats } from '../types';

interface StatsBarProps {
  stats: PlatformStats;
}

export default function StatsBar({ stats }: StatsBarProps) {
  return (
    <div className="flex flex-wrap items-center justify-center gap-x-6 gap-y-1 text-xs font-mono text-text-secondary">
      <span>
        <span className="text-text-primary">{(stats?.total_tasks ?? 0).toLocaleString()}</span> repos audited
      </span>
      <span className="text-border">|</span>
      <span>
        <span className="text-accent-green">${(stats?.total_cost_usd ?? 0).toFixed(3)}</span> total cost
      </span>
      <span className="text-border">|</span>
      <span>
        <span className="text-text-primary">${(stats?.total_savings_usd ?? 0).toFixed(2)}</span> saved vs always-on
      </span>
    </div>
  );
}
