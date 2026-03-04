import type { PlatformStats } from '../types';

interface StatsBarProps {
  stats: PlatformStats;
}

export default function StatsBar({ stats }: StatsBarProps) {
  return (
    <div className="flex flex-wrap items-center justify-center gap-x-6 gap-y-1 text-sm font-mono text-text-secondary">
      <span>
        <span className="text-text-primary">{(stats?.total_tasks ?? 0)}</span> repos scanned
      </span>
      <span className="text-border">|</span>
      <span>
        48+ vulnerability patterns
      </span>
      <span className="text-border">|</span>
      <span>
        3 AI models
      </span>
    </div>
  );
}
