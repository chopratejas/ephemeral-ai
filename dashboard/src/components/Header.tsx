import type { PlatformStats } from '../types';

interface HeaderProps {
  stats: PlatformStats;
  onLogoClick: () => void;
}

function ShieldIcon() {
  return (
    <svg
      width="24"
      height="24"
      viewBox="0 0 32 32"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className="shrink-0"
    >
      <path
        d="M16 2L4 8v8c0 7.18 5.12 13.9 12 16 6.88-2.1 12-8.82 12-16V8L16 2z"
        fill="#8b5cf6"
        fillOpacity="0.15"
        stroke="#8b5cf6"
        strokeWidth="1.5"
      />
      <path
        d="M12 16l3 3 6-6"
        stroke="#8b5cf6"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export default function Header({ stats, onLogoClick }: HeaderProps) {
  return (
    <header className="border-b border-border bg-surface/50 backdrop-blur-sm sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-6 h-14 flex items-center justify-between">
        <button
          onClick={onLogoClick}
          className="flex items-center gap-2.5 hover:opacity-80 transition-opacity"
        >
          <ShieldIcon />
          <span className="text-text-primary font-semibold text-[15px] tracking-tight">
            CodeScope
          </span>
          <span className="text-text-muted text-xs font-normal hidden sm:inline">
            / ephemeral.ai
          </span>
        </button>

        <div className="flex items-center gap-6 text-xs font-mono text-text-secondary">
          <div className="hidden md:flex items-center gap-1.5">
            <span className="text-text-muted">audits</span>
            <span className="text-text-primary">{(stats?.total_tasks ?? 0).toLocaleString()}</span>
          </div>
          <div className="hidden md:flex items-center gap-1.5">
            <span className="text-text-muted">saved</span>
            <span className="text-accent-green">${(stats?.total_savings_usd ?? 0).toFixed(2)}</span>
          </div>
          <div className="hidden sm:flex items-center gap-1.5">
            <span className="text-text-muted">cost</span>
            <span className="text-accent-green">${(stats?.total_cost_usd ?? 0).toFixed(3)}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-accent-green" />
            <span className="text-text-muted">operational</span>
          </div>
        </div>
      </div>
    </header>
  );
}
