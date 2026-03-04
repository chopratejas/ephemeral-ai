interface RiskScoreProps {
  score: number;
}

function getRiskLevel(score: number): { label: string; color: string } {
  if (score >= 70) return { label: 'CRITICAL', color: '#ef4444' };
  if (score >= 50) return { label: 'HIGH', color: '#f59e0b' };
  if (score >= 30) return { label: 'MODERATE', color: '#eab308' };
  if (score >= 15) return { label: 'LOW', color: '#3b82f6' };
  return { label: 'MINIMAL', color: '#22c55e' };
}

export default function RiskScore({ score }: RiskScoreProps) {
  const { label, color } = getRiskLevel(score);

  return (
    <div className="flex items-center gap-4">
      <div className="flex items-baseline gap-2">
        <span className="text-3xl font-bold font-mono text-text-primary">{score}</span>
        <span className="text-sm font-mono text-text-muted">/100</span>
      </div>

      <div className="flex-1 max-w-[200px]">
        <div className="h-2 bg-border rounded-full overflow-hidden">
          <div
            className="h-full rounded-full transition-all duration-1000 ease-out animate-progress"
            style={{
              width: `${score}%`,
              backgroundColor: color,
            }}
          />
        </div>
      </div>

      <span
        className="text-xs font-mono font-semibold tracking-wider"
        style={{ color }}
      >
        {label}
      </span>
    </div>
  );
}
