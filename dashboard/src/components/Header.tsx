interface HeaderProps {
  stats?: unknown;
  onLogoClick: () => void;
}

function ShieldIcon() {
  return (
    <svg
      width="20"
      height="20"
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

export default function Header({ onLogoClick }: HeaderProps) {
  return (
    <header
      className="sticky top-0 z-50"
      style={{
        borderBottom: '1px solid rgba(30, 30, 46, 0.5)',
        background: 'rgba(10, 10, 15, 0.8)',
        backdropFilter: 'blur(12px)',
        WebkitBackdropFilter: 'blur(12px)',
      }}
    >
      <div className="max-w-7xl mx-auto px-6 flex items-center justify-between" style={{ height: '56px' }}>
        <button
          onClick={onLogoClick}
          className="flex items-center gap-2.5 hover:opacity-80 transition-opacity"
        >
          <ShieldIcon />
          <span
            className="font-semibold tracking-tight"
            style={{ fontSize: '15px', color: '#e4e4e7' }}
          >
            CodeScope
          </span>
        </button>

        <div className="flex items-center gap-1.5">
          <span
            className="rounded-full"
            style={{
              width: '6px',
              height: '6px',
              background: '#22c55e',
            }}
          />
          <span
            className="font-mono"
            style={{ fontSize: '12px', color: '#52525b' }}
          >
            operational
          </span>
        </div>
      </div>
    </header>
  );
}
