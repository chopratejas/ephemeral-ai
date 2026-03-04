/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
      },
      colors: {
        bg: '#0a0a0f',
        surface: '#12121a',
        'surface-hover': '#181825',
        border: '#1e1e2e',
        'border-subtle': '#16161f',
        'text-primary': '#e4e4e7',
        'text-secondary': '#71717a',
        'text-muted': '#52525b',
        'accent-green': '#22c55e',
        'accent-red': '#ef4444',
        'accent-orange': '#f59e0b',
        'accent-blue': '#3b82f6',
        'accent-purple': '#8b5cf6',
      },
      fontSize: {
        '2xs': ['0.625rem', { lineHeight: '0.875rem' }],
      },
    },
  },
  plugins: [],
};
