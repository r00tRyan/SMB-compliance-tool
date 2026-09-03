import type { Config } from 'tailwindcss';

export default {
  content: ['./src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: '#f6f7f9',
        card: '#ffffff',
        ink: '#0f172a',
        muted: '#64748b',
        line: '#e2e8f0',
        brand: { DEFAULT: '#1d4ed8', soft: '#eff4ff' },
        sev: {
          critical: '#b91c1c',
          high: '#c2410c',
          medium: '#a16207',
          low: '#0369a1',
          info: '#475569',
          ok: '#15803d',
        },
      },
      fontFamily: {
        sans: ['ui-sans-serif', 'system-ui', '-apple-system', 'Segoe UI', 'Roboto', 'sans-serif'],
      },
    },
  },
  plugins: [],
} satisfies Config;
