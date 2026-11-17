/** OutisCloud design system — Tailwind binding.
 *  Clinical Blueprint on Frosted Paper: monochrome ink on paper, one ember
 *  accent reserved for destructive/error states. Colours come from CSS
 *  variables (src/index.css) so utilities and legacy `primary-*` / `gray-*`
 *  classes follow the active theme without carrying decorative colour. */
const v = (name) => `rgb(var(--${name}) / <alpha-value>)`;
const scale = (prefix, steps) => Object.fromEntries(steps.map((s) => [s, v(`${prefix}-${s}`)]));
const STEPS = [50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 950];

/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx,ts,tsx}"],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        primary: scale('p', STEPS),
        gray: scale('g', STEPS),
        secondary: { 400: '#a3a3a3', 500: '#737373', 600: '#171717' },
        violet: { 400: '#a3a3a3', 500: '#737373', 600: '#171717' },
        success: scale('ok', [50, 100, 200, 300, 400, 500, 600, 700, 800, 900]),
        warning: scale('wn', [50, 100, 200, 300, 400, 500, 600, 700, 800, 900]),
        danger: scale('er', [50, 100, 200, 300, 400, 500, 600, 700, 800, 900]),
        app: v('bg'),
        surface: v('surface'),
        'surface-2': v('surface-2'),
        line: v('line'),
        ink: v('ink'),
        muted: v('muted'),
        accent: v('accent'),
        'on-accent': v('on-accent'),
      },
      fontFamily: {
        sans: ['Geist', 'Inter', 'Vazirmatn', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
        display: ['Geist', 'Inter', 'Vazirmatn', 'system-ui', 'sans-serif'],
        mono: ['"Geist Mono"', '"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      borderRadius: {
        sm: '6px', md: '10px', lg: '14px', xl: '18px', '2xl': '24px', '3xl': '24px',
      },
      boxShadow: {
        card: '0 1px 2px 0 rgb(0 0 0 / 0.025), 0 16px 40px -32px rgb(0 0 0 / var(--shadow-a))',
        pop: '0 24px 64px -24px rgb(0 0 0 / 0.32), 0 4px 16px -8px rgb(0 0 0 / 0.12)',
        glow: '0 0 0 1px rgb(var(--ink) / 0.10)',
      },
      animation: {
        'fade-in': 'fadeIn 0.18s ease-out',
        'slide-in': 'slideIn 0.24s ease-out',
        'flow': 'flow 14s linear infinite',
      },
      keyframes: {
        fadeIn: { '0%': { opacity: '0' }, '100%': { opacity: '1' } },
        slideIn: { '0%': { transform: 'translateY(-6px)', opacity: '0' }, '100%': { transform: 'translateY(0)', opacity: '1' } },
        flow: { '0%': { strokeDashoffset: '0' }, '100%': { strokeDashoffset: '-400' } },
      },
    },
  },
  plugins: [],
}
