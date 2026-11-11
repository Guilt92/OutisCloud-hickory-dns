/** OutisCloud design system — Tailwind binding.
 *  Colours come from CSS variables (src/index.css) so every utility (including the legacy
 *  `gray-*` / `dark:` ones used across the pages) follows the active theme.
 *  Brand: electric yellow on deep ink; restrained blue and violet as secondary accents. */
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
        // brand accent (theme aware: bright yellow fills, readable ink-yellow text in light mode)
        primary: scale('p', STEPS),
        // neutrals: ink-tinted, used as surfaces / borders / text in both themes
        gray: scale('g', STEPS),
        // secondary accents (restrained)
        secondary: { 400: '#7C93FF', 500: '#5B7CFA', 600: '#4663E0' },
        violet: { 400: '#B18CFF', 500: '#9B6BFF', 600: '#7F4DE6' },
        success: scale('ok', [50, 100, 200, 300, 400, 500, 600, 700, 800, 900]),
        warning: scale('wn', [50, 100, 200, 300, 400, 500, 600, 700, 800, 900]),
        danger: scale('er', [50, 100, 200, 300, 400, 500, 600, 700, 800, 900]),
        // semantic surfaces
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
        sans: ['Inter', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
        display: ['"Space Grotesk"', 'Inter', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      borderRadius: { xl: '0.75rem', '2xl': '1rem' },
      boxShadow: {
        card: '0 1px 0 0 rgb(var(--line) / 0.6), 0 8px 24px -12px rgb(0 0 0 / var(--shadow-a))',
        pop: '0 16px 48px -16px rgb(0 0 0 / 0.55)',
        glow: '0 0 0 1px rgb(var(--accent) / 0.45), 0 0 32px -6px rgb(var(--accent) / 0.35)',
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
