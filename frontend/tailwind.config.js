/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    // Breakpoints account for the sidebar: `nav` is where the sidebar appears, `lg` where two-column pages have room.
    screens: { sm: '640px', md: '860px', nav: '1100px', lg: '1280px', xl: '1600px', '2xl': '1920px' },
    extend: {
      colors: {
        // Surfaces and text come from CSS variables, so "Glass" and "Solid" are one switch (see index.css).
        bg: 'var(--c-bg)', surface: 'var(--c-surface)', raised: 'var(--c-raised)', line: 'var(--c-line)', line2: 'var(--c-line2)',
        ink: 'var(--c-ink)', mute: 'var(--c-mute)', faint: 'var(--c-faint)',
        brand: '#37B6A6', 'brand-dim': '#2A8A7E',
        crit: '#E5484D', high: '#F06A3F', med: '#E0A23B', low: '#4C8DD6', ok: '#45A06A',
      },
      fontFamily: {
        sans: ['"IBM Plex Sans"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'ui-monospace', 'monospace'],
      },
      borderRadius: { md: '8px', lg: '12px', xl: '14px', '2xl': '18px' },
    },
  },
  plugins: [],
}
