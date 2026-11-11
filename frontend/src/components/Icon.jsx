// A small, consistent icon set (24px grid, 1.7 stroke). Drawn for lasy; no icon library.
const P = {
  projects: <path d="M3.5 7.5a2 2 0 0 1 2-2h3.6l2 2.2h7.4a2 2 0 0 1 2 2V17a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2z" />,
  overview: <><rect x="4" y="4" width="6.5" height="6.5" rx="1.7" /><rect x="13.5" y="4" width="6.5" height="6.5" rx="1.7" /><rect x="4" y="13.5" width="6.5" height="6.5" rx="1.7" /><rect x="13.5" y="13.5" width="6.5" height="6.5" rx="1.7" /></>,
  scan: <><circle cx="12" cy="12" r="8.5" /><circle cx="12" cy="12" r="4.2" /><path d="M12 12l5.2-5.2" /></>,
  network: <><circle cx="12" cy="5.5" r="2.2" /><circle cx="5.5" cy="18" r="2.2" /><circle cx="18.5" cy="18" r="2.2" /><path d="M12 7.7v3.3M12 11l-5 5M12 11l5 5" /></>,
  server: <><rect x="4" y="4.5" width="16" height="6" rx="2" /><rect x="4" y="13.5" width="16" height="6" rx="2" /><path d="M8 7.5h.01M8 16.5h.01" /></>,
  pulse: <path d="M3 12h4l2.2-6 4.2 12 2.4-6H21" />,
  shield: <path d="M12 3.5l7.5 2.8v5.4c0 4.4-3.1 7.6-7.5 8.8-4.4-1.2-7.5-4.4-7.5-8.8V6.3z" />,
  list: <><path d="M9 6.5h11M9 12h11M9 17.5h11" /><path d="M4.5 6.5h.01M4.5 12h.01M4.5 17.5h.01" /></>,
  search: <><circle cx="10.5" cy="10.5" r="6.5" /><path d="M15.5 15.5L20 20" /></>,
  sliders: <><path d="M4 7h9M17 7h3M4 17h3M11 17h9" /><circle cx="15" cy="7" r="2" /><circle cx="9" cy="17" r="2" /></>,
  trash: <path d="M4.5 7h15M9.5 7V4.8h5V7M6.5 7l.8 11.2a2 2 0 0 0 2 1.8h5.4a2 2 0 0 0 2-1.8L17.5 7M10 11v6M14 11v6" />,
  chevron: <path d="M9 6l6 6-6 6" />,
  back: <path d="M15 6l-6 6 6 6" />,
  plus: <path d="M12 5v14M5 12h14" />,
  collapse: <path d="M14 6l-5 6 5 6" />,
  expand: <path d="M10 6l5 6-5 6" />,
  menu: <path d="M4 7h16M4 12h16M4 17h16" />,
  x: <path d="M6 6l12 12M18 6L6 18" />,
}

export function Icon({ name, size = 18, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"
      className={className} aria-hidden="true" focusable="false">{P[name]}</svg>
  )
}
