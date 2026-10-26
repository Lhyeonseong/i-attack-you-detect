import { Link, useLocation } from 'react-router-dom';
import type { ReactNode } from 'react';

interface NavItem { to: string; label: string; icon: ReactNode; match: string[] }

const icon = {
  gauge: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" aria-hidden="true">
      <circle cx="12" cy="13" r="8"></circle><path d="M12 13l3-3M12 5V3"></path>
    </svg>
  ),
  grid: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
      <rect x="3" y="3" width="7" height="7" rx="1.5"></rect><rect x="14" y="3" width="7" height="7" rx="1.5"></rect>
      <rect x="3" y="14" width="7" height="7" rx="1.5"></rect><rect x="14" y="14" width="7" height="7" rx="1.5"></rect>
    </svg>
  ),
  bell: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" aria-hidden="true">
      <path d="M6 18V11a6 6 0 0 1 12 0v7M4 18h16M12 3v2"></path>
    </svg>
  ),
  bars: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" aria-hidden="true">
      <path d="M4 20V4M4 20h16M8 16v-4M12 16V8M16 16v-6"></path>
    </svg>
  ),
  server: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
      <rect x="4" y="3" width="16" height="18" rx="2"></rect><path d="M4 9h16M4 15h16"></path>
    </svg>
  ),
  refresh: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M20 12a8 8 0 1 1-2.3-5.7M20 4v4h-4"></path>
    </svg>
  ),
  doc: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M7 3h7l5 5v13H7z"></path><path d="M14 3v5h5M10 14l2 2 4-4"></path>
    </svg>
  ),
};

const screens: NavItem[] = [
  { to: '/overview', label: '개요', icon: icon.gauge, match: ['/overview'] },
  { to: '/attacks', label: '공격 결과', icon: icon.grid, match: ['/attacks', '/attempts'] },
  { to: '/detection', label: '탐지 분석', icon: icon.bell, match: ['/detection'] },
  { to: '/attck', label: 'ATT&CK 검증', icon: icon.bars, match: ['/attck'] },
  { to: '/system', label: '시스템 상태', icon: icon.server, match: ['/system'] },
];
const improve: NavItem[] = [
  { to: '/revalidate', label: '공백 · 재검증', icon: icon.refresh, match: ['/revalidate'] },
];
const result: NavItem[] = [
  { to: '/report', label: '검증 결과', icon: icon.doc, match: ['/report'] },
];

function NavGroup({ title, items, path }: { title: string; items: NavItem[]; path: string }) {
  return (
    <>
      <div className="sec">{title}</div>
      <nav className="nav" aria-label={title}>
        {items.map((it) => {
          const active = it.match.some((m) => path === m || path.startsWith(m + '/'));
          return (
            <Link key={it.to} to={it.to} className={active ? 'active' : undefined} aria-current={active ? 'page' : undefined}>
              {it.icon}{it.label}
            </Link>
          );
        })}
      </nav>
    </>
  );
}

export function Sidebar() {
  const { pathname } = useLocation();
  return (
    <aside className="sidebar">
      <div className="brand">
        <span className="bm" aria-hidden="true">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinejoin="round">
            <path d="M12 2 2 12l10 10 10-10z"></path><path d="M12 7 7 12l5 5 5-5z" fill="currentColor"></path>
          </svg>
        </span>
        <span><strong>ATT&amp;CK VALIDATOR</strong><small>CONTINUOUS SECURITY</small></span>
      </div>
      <NavGroup title="검증 화면" items={screens} path={pathname} />
      <NavGroup title="개선" items={improve} path={pathname} />
      <NavGroup title="결과" items={result} path={pathname} />
      <div className="sfoot"><span className="gdot"></span>검증 범위: 확정된 측정 결과</div>
    </aside>
  );
}
