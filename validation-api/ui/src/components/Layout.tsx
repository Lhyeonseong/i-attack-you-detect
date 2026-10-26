import type { ReactNode } from 'react';
import { Sidebar } from './Sidebar';
import { Provenance } from './Provenance';

interface Props {
  /** data-testid="screen-<id>" 의 id. */
  screenId: string;
  /** 상단바 제목(브레드크럼 끝). */
  title: string;
  /** 상단바 우측 안내 pill. */
  topNote: string;
  children: ReactNode;
  /** false 면 R-g 출처 줄을 숨김(상세 화면 등). 기본 true. */
  provenance?: boolean;
}

export function Layout({ screenId, title, topNote, children, provenance = true }: Props) {
  return (
    <div className="app">
      <Sidebar />
      <div className="ws">
        <header className="topbar">
          <div className="tl">
            <span className="tp">보안 검증</span>
            <span className="topbar-sep" aria-hidden="true">/</span>
            <strong>{title}</strong>
          </div>
          <span className="tnote">{topNote}</span>
        </header>
        <main className="main" data-testid={`screen-${screenId}`}>
          {children}
          {provenance ? <Provenance /> : null}
        </main>
      </div>
    </div>
  );
}
