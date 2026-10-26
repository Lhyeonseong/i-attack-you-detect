import { describe, it, expect } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { RatioBlock } from '../components/RatioBlock';
import { TERMS } from '../lib/format';
import { SCENARIO, TECH_NAME, gtBadge, detectionBadge, verdictBadge } from '../lib/labels';

// 화면에 노출되는 라벨 문자열을 모아 용어(R-i) 검증.
function collectLabels(): string {
  const parts: string[] = [];
  parts.push(...Object.values(TERMS));
  for (const s of Object.values(SCENARIO)) { parts.push(s.name, s.desc); }
  parts.push(...Object.values(TECH_NAME));
  const sampleVerdicts = ['SUCCEEDED_DETECTED', 'SUCCEEDED_MISSED', 'FAILED_UNSEEN'];
  const sampleDet = ['DETECTED', 'UNSEEN', 'LATE'];
  for (const v of sampleVerdicts) parts.push(verdictBadge({ verdict: v }).text);
  for (const d of sampleDet) parts.push(detectionBadge({ detection_status: d }).text);
  parts.push(gtBadge({ attempt_role: 'ATTACK', gt_outcome: 'SUCCEEDED' }).text);
  parts.push(gtBadge({ attempt_role: 'CONTROL', gt_outcome: 'FAILED' }).text);
  // R-b 렌더 결과도 포함
  parts.push(renderToStaticMarkup(<RatioBlock x={140} n={140} status="VALID" label="탐지율" />));
  // 사이드바/상단바 라벨(Sidebar.tsx 와 동일 문자열)
  parts.push('개요', '공격 결과', '탐지 분석', 'ATT&CK 검증', '시스템 상태', '공백 · 재검증', '검증 결과', '보안 검증');
  // 공통 상단바 안내 라벨
  parts.push('확정 결과', '읽기 전용 연결');
  return parts.join(' || ');
}

describe('용어 규칙 (R-i)', () => {
  const text = collectLabels();

  it('"Run" 은 화면에 0건 (측정 으로 표기)', () => {
    expect(/\brun\b/i.test(text)).toBe(false);
    expect(text).toContain('측정');
  });

  it('"관제 탐지" 로 쓰지 않는다 (→ 탐지)', () => {
    expect(text).not.toContain('관제 탐지');
  });

  it('센서명 "앱 로그 관제" · "네트워크 관제" 는 유지', () => {
    expect(TERMS.sensorApp).toBe('앱 로그 관제');
    expect(TERMS.sensorNet).toBe('네트워크 관제');
  });

  it('종합 점수·등급 용어를 쓰지 않는다', () => {
    expect(text).not.toContain('종합 점수');
    expect(text).not.toContain('등급');
  });
});

describe('R-b 렌더: % 와 보조문구가 함께 나온다', () => {
  it('"x건 중 y건" 보조문구 포함', () => {
    const html = renderToStaticMarkup(<RatioBlock x={140} n={140} status="VALID" label="탐지율" />);
    expect(html).toContain('%');
    expect(html).toContain('140건 중 140건');
    expect(html).toContain('95% 신뢰도');
  });

  it('n=0 은 "해당 없음(n=0)"', () => {
    const html = renderToStaticMarkup(<RatioBlock x={0} n={0} />);
    expect(html).toContain('해당 없음(n=0)');
  });
});
