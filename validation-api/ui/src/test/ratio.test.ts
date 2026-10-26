import { describe, it, expect } from 'vitest';
import {
  wilson, ratioBlock, diffVerdict, diffVerdictLabel, diffMain, pct, pctRange, isDisplayable,
} from '../lib/ratio';

describe('Wilson 픽스처 (ADR 지정값)', () => {
  it('20/20 하한 83.9%', () => {
    const w = wilson(20, 20)!;
    expect(+(w.lo * 100).toFixed(1)).toBe(83.9);
  });
  it('0/20 상한 16.1%', () => {
    const w = wilson(0, 20)!;
    expect(+(w.hi * 100).toFixed(1)).toBe(16.1);
  });
  it('140/140 하한 97.3%', () => {
    const w = wilson(140, 140)!;
    expect(+(w.lo * 100).toFixed(1)).toBe(97.3);
  });
  it('120/140 범위 79.0–90.6%', () => {
    const w = wilson(120, 140)!;
    expect(+(w.lo * 100).toFixed(1)).toBe(79.0);
    expect(+(w.hi * 100).toFixed(1)).toBe(90.6);
  });
  it('n=0 이면 null', () => {
    expect(wilson(0, 0)).toBeNull();
  });
});

describe('R-b 포맷터: % 단독 금지', () => {
  const cases = [
    { x: 140, n: 140 },
    { x: 20, n: 20 },
    { x: 0, n: 20 },
    { x: 76, n: 300 },
  ];
  it('ratio 종류는 항상 보조문구(aux)를 동반한다 (% 단독 0건)', () => {
    for (const c of cases) {
      const m = ratioBlock(c);
      expect(m.kind).toBe('ratio');
      expect(m.primary.endsWith('%')).toBe(true);
      expect(m.aux).not.toBeNull();
      expect(m.aux!).toContain('건 중');
      expect(m.aux!).toContain('95% 신뢰도');
    }
  });
});

describe('n=0 문구', () => {
  it('"해당 없음(n=0)" 으로 표시', () => {
    const m = ratioBlock({ x: 0, n: 0 });
    expect(m.kind).toBe('na-zero');
    expect(m.primary).toBe('해당 없음(n=0)');
    expect(m.aux).toBeNull();
  });
});

describe('차단류(IDS 모드)', () => {
  it('"N/A(IDS 모드)"', () => {
    const m = ratioBlock({ x: 0, n: 100, blocked: true });
    expect(m.kind).toBe('blocked');
    expect(m.primary).toBe('N/A(IDS 모드)');
  });
});

describe('비-VALID 미표시', () => {
  it('VALID 가 아니면 수치를 표시하지 않는다', () => {
    const m = ratioBlock({ x: 20, n: 20, status: 'INVALID' });
    expect(m.kind).toBe('not-valid');
    expect(m.primary).not.toContain('%');
    expect(m.aux).toBe('측정이 VALID 가 아님');
    expect(isDisplayable('INVALID')).toBe(false);
    expect(isDisplayable('VALID')).toBe(true);
  });
  it('VALID 이면 표시', () => {
    const m = ratioBlock({ x: 20, n: 20, status: 'VALID' });
    expect(m.kind).toBe('ratio');
  });
});

describe('차이 해석: 95% 신뢰도가 0 을 지나면 "차이 불확실"', () => {
  it('lo<0<hi → uncertain', () => {
    expect(diffVerdict(-0.1, 0.2)).toBe('uncertain');
    expect(diffVerdictLabel(diffVerdict(-0.1, 0.2))).toBe('차이 불확실');
  });
  it('둘 다 음수 → decrease (불확실 아님)', () => {
    expect(diffVerdict(-1.0, -0.772)).toBe('decrease');
    expect(diffVerdictLabel(diffVerdict(-1.0, -0.772))).not.toBe('차이 불확실');
  });
  it('둘 다 양수 → increase', () => {
    expect(diffVerdict(0.1, 0.5)).toBe('increase');
  });
  it('경계(0 포함) → uncertain', () => {
    expect(diffVerdict(0, 0.3)).toBe('uncertain');
    expect(diffVerdict(-0.3, 0)).toBe('uncertain');
  });
});

describe('Before/After 주표시 (Newcombe)', () => {
  it('-100%p · 95% 신뢰도 -100 ~ -77.2%p', () => {
    expect(diffMain(-1.0, -1.0, -0.772)).toBe('-100%p · 95% 신뢰도 -100 ~ -77.2%p');
  });
});

describe('퍼센트 포맷', () => {
  it('정수는 소수점 없이', () => {
    expect(pct(1)).toBe('100');
    expect(pct(0)).toBe('0');
  });
  it('소수 1자리', () => {
    expect(pct(0.857143)).toBe('85.7');
  });
  it('범위 표기(en-dash)', () => {
    expect(pctRange(0.973, 1)).toBe('97.3–100');
  });
});
