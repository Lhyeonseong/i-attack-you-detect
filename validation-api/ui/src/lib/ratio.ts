// 표시 규칙(ADR-S4-04) 구현. 비율은 R-b 로만 표시(% 단독 금지).
// 숫자는 여기 정의된 Wilson/Newcombe 로만 계산한다(지어내지 않음).

export const Z_95 = 1.959963984540054;

/** Wilson score interval. x 성공 / n 시도. 비율(0..1)로 lo·hi 반환. n=0 이면 null. */
export function wilson(x: number, n: number, z: number = Z_95): { lo: number; hi: number } | null {
  if (!Number.isFinite(x) || !Number.isFinite(n) || n <= 0) return null;
  const p = x / n;
  const z2 = z * z;
  const denom = 1 + z2 / n;
  const center = (p + z2 / (2 * n)) / denom;
  const half = (z * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n))) / denom;
  return { lo: clamp01(center - half), hi: clamp01(center + half) };
}

function clamp01(v: number): number {
  if (v < 0) return 0;
  if (v > 1) return 1;
  return v;
}

/** 비율(0..1)을 퍼센트 문자열로. 소수 1자리, 불필요한 .0 제거. */
export function pct(p: number, digits = 1): string {
  const v = p * 100;
  const s = v.toFixed(digits);
  return s.replace(/\.0+$/, '');
}

/** "a–b" (en-dash) 퍼센트 범위. */
export function pctRange(lo: number, hi: number, digits = 1): string {
  return `${pct(lo, digits)}–${pct(hi, digits)}`;
}

/** 측정 지표가 표시 가능한지(VALID 만 표시). 비-VALID 미표시. */
export function isDisplayable(status: string | null | undefined): boolean {
  return status === 'VALID';
}

export type RatioKind = 'ratio' | 'na-zero' | 'blocked' | 'not-valid';

export interface RatioBlockModel {
  kind: RatioKind;
  /** 큰 글씨 주값(% 또는 안내문). */
  primary: string;
  /** 보조 문구("x건 중 y건 · 95% 신뢰도 a–b%"). 없으면 null. */
  aux: string | null;
  /** 접근성 라벨("x건 중 y건"). */
  ariaCount: string;
}

export interface RatioInput {
  x: number | null;
  n: number;
  lo?: number | null;
  hi?: number | null;
  p?: number | null;
  status?: string | null;
  /** 차단류(IDS 모드) → "N/A(IDS 모드)". */
  blocked?: boolean;
}

/**
 * R-b 모델 생성. % 는 절대 단독으로 반환하지 않는다(aux 동반).
 * - n=0 → "해당 없음(n=0)"
 * - blocked → "N/A(IDS 모드)"
 * - 비-VALID → 미표시
 */
export function ratioBlock(input: RatioInput): RatioBlockModel {
  const { x, n, status, blocked } = input;

  if (blocked) {
    return { kind: 'blocked', primary: 'N/A(IDS 모드)', aux: null, ariaCount: 'N/A(IDS 모드)' };
  }
  if (status !== undefined && status !== null && !isDisplayable(status)) {
    return { kind: 'not-valid', primary: '표시 안 함', aux: '측정이 VALID 가 아님', ariaCount: '표시 안 함' };
  }
  if (!n || n <= 0) {
    return { kind: 'na-zero', primary: '해당 없음(n=0)', aux: null, ariaCount: '해당 없음(n=0)' };
  }

  const xv = x ?? 0;
  const p = input.p ?? xv / n;
  const ci = input.lo != null && input.hi != null
    ? { lo: input.lo, hi: input.hi }
    : wilson(xv, n);
  const ariaCount = `${n}건 중 ${xv}건`;
  const rangeText = ci ? ` · 95% 신뢰도 ${pctRange(ci.lo, ci.hi)}%` : '';
  return {
    kind: 'ratio',
    primary: `${pct(p)}%`,
    aux: `${ariaCount}${rangeText}`,
    ariaCount,
  };
}

export type DiffVerdict = 'decrease' | 'increase' | 'uncertain';

/** 차이 해석. 95% 신뢰도가 0 을 지나면 "차이 불확실". */
export function diffVerdict(lo: number, hi: number): DiffVerdict {
  if (lo <= 0 && hi >= 0) return 'uncertain';
  return hi < 0 ? 'decrease' : 'increase';
}

export function diffVerdictLabel(v: DiffVerdict): string {
  switch (v) {
    case 'uncertain': return '차이 불확실';
    case 'decrease': return '감소';
    case 'increase': return '증가';
  }
}

/** Before/After 주표시: "diff%p · 95% 신뢰도 lo ~ hi%p" (Newcombe). diff/lo/hi 는 비율차(−1..1). */
export function diffMain(diff: number, lo: number, hi: number, digits = 1): string {
  const pp = (v: number) => {
    const s = (v * 100).toFixed(digits).replace(/\.0+$/, '');
    return s;
  };
  const sign = diff > 0 ? '+' : '';
  return `${sign}${pp(diff)}%p · 95% 신뢰도 ${pp(lo)} ~ ${pp(hi)}%p`;
}

/** ms → 초(소수 1자리). */
export function msToSec(ms: number | null | undefined, digits = 1): string {
  if (ms == null || !Number.isFinite(ms)) return '기록 없음';
  return `${(ms / 1000).toFixed(digits)}초`;
}

export const NO_RECORD = '기록 없음';
