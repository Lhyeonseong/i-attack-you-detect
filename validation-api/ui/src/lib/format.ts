// 공통 포맷/용어(R-i). "Run"→"측정", "관제 탐지"→"탐지" (센서명 "앱 로그 관제"·"네트워크 관제"는 유지).

export const TERMS = {
  measurement: '측정',
  detection: '탐지',
  sensorApp: '앱 로그 관제',
  sensorNet: '네트워크 관제',
  sensorBackend: '백엔드 상관',
} as const;

/** KST(Asia/Seoul) 로 표시. */
export function kst(iso: string | null | undefined): string {
  if (!iso) return '기록 없음';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return new Intl.DateTimeFormat('ko-KR', {
    timeZone: 'Asia/Seoul',
    year: 'numeric', month: 'long', day: 'numeric',
    hour: 'numeric', minute: '2-digit', second: '2-digit',
    hour12: true,
  }).format(d);
}

/** KST 짧은 표시(날짜만). */
export function kstDate(iso: string | null | undefined): string {
  if (!iso) return '기록 없음';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return new Intl.DateTimeFormat('ko-KR', {
    timeZone: 'Asia/Seoul',
    year: 'numeric', month: 'long', day: 'numeric',
  }).format(d);
}

export function short8(id: string | null | undefined): string {
  if (!id) return '기록 없음';
  return id.slice(0, 8);
}

export function short12(id: string | null | undefined): string {
  if (!id) return '기록 없음';
  return id.slice(0, 12);
}
