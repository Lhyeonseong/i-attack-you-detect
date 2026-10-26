// 백엔드 enum → 화면 표시 라벨/배지. 색 단독 금지 → 모든 배지에 텍스트 병기.
import type { Attempt } from '../api/types';

export interface ScenarioMeta { name: string; desc: string }

export const SCENARIO: Record<string, ScenarioMeta> = {
  SQLI: { name: 'SQL 인젝션', desc: '따옴표 주입으로 SQL 오류 유도' },
  PATH_TRAVERSAL: { name: '경로 조작', desc: '업로드 폴더 밖 파일 요청' },
  SSRF: { name: 'SSRF', desc: '메타데이터 주소 169.254.169.254 요청' },
  BRUTE_FORCE: { name: '무차별 대입', desc: '로그인 실패 반복 후 성공 시도' },
};

const ABILITY_OVERRIDE: Record<string, ScenarioMeta> = {
  ssrf_control: { name: '대조 요청', desc: '정상 주소 example.com 요청 · 공격 아님' },
  path_traversal_1: { name: '경로 조작', desc: '업로드 폴더 밖 파일 요청 · 변형 1' },
  path_traversal_2: { name: '경로 조작', desc: '업로드 폴더 밖 파일 요청 · 변형 2' },
};

export function scenarioMeta(a: Pick<Attempt, 'scenario' | 'ability_id'>): ScenarioMeta {
  return ABILITY_OVERRIDE[a.ability_id] ?? SCENARIO[a.scenario] ?? { name: a.scenario, desc: a.ability_id };
}

export type BadgeClass = 'b-ok' | 'b-at' | 'b-dg' | 'b-nu';
export interface BadgeModel { text: string; cls: BadgeClass }

export function gtBadge(a: Pick<Attempt, 'attempt_role' | 'gt_outcome'>): BadgeModel {
  if (a.attempt_role === 'CONTROL') return { text: '실패', cls: 'b-nu' };
  return a.gt_outcome === 'SUCCEEDED' ? { text: '성공', cls: 'b-at' } : { text: '실패', cls: 'b-nu' };
}

export function detectionBadge(a: Pick<Attempt, 'detection_status'>): BadgeModel {
  switch (a.detection_status) {
    case 'DETECTED': return { text: '탐지됨', cls: 'b-ok' };
    case 'LATE': return { text: '늦은 탐지', cls: 'b-at' };
    case 'UNSEEN': return { text: '알림 없음', cls: 'b-nu' };
    default: return { text: '기록 없음', cls: 'b-nu' };
  }
}

export function verdictBadge(a: Pick<Attempt, 'verdict'>): BadgeModel {
  switch (a.verdict) {
    case 'SUCCEEDED_DETECTED': return { text: '성공 · 탐지', cls: 'b-ok' };
    case 'SUCCEEDED_MISSED': return { text: '성공 · 놓침', cls: 'b-dg' };
    case 'FAILED_DETECTED': return { text: '실패 · 탐지', cls: 'b-ok' };
    case 'FAILED_UNSEEN': return { text: '실패 · 안 보임', cls: 'b-nu' };
    default: return { text: '판정 불가', cls: 'b-nu' };
  }
}

export const TECH_NAME: Record<string, string> = {
  T1190: 'Exploit Public-Facing Application',
  T1110: 'Brute Force · 무차별 대입',
};
