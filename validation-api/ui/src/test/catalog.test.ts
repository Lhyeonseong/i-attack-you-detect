import { describe, it, expect } from 'vitest';
import { mockClient, RUN_IDS } from '../api/mock';

// 실제 백엔드가 내보내는 metric_id 카탈로그(ADR-S4-01). mock 은 이 안의 값만 써야 한다
// (가상 id 재발 방지 — 운영 fetch 시 매칭 실패로 화면이 빈값이 되는 버그를 막는다).
const CATALOG = new Set([
  'M01', 'M02', 'M03', 'M02_INITIAL', 'M03_INITIAL', 'M04', 'M05', 'M06a', 'M06b',
  'M07a_APP_LOG', 'M07a_NIDS', 'M07b', 'M08', 'M10', 'M12',
  'M13_APP_RULE', 'M13_NIDS', 'M13_BACKEND_CORR',
  'M14a_APP_RULE', 'M14a_NIDS', 'M14a_BACKEND_CORR', 'M14b_APP_RULE', 'M14b_NIDS', 'M14b_BACKEND_CORR',
]);
const SCOPE_KIND = new Set(['ALL', 'SCENARIO', 'TECHNIQUE']);

describe('mock metric_id ⊆ 실제 카탈로그', () => {
  it('snapshot·rates·coverage 의 metric_id·scope_kind 가 실제 값', async () => {
    const rows: { metric_id: string; scope_kind: string }[] = [];
    for (const r of [RUN_IDS.after, RUN_IDS.before, RUN_IDS.benignWeb, RUN_IDS.benignLogin]) {
      rows.push(...(await mockClient.getSnapshot('', r)));
    }
    rows.push(...(await mockClient.getRates(RUN_IDS.after)));
    rows.push(...(await mockClient.getRates(RUN_IDS.before)));
    rows.push(...(await mockClient.getCoverage(RUN_IDS.after)));
    rows.push(...(await mockClient.getCoverage(RUN_IDS.before)));

    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      expect(CATALOG.has(row.metric_id), `허용되지 않은 metric_id: ${row.metric_id}`).toBe(true);
      expect(SCOPE_KIND.has(row.scope_kind), `허용되지 않은 scope_kind: ${row.scope_kind} (metric ${row.metric_id})`).toBe(true);
    }
  });

  it('M02 ALL 탐지율 = 개선 전 120/140 · 개선 후 140/140 (화면 경로)', async () => {
    const after = await mockClient.getSnapshot('', RUN_IDS.after);
    const before = await mockClient.getSnapshot('', RUN_IDS.before);
    const pick = (rows: typeof after) => rows.find((r) => r.metric_id === 'M02' && r.scope_kind === 'ALL');
    expect(pick(after)).toMatchObject({ x: 140, n: 140 });
    expect(pick(before)).toMatchObject({ x: 120, n: 140 });
  });
});
