import type {
  ApiClient, Meta, RunSummary, RunDetail, SnapshotRow, RateRow, CorrelationRow,
  AttackerRow, MttdRow, H2Metric, Attempt, AlertLink, ImdsRequestCount, Compare, GapItem, Finding, DisplayNames,
} from './types';

const BASE = '/api/v1';

// 세션 쿠키로 호출 (credentials: 'include').
async function get<T>(path: string): Promise<T> {
  const res = await fetch(BASE + path, {
    credentials: 'include',
    headers: { Accept: 'application/json' },
  });
  if (res.status === 409) {
    throw new Error(`비-VALID 측정: 지표를 표시할 수 없습니다 (${path})`);
  }
  if (!res.ok) {
    throw new Error(`요청 실패 ${res.status}: ${path}`);
  }
  return (await res.json()) as T;
}

function qs(params: Record<string, string | number | undefined>): string {
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== '') u.set(k, String(v));
  }
  const s = u.toString();
  return s ? `?${s}` : '';
}

export const httpClient: ApiClient = {
  getMeta: () => get<Meta>('/meta'),
  getRuns: () => get<RunSummary[]>('/runs'),
  getRun: (runId) => get<RunDetail>(`/runs/${encodeURIComponent(runId)}`),
  getSnapshot: (definitionVersion, runId) =>
    get<SnapshotRow[]>(`/snapshot${qs({ definition_version: definitionVersion, run_id: runId })}`),
  getRates: (runId) => get<RateRow[]>(`/runs/${encodeURIComponent(runId)}/metrics/rates`),
  getCoverage: (runId) => get<RateRow[]>(`/runs/${encodeURIComponent(runId)}/metrics/coverage`),
  getCorrelation: (runId) => get<CorrelationRow[]>(`/runs/${encodeURIComponent(runId)}/metrics/correlation`),
  getAttacker: (runId) => get<AttackerRow[]>(`/runs/${encodeURIComponent(runId)}/metrics/attacker`),
  getMttd: (runId) => get<MttdRow[]>(`/runs/${encodeURIComponent(runId)}/metrics/mttd`),
  getH2: (runId) => get<H2Metric>(`/runs/${encodeURIComponent(runId)}/metrics/h2`),
  getAttempts: (runId, opts = {}) =>
    get<Attempt[]>(`/runs/${encodeURIComponent(runId)}/attempts${qs({ verdict: opts.verdict, limit: opts.limit })}`),
  getAlertLinks: (runId, limit) =>
    get<AlertLink[]>(`/runs/${encodeURIComponent(runId)}/alert-links${qs({ limit })}`),
  getImdsRequests: (runId) =>
    get<ImdsRequestCount>(`/runs/${encodeURIComponent(runId)}/imds-requests`),
  getCompare: (before, after) => get<Compare>(`/compare${qs({ before, after })}`),
  getNavigatorLayer: (runId, layer) =>
    get<unknown>(`/navigator-layer${qs({ run_id: runId, layer })}`),
  getGaps: () => get<GapItem[]>('/content/gaps'),
  getFindings: () => get<Finding[]>('/content/findings'),
  getDisplayNames: () => get<DisplayNames>('/content/display-names'),
};
