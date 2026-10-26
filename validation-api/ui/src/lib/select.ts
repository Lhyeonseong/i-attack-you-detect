// 지표 배열에서 행을 고르는 보조 함수.
interface HasScope { scope_key: string; metric_id?: string; source?: string }

export function byScope<T extends HasScope>(rows: T[] | null | undefined, scopeKey: string): T | undefined {
  return rows?.find((r) => r.scope_key === scopeKey);
}

export function byMetricScope<T extends HasScope>(rows: T[] | null | undefined, metricId: string, scopeKey: string): T | undefined {
  return rows?.find((r) => r.metric_id === metricId && r.scope_key === scopeKey);
}

export function bySource<T extends HasScope>(rows: T[] | null | undefined, source: string, scopeKey?: string): T | undefined {
  return rows?.find((r) => r.source === source && (scopeKey === undefined || r.scope_key === scopeKey));
}
