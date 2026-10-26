// validation-api 응답 타입 (JSON 은 snake_case). baseURL = /api/v1
// 비-VALID run 은 409. n=0 이면 p·lo·hi(또는 p50/p95) 는 null.

export type RunStatus = 'VALID' | 'INVALID' | 'PENDING' | 'RUNNING' | string;
export type MetricStatus = 'VALID' | 'INSUFFICIENT' | 'NA' | 'BLOCKED' | string;

export interface NavigatorMeta {
  attack: string;
  navigator: string;
  layer: string;
}

export interface Meta {
  definition_versions: string[];
  latest_definition_version: string;
  run_count: number;
  navigator: NavigatorMeta;
}

export interface RunSummary {
  run_id: string;
  label: string;
  kind: string;
  status: RunStatus;
  started_at: string;
  ended_at: string;
  git_commit: string;
  git_dirty: boolean;
  integrity_status: string;
  expected_attempts: number | null;
  expected_controls: number | null;
}

export interface ProvenanceItem {
  item: string;
  value: string;
  source_file: string;
  source_line: number;
}

export interface RunDetail extends RunSummary {
  definition_versions: string[];
  provenance: ProvenanceItem[];
}

export interface SnapshotRow {
  metric_id: string;
  scope_kind: string;
  scope_key: string;
  x: number | null;
  n: number;
  p: number | null;
  lo: number | null;
  hi: number | null;
  p50_ms: number | null;
  p95_ms: number | null;
  status: MetricStatus;
  definition_version: string;
  snapshot_rule_version: string;
}

// GET /runs/{runId}/metrics/{name}
export interface RateRow {
  metric_id: string;
  scope_kind: string;
  scope_key: string;
  x: number | null;
  n: number;
  p: number | null;
  lo: number | null;
  hi: number | null;
  status: MetricStatus;
  definition_version: string;
}

export interface CorrelationRow {
  scope_kind: string;
  scope_key: string;
  source: string;
  x: number | null;
  n: number;
  p: number | null;
  lo: number | null;
  hi: number | null;
  status: MetricStatus;
  definition_version: string;
}

export interface AttackerRow {
  scope_kind: string;
  scope_key: string;
  x: number | null;
  n: number;
  p: number | null;
  lo: number | null;
  hi: number | null;
  overestimate: number;
  uncertain: number;
  criteria_met: boolean;
  status: MetricStatus;
  definition_version: string;
}

export interface MttdRow {
  scope_kind: string;
  scope_key: string;
  n: number;
  p50_ms: number | null;
  p95_ms: number | null;
  status: MetricStatus;
  definition_version: string;
}

export interface H2Metric {
  n: number;
  rid_header_x: number | null;
  rid_header_p: number | null;
  rid_header_lo: number | null;
  rid_header_hi: number | null;
  none_x: number | null;
  none_p: number | null;
  none_lo: number | null;
  none_hi: number | null;
  status: MetricStatus;
  definition_version: string;
}

export type MetricName = 'rates' | 'coverage' | 'correlation' | 'attacker' | 'mttd' | 'h2';

export interface Attempt {
  attempt_id: string;
  unit_key: string;
  scenario: string;
  technique_id: string;
  attempt_role: string;
  gt_outcome: string;
  attacker_verdict: string;
  attacker_match: boolean;
  verdict: string;
  initial_verdict: string;
  detection_status: string;
  mttd_ms: number | null;
  best_confidence: number | null;
  late_detection: boolean;
  engine_version: string;
  decided_at: string;
  op_id: string;
  rid: string;
  ability_id: string;
  attack_time: string;
  correlation_source: string;
}

export interface AlertLink {
  run_id: string;
  attempt_id: string;
  rid: string;
  rule_id: string;
  control: string;
  alert_time: string;
  match_path: string;
  confidence: number | null;
}

export interface ImdsRequestCount {
  request_count: number;
}

export interface CompareRow {
  metric_id: string;
  scope_kind: string;
  scope_key: string;
  definition_version: string;
  x1: number;
  n1: number;
  x2: number;
  n2: number;
  diff: number;
  lo: number;
  hi: number;
}

export interface Compare {
  before: string;
  after: string;
  shared_definition_versions: string[];
  rows: CompareRow[];
}

export interface GapItem {
  id: string;
  title: string;
  detail: string;
  control: string;
  found_run: string;
  found_note: string;
  fix: string;
  fix_note: string;
  reval_run: string;
  reval_note: string;
  status: string;
}

export interface Finding {
  id: string;
  title: string;
  location: string;
  description: string;
  impact: string;
  tags: string[];
  kisa: string;
  target_status: string;
  detection: string;
  remediation: string;
  detection_followup: string;
  technique_id: string;
}

export type DisplayNames = Record<string, string>;

export interface ApiClient {
  getMeta(): Promise<Meta>;
  getRuns(): Promise<RunSummary[]>;
  getRun(runId: string): Promise<RunDetail>;
  getSnapshot(definitionVersion: string, runId: string): Promise<SnapshotRow[]>;
  getRates(runId: string): Promise<RateRow[]>;
  getCoverage(runId: string): Promise<RateRow[]>;
  getCorrelation(runId: string): Promise<CorrelationRow[]>;
  getAttacker(runId: string): Promise<AttackerRow[]>;
  getMttd(runId: string): Promise<MttdRow[]>;
  getH2(runId: string): Promise<H2Metric>;
  getAttempts(runId: string, opts?: { verdict?: string; limit?: number }): Promise<Attempt[]>;
  getAlertLinks(runId: string, limit?: number): Promise<AlertLink[]>;
  getImdsRequests(runId: string): Promise<ImdsRequestCount>;
  getCompare(before: string, after: string): Promise<Compare>;
  getNavigatorLayer(runId: string, layer: 'detection' | 'visibility'): Promise<unknown>;
  getGaps(): Promise<GapItem[]>;
  getFindings(): Promise<Finding[]>;
  getDisplayNames(): Promise<DisplayNames>;
}
