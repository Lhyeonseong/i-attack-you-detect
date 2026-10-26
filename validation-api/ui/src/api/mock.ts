// 개발용 가짜 데이터 — 운영 빌드 제외(import.meta.env.DEV 일 때만 사용).
// 실제 백엔드 API shape(metric_id·scope_kind·scope_key)와 동일하게 구성한다(dev==prod).
// 모든 수치는 스모크에서 확인된 실측값. 비율 CI 는 wilson() 로 계산. 없는 값은 null.
import type {
  ApiClient, Meta, RunSummary, RunDetail, SnapshotRow, RateRow, CorrelationRow,
  AttackerRow, MttdRow, H2Metric, Attempt, AlertLink, Compare, GapItem, Finding, DisplayNames,
} from './types';
import { wilson } from '../lib/ratio';

const DEF = 'ADR-S4-01 v1.7';       // ATTACK run 정의
const DEF_BENIGN = 'ADR-S4-01 v2.0'; // BENIGN run 정의
const SNAP_RULE = 'v1.6';

const RUN_AFTER = '805f3b8e-0000-0000-0000-000000000001';
const RUN_BEFORE = 'b1c26be1-0000-0000-0000-000000000002';
const RUN_BENIGN_WEB = '2ad849e0-0000-0000-0000-000000000003';
const RUN_BENIGN_LOGIN = '7fc9767f-0000-0000-0000-000000000004';

function ci(x: number, n: number): { p: number | null; lo: number | null; hi: number | null } {
  if (n <= 0) return { p: null, lo: null, hi: null };
  const w = wilson(x, n);
  return { p: x / n, lo: w ? w.lo : null, hi: w ? w.hi : null };
}

// ── RateRow / SnapshotRow 빌더 (실제 shape) ──────────────────────────────────
function rate(metricId: string, scopeKind: string, scopeKey: string, x: number, n: number, def = DEF): RateRow {
  const c = ci(x, n);
  return { metric_id: metricId, scope_kind: scopeKind, scope_key: scopeKey, x, n, p: c.p, lo: c.lo, hi: c.hi, status: n === 0 ? 'NO_DATA' : 'OK', definition_version: def };
}
function snapRate(r: RateRow): SnapshotRow {
  return { ...r, p50_ms: null, p95_ms: null, snapshot_rule_version: SNAP_RULE };
}
function snapMttd(scopeKind: string, scopeKey: string, n: number, p50: number, p95: number, def = DEF): SnapshotRow {
  return { metric_id: 'M04', scope_kind: scopeKind, scope_key: scopeKey, x: null, n, p: null, lo: null, hi: null, p50_ms: n ? p50 : null, p95_ms: n ? p95 : null, status: n === 0 ? 'NO_DATA' : 'OK', definition_version: def, snapshot_rule_version: SNAP_RULE };
}
function covRow(metricId: string, scopeKind: string, x: number, n: number, def = DEF): RateRow {
  const c = ci(x, n);
  // 커버리지는 scope_key 없음(실제 null) — 선택은 metric_id+scope_kind 로. 타입(string) 때문에 '' 사용.
  return { metric_id: metricId, scope_kind: scopeKind, scope_key: '', x, n, p: c.p, lo: c.lo, hi: c.hi, status: 'OK', definition_version: def };
}

const SCEN = ['SQLI', 'PATH_TRAVERSAL', 'SSRF', 'BRUTE_FORCE'] as const;
// 시나리오별 공격 수(S_ALL): SQLI 20, PT 60, SSRF 40, BF 20 = 140
const SCEN_N: Record<string, number> = { SQLI: 20, PATH_TRAVERSAL: 60, SSRF: 40, BRUTE_FORCE: 20 };
// 개선 전/후 탐지 수: 개선 전은 SQLI 0, 나머지 전부. 개선 후는 전부.
const detAfter: Record<string, number> = { SQLI: 20, PATH_TRAVERSAL: 60, SSRF: 40, BRUTE_FORCE: 20 };
const detBefore: Record<string, number> = { SQLI: 0, PATH_TRAVERSAL: 60, SSRF: 40, BRUTE_FORCE: 20 };

// ── rates (GET /runs/{id}/metrics/rates): M01·M02·M03, ALL + SCENARIO ──────────
function buildRates(det: Record<string, number>): RateRow[] {
  const detAll = SCEN.reduce((a, s) => a + det[s], 0);
  const rows: RateRow[] = [
    rate('M01', 'ALL', 'ALL', 140, 140),          // 공격 성공률 S_ALL/CONCL
    rate('M02', 'ALL', 'ALL', detAll, 140),       // 탐지율(주지표)
    rate('M03', 'ALL', 'ALL', 140 - detAll, 140), // 놓침률
  ];
  for (const s of SCEN) {
    rows.push(rate('M02', 'SCENARIO', s, det[s], SCEN_N[s]));
    rows.push(rate('M03', 'SCENARIO', s, SCEN_N[s] - det[s], SCEN_N[s]));
  }
  return rows;
}
const ratesAfter = buildRates(detAfter);
const ratesBefore = buildRates(detBefore);

// ── coverage (GET /metrics/coverage): M06a(존재)·M06b(일관), TECHNIQUE 2/2(개선후)·1/2(개선전) ──
const coverageAfter: RateRow[] = [
  covRow('M06a', 'TECHNIQUE', 2, 2), covRow('M06b', 'TECHNIQUE', 2, 2),
  covRow('M06a', 'ALL', 1, 1), covRow('M06b', 'ALL', 1, 1),
];
const coverageBefore: RateRow[] = [
  covRow('M06a', 'TECHNIQUE', 2, 2), covRow('M06b', 'TECHNIQUE', 1, 2),  // SQLI(T1190) 놓침 → 일관 1/2
  covRow('M06a', 'ALL', 1, 1), covRow('M06b', 'ALL', 0, 1),
];

// ── mttd (GET /metrics/mttd) ──────────────────────────────────────────────────
const mttdAfter: MttdRow[] = [
  { scope_kind: 'ALL', scope_key: 'ALL', n: 140, p50_ms: 690.5, p95_ms: 1090.9, status: 'OK', definition_version: DEF },
  { scope_kind: 'SCENARIO', scope_key: 'SQLI', n: 20, p50_ms: 641, p95_ms: 1076.9, status: 'OK', definition_version: DEF },
  { scope_kind: 'TECHNIQUE', scope_key: 'T1110', n: 20, p50_ms: 1018.5, p95_ms: 1271.25, status: 'OK', definition_version: DEF },
];
const mttdBefore: MttdRow[] = [
  { scope_kind: 'ALL', scope_key: 'ALL', n: 120, p50_ms: 1341, p95_ms: 1986.2, status: 'OK', definition_version: DEF },
];

// ── attacker (GET /metrics/attacker) ──────────────────────────────────────────
const attackerAfter: AttackerRow[] = [
  { scope_kind: 'ALL', scope_key: 'ALL', x: 140, n: 140, p: 1, lo: wilson(140, 140)!.lo, hi: wilson(140, 140)!.hi, overestimate: 0, uncertain: 0, criteria_met: true, status: 'OK', definition_version: DEF },
];

// ── correlation (GET /metrics/correlation): source 별 ──────────────────────────
function corr(scopeKind: string, scopeKey: string, source: string, x: number, n: number): CorrelationRow {
  const c = ci(x, n);
  return { scope_kind: scopeKind, scope_key: scopeKey, source, x, n, p: c.p, lo: c.lo, hi: c.hi, status: n === 0 ? 'NO_DATA' : 'OK', definition_version: DEF };
}
const correlationAfter: CorrelationRow[] = [
  corr('ALL', 'ALL', 'RID', 120, 140), corr('ALL', 'ALL', 'HEADER', 20, 140),
  corr('ALL', 'ALL', 'UA_FALLBACK', 0, 140), corr('ALL', 'ALL', 'NONE', 0, 140),
];
const correlationBefore = correlationAfter;

const h2After: H2Metric = {
  n: 140, rid_header_x: null, rid_header_p: null, rid_header_lo: null, rid_header_hi: null,
  none_x: null, none_p: null, none_lo: null, none_hi: null, status: 'OK', definition_version: DEF,
};

// ── snapshots (GET /snapshot) : run 별 ────────────────────────────────────────
function snapshotAttack(det: Record<string, number>, mttdAll: { p50: number; p95: number; n: number }): SnapshotRow[] {
  const detAll = SCEN.reduce((a, s) => a + det[s], 0);
  const rows: SnapshotRow[] = [
    snapRate(rate('M01', 'ALL', 'ALL', 140, 140)),
    snapRate(rate('M02', 'ALL', 'ALL', detAll, 140)),
    snapRate(rate('M03', 'ALL', 'ALL', 140 - detAll, 140)),
    snapMttd('ALL', 'ALL', mttdAll.n, mttdAll.p50, mttdAll.p95),
  ];
  for (const s of SCEN) {
    rows.push(snapRate(rate('M02', 'SCENARIO', s, det[s], SCEN_N[s])));
    rows.push(snapRate(rate('M03', 'SCENARIO', s, SCEN_N[s] - det[s], SCEN_N[s])));
  }
  // M13 통제별(SQLI): 앱룰 개선후 20/20·개선전 0/20, NIDS 0/20
  rows.push(snapRate(rate('M13_APP_RULE', 'SCENARIO', 'SQLI', det['SQLI'], 20)));
  rows.push(snapRate(rate('M13_NIDS', 'SCENARIO', 'SQLI', 0, 20)));
  rows.push(snapRate(rate('M07a_NIDS', 'SCENARIO', 'SQLI', 20, 20)));
  return rows;
}
const snapshotAfter = snapshotAttack(detAfter, { p50: 690.5, p95: 1090.9, n: 140 });
const snapshotBefore = snapshotAttack(detBefore, { p50: 1341, p95: 1986.2, n: 120 });

// benign web: M14a APP_RULE·NIDS 각 시나리오 0/320, M14b ALL 0/360
const snapshotBenignWeb: SnapshotRow[] = [
  ...['SQLI', 'PATH_TRAVERSAL', 'SSRF'].flatMap((s) => [
    snapRate(rate('M14a_APP_RULE', 'SCENARIO', s, 0, 320, DEF_BENIGN)),
    snapRate(rate('M14a_NIDS', 'SCENARIO', s, 0, 320, DEF_BENIGN)),
  ]),
  snapRate(rate('M14b_APP_RULE', 'ALL', 'ALL', 0, 360, DEF_BENIGN)),
  snapRate(rate('M14b_NIDS', 'ALL', 'ALL', 0, 163, DEF_BENIGN)),
];
// benign login: M14a BACKEND_CORR 0/300, NIDS 76/300, M14b BACKEND_CORR ALL 0/260
const snapshotBenignLogin: SnapshotRow[] = [
  snapRate(rate('M14a_BACKEND_CORR', 'SCENARIO', 'BRUTE_FORCE', 0, 300, DEF_BENIGN)),
  snapRate(rate('M14a_NIDS', 'SCENARIO', 'BRUTE_FORCE', 76, 300, DEF_BENIGN)),
  snapRate(rate('M14b_BACKEND_CORR', 'ALL', 'ALL', 0, 260, DEF_BENIGN)),
];

// ── compare (GET /compare): 모든 metric×scope. 주지표 M03 SCENARIO SQLI = −1.000 ──
const compare: Compare = {
  before: RUN_BEFORE, after: RUN_AFTER, shared_definition_versions: [DEF],
  rows: [
    { metric_id: 'M02', scope_kind: 'ALL', scope_key: 'ALL', definition_version: DEF, x1: 140, n1: 140, x2: 120, n2: 140, diff: 140 / 140 - 120 / 140, lo: 0.044, hi: 0.212 },
    { metric_id: 'M03', scope_kind: 'SCENARIO', scope_key: 'SQLI', definition_version: DEF, x1: 0, n1: 20, x2: 20, n2: 20, diff: -1.0, lo: -1.0, hi: -0.772 },
  ],
};

// ── run 메타 ───────────────────────────────────────────────────────────────────
function mkRun(run_id: string, label: string, kind: string, git_commit: string, def: string,
               expected_attempts: number | null, expected_controls: number | null, prov = true): RunDetail {
  return {
    run_id, label, kind, status: 'CLOSED', started_at: '2026-10-22T09:30:00+09:00', ended_at: '2026-10-22T10:00:00+09:00',
    git_commit, git_dirty: false, integrity_status: 'VALID', expected_attempts, expected_controls,
    definition_versions: [def],
    provenance: prov ? [
      { item: 'spring_boot', value: '4.1.1', source_file: 'detections/measurements/evidence/2026-10-21_reboot-verify.log', source_line: 2 },
      { item: 'wazuh', value: '4.14.9', source_file: 'detections/measurements/evidence/2026-10-21_reboot-verify.log', source_line: 2 },
      { item: 'suricata', value: '8.0.7', source_file: 'detections/measurements/evidence/2026-10-21_reboot-verify.log', source_line: 2 },
      { item: 'postgresql', value: '16.15', source_file: 'detections/measurements/evidence/2026-10-21_reboot-verify.log', source_line: 2 },
      { item: 'caldera', value: '5.2.0', source_file: 'detections/measurements/evidence/2026-10-20_4-caldera-pin.log', source_line: 2 },
    ] : [],
  };
}
const runAfter = mkRun(RUN_AFTER, 'S5-SQLI-AFTER', 'ATTACK', '2abc879', DEF, 140, 20);
const runBefore = mkRun(RUN_BEFORE, 'S4-STACK-6-BASELINE', 'ATTACK', 'e3b5f52', DEF, 140, 20);
const runBenignWeb = mkRun(RUN_BENIGN_WEB, 'S5-SQLI-AFTER-BENIGN-WEB', 'BENIGN', '2abc879', DEF_BENIGN, 960, 0);
const runBenignLogin = mkRun(RUN_BENIGN_LOGIN, 'S4-5-BENIGN-LOGIN', 'BENIGN', '3344d54', DEF_BENIGN, 300, 0);

const runsById: Record<string, RunDetail> = {
  [RUN_AFTER]: runAfter, [RUN_BEFORE]: runBefore, [RUN_BENIGN_WEB]: runBenignWeb, [RUN_BENIGN_LOGIN]: runBenignLogin,
};
const snapshotByRun: Record<string, SnapshotRow[]> = {
  [RUN_AFTER]: snapshotAfter, [RUN_BEFORE]: snapshotBefore,
  [RUN_BENIGN_WEB]: snapshotBenignWeb, [RUN_BENIGN_LOGIN]: snapshotBenignLogin,
};

// ── 시도 목록 ──────────────────────────────────────────────────────────────────
const AB: Record<string, { tech: string; scenario: string }> = {
  sqli_error_probe: { tech: 'T1190', scenario: 'SQLI' },
  path_traversal_1: { tech: 'T1190', scenario: 'PATH_TRAVERSAL' },
  path_traversal_2: { tech: 'T1190', scenario: 'PATH_TRAVERSAL' },
  brute_force: { tech: 'T1110', scenario: 'BRUTE_FORCE' },
  ssrf_metadata: { tech: 'T1190', scenario: 'SSRF' },
  ssrf_control: { tech: 'T1190', scenario: 'SSRF' },
};
function mkAttempt(id: string, time: string, rid: string, ability: string, role: 'ATTACK' | 'CONTROL',
                   gt: string, det: string, verdict: string, mttd: number | null, op: number, source: string): Attempt {
  const meta = AB[ability];
  return {
    attempt_id: id, unit_key: `${meta.scenario}-${op}`, scenario: meta.scenario, technique_id: meta.tech,
    attempt_role: role, gt_outcome: gt, attacker_verdict: gt, attacker_match: true, verdict, initial_verdict: verdict,
    detection_status: det, mttd_ms: mttd, best_confidence: det === 'DETECTED' ? 1.0 : null, late_detection: false,
    engine_version: 's4-v1', decided_at: time, op_id: `805f3b8e · op ${op}/20`, rid, ability_id: ability,
    attack_time: time, correlation_source: source,
  };
}
const attemptsAfter: Attempt[] = [
  mkAttempt('a-01', '2026-10-22T09:41:05+09:00', '7c1e…a90b', 'sqli_error_probe', 'ATTACK', 'SUCCEEDED', 'DETECTED', 'SUCCEEDED_DETECTED', 641, 20, 'RID'),
  mkAttempt('a-02', '2026-10-22T09:41:12+09:00', '2d04…13fe', 'path_traversal_1', 'ATTACK', 'SUCCEEDED', 'DETECTED', 'SUCCEEDED_DETECTED', 420, 20, 'RID'),
  mkAttempt('a-03', '2026-10-22T09:41:18+09:00', 'a3c9…5e21', 'path_traversal_2', 'ATTACK', 'SUCCEEDED', 'DETECTED', 'SUCCEEDED_DETECTED', 450, 20, 'RID'),
  mkAttempt('a-04', '2026-10-22T09:41:30+09:00', '91aa…c27d', 'brute_force', 'ATTACK', 'SUCCEEDED', 'DETECTED', 'SUCCEEDED_DETECTED', 1018, 20, 'HEADER'),
  mkAttempt('a-05', '2026-10-22T09:41:48+09:00', 'e5b2…07d1', 'ssrf_metadata', 'ATTACK', 'SUCCEEDED', 'DETECTED', 'SUCCEEDED_DETECTED', 700, 20, 'RID'),
  mkAttempt('a-06', '2026-10-22T09:41:52+09:00', '4f90…b6e2', 'ssrf_control', 'CONTROL', 'FAILED', 'NOT_DETECTED', 'FAILED_UNSEEN', null, 20, 'NONE'),
];
const attemptsBefore: Attempt[] = attemptsAfter.map((a) =>
  a.scenario === 'SQLI'
    ? { ...a, engine_version: 's3-v1', detection_status: 'NOT_DETECTED', verdict: 'SUCCEEDED_MISSED', initial_verdict: 'SUCCEEDED_MISSED', mttd_ms: null, best_confidence: null, correlation_source: 'NONE' }
    : { ...a, engine_version: 's3-v1' });

const alertLinksAfter: AlertLink[] = [
  { run_id: RUN_AFTER, attempt_id: 'a-01', rid: '7c1e…a90b', rule_id: '100211', control: 'app', alert_time: '2026-10-22T09:41:06+09:00', match_path: 'rid', confidence: 1.0 },
  { run_id: RUN_AFTER, attempt_id: 'a-02', rid: '2d04…13fe', rule_id: '100220', control: 'app', alert_time: '2026-10-22T09:41:13+09:00', match_path: 'rid', confidence: 1.0 },
  { run_id: RUN_AFTER, attempt_id: 'a-04', rid: '91aa…c27d', rule_id: 'BF 시퀀스', control: 'backend', alert_time: '2026-10-22T09:41:31+09:00', match_path: 'sequence', confidence: 1.0 },
  { run_id: RUN_AFTER, attempt_id: 'a-05', rid: 'e5b2…07d1', rule_id: '100240', control: 'app', alert_time: '2026-10-22T09:41:49+09:00', match_path: 'rid', confidence: 1.0 },
];

const gaps: GapItem[] = [
  { id: 'Gap #7', title: 'SQL 인젝션 미탐 · Gap #7', detail: '따옴표만 있는 주입 요청을 룰 100210이 놓침', control: '앱 로그', found_run: 'S4-STACK-6-BASELINE', found_note: '놓침 20 / 20', fix: '룰 100211 추가', fix_note: '4668e71', reval_run: 'S5-SQLI-AFTER', reval_note: '놓침 0 / 20', status: '해결' },
  { id: 'Gap #7n', title: 'SQL 인젝션 미탐 · Gap #7', detail: '네트워크 룰 1000013이 %27만 검색', control: '네트워크', found_run: 'S4-STACK-6-BASELINE', found_note: '0 / 20', fix: '—', fix_note: '', reval_run: 'S5-SQLI-AFTER', reval_note: '0 / 20', status: '잔존' },
  { id: 'Gap-login', title: '정상 로그인 오탐', detail: '룰 1000031 · 1000032를 HTTP 401 실패 응답 기반으로 보완했으며 일부 정상 오타는 잔존 오탐으로 측정', control: '네트워크', found_run: 'S4-5 login', found_note: '76 / 300', fix: 'HTTP 401 실패 응답 기반 탐지로 보완', fix_note: '', reval_run: '—', reval_note: '', status: '개선 예정' },
  { id: 'Gap-ssrf-ctrl', title: '대조 요청 성공 오판', detail: 'SSRF 대조(example.com)를 공격 성공으로 판단', control: '측정 도구', found_run: 'S5-SQLI-AFTER', found_note: '', fix: '—', fix_note: '', reval_run: '—', reval_note: '', status: '발견' },
];

const findings: Finding[] = [
  { id: 'V-01', title: 'SQL 인젝션', technique_id: 'T1190', location: '상품 검색 API · 검색어 입력값', kisa: 'SI · 상', target_status: '취약', description: '검색어가 SQL 문에 그대로 들어가 쿼리 구조를 바꿀 수 있습니다.', impact: '정답지가 SQL 오류 노출을 확인 · 20회 모두 성공 (주입 가능성 입증, 데이터 유출까지는 측정하지 않음)', tags: ['CWE-89', 'OWASP A05:2025 Injection', 'KISA SI (상)', 'ATT&CK T1190'], detection: '앱 로그 관제 20/20 탐지 (룰 100211 추가 후) · 네트워크 관제는 요청을 기록했지만 경보 0/20', remediation: '입력값 바인딩(Prepared Statement), 입력값 검증', detection_followup: '네트워크 룰 1000013 보완 · 다른 SQL 인젝션 변형으로 추가 측정' },
  { id: 'V-02', title: '경로 조작', technique_id: 'T1190', location: '파일 다운로드 API · 파일명 입력값', kisa: 'FD · 상', target_status: '취약', description: '파일명 입력값을 검증하지 않아 허용된 폴더 밖 파일을 받을 수 있습니다.', impact: '정답지가 업로드 폴더 밖 파일 반환을 확인 · 측정 전 회차 성공', tags: ['CWE-22', 'OWASP A01:2025 Broken Access Control', 'KISA FD (상)', 'ATT&CK T1190'], detection: '앱 로그 · 네트워크 관제 모두 탐지', remediation: '파일명 DB 매칭 · 확장자 허용 목록 · 경로 문자 필터링', detection_followup: '인코딩 변형 탐지 확인 (Gap #2)' },
  { id: 'V-03', title: '서버 측 요청 위조 (SSRF)', technique_id: 'T1190', location: '미리보기 API · URL 입력값', kisa: 'SF · 상', target_status: '취약', description: '서버가 사용자가 준 URL로 대신 요청해, 외부에서 닿지 않는 내부 메타데이터 서비스에 접근합니다.', impact: '정답지가 내부 메타데이터 응답(시험용 표식) 도달을 확인 · 측정 전 회차 성공', tags: ['CWE-918', 'OWASP A01:2025 Broken Access Control', 'KISA SF (상)', 'ATT&CK T1190'], detection: '앱 로그 · 네트워크 관제 모두 탐지', remediation: '허용 URL · IP 목록 검증 · 내부 주소 차단 · 네트워크 분리', detection_followup: '측정 도구의 대조 요청 오판 수정' },
  { id: 'V-04', title: '인증 시도 제한 없음 · 약한 비밀번호', technique_id: 'T1110', location: '로그인 API', kisa: 'AU · 상', target_status: '취약', description: '로그인 실패 횟수를 제한하지 않고, 추측하기 쉬운 비밀번호를 허용합니다.', impact: '정답지가 반복 시도 끝 로그인 성공을 확인 · 측정 전 회차 성공', tags: ['CWE-307', 'CWE-521', 'OWASP A07:2025 Authentication Failures', 'KISA AU (상)', 'ATT&CK T1110'], detection: '앱 로그 · 백엔드 상관 탐지 · 네트워크 관제는 HTTP 401 실패 응답 기반으로 보완했으며 오탐은 재검증 지표로 추적', remediation: '로그인 시도 횟수 제한 · 비밀번호 정책 강화 · 추가 인증', detection_followup: '네트워크 룰 1000031 · 1000032를 HTTP 401 실패 응답 기반으로 보완' },
];

const displayNames: DisplayNames = {
  'S5-SQLI-AFTER': '개선 후 측정 (10/22)',
  'S4-STACK-6-BASELINE': '개선 전 측정 (10/21)',
  'S5-SQLI-AFTER-BENIGN-WEB': '정상 트래픽·웹 (개선 후)',
  'S4-5-BENIGN-LOGIN': '정상 트래픽·로그인',
};

async function delay<T>(v: T): Promise<T> { return v; }
const isBefore = (runId: string) => runId === RUN_BEFORE;

export const RUN_IDS = { after: RUN_AFTER, before: RUN_BEFORE, benignWeb: RUN_BENIGN_WEB, benignLogin: RUN_BENIGN_LOGIN };

function stripDetail(r: RunDetail): RunSummary {
  const { definition_versions: _d, provenance: _p, ...summary } = r;
  void _d; void _p;
  return summary;
}

export const mockClient: ApiClient = {
  getMeta: () => delay<Meta>({
    definition_versions: [DEF, DEF_BENIGN],
    latest_definition_version: DEF,
    run_count: 4,
    navigator: { attack: '20.0', navigator: '5.3.2', layer: '4.5' },
  }),
  getRuns: () => delay<RunSummary[]>([stripDetail(runAfter), stripDetail(runBefore), stripDetail(runBenignWeb), stripDetail(runBenignLogin)]),
  getRun: (runId) => delay<RunDetail>(runsById[runId] ?? runAfter),
  getSnapshot: (_def, runId) => delay<SnapshotRow[]>(snapshotByRun[runId] ?? []),
  getRates: (runId) => delay<RateRow[]>(isBefore(runId) ? ratesBefore : ratesAfter),
  getCoverage: (runId) => delay<RateRow[]>(isBefore(runId) ? coverageBefore : coverageAfter),
  getCorrelation: (runId) => delay<CorrelationRow[]>(isBefore(runId) ? correlationBefore : correlationAfter),
  getAttacker: (_runId) => delay<AttackerRow[]>(attackerAfter),
  getMttd: (runId) => delay<MttdRow[]>(isBefore(runId) ? mttdBefore : mttdAfter),
  getH2: (_runId) => delay<H2Metric>(h2After),
  getAttempts: (runId, opts = {}) => {
    const list = isBefore(runId) ? attemptsBefore : attemptsAfter;
    const filtered = opts.verdict ? list.filter((a) => a.verdict === opts.verdict) : list;
    return delay<Attempt[]>(opts.limit ? filtered.slice(0, opts.limit) : filtered);
  },
  getAlertLinks: (_runId, limit) => delay<AlertLink[]>(limit ? alertLinksAfter.slice(0, limit) : alertLinksAfter),
  getImdsRequests: (_runId) => delay({ request_count: 40 }),
  getCompare: (_before, _after) => delay<Compare>(compare),
  getNavigatorLayer: (runId, layer) => delay<unknown>({
    name: `validation-${layer}`,
    versions: { attack: '20.0', navigator: '5.3.2', layer: '4.5' },
    domain: 'enterprise-attack', run_id: runId,
    techniques: [
      { techniqueID: 'T1190', score: 100, comment: '측정 범위 · 꾸준히 탐지' },
      { techniqueID: 'T1110', score: 100, comment: '측정 범위 · 꾸준히 탐지' },
    ],
  }),
  getGaps: () => delay<GapItem[]>(gaps),
  getFindings: () => delay<Finding[]>(findings),
  getDisplayNames: () => delay<DisplayNames>(displayNames),
};
