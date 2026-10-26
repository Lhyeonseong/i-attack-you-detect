-- validation schema v4 (S4-2) — 지표 뷰 M01~M06·M07b·M08~M10·M12 (ADR-S4-01 v1.4)
-- 판정은 verdict_result.verdict(·initial_verdict) 만 읽는다 — 재계산 금지(R1). M05 만 verdict_member·correlation·
-- detection_link 조인, M09 는 verdict_result 의 공격자 판정 컬럼(attacker_match·overestimate)만 읽는다.
-- 대상: kind = ATTACK ∧ attempt_role = ATTACK ∧ r10_status = VALID (D7·R6·R10). run 간 합산 없음(R4).
-- 비율 행은 x, n, p, lo, hi 병기(R3), n = 0 → p·lo·hi NULL·NO_DATA. definition_version = 'ADR-S4-01 v1.4'.
-- 내부 뷰(v_metric_run·v_metric_attempt·v_metric_split_attempt·v_metric_split_count)는 지표 뷰의 공통 기반이다.

-- 1) 지표 대상 run (D7·R10)
CREATE VIEW v_metric_run AS
SELECT run_id
FROM v_run_integrity
WHERE kind = 'ATTACK' AND r10_status = 'VALID';

COMMENT ON VIEW v_metric_run IS '내부 — ADR-S4-01 v1.4 D7·R10: 지표 대상 run = kind ATTACK ∧ r10_status VALID (BENIGN 은 M14 전용)';

-- 2) 지표 대상 시도 + 분할 단위 매핑 (R6·D6: NULL·metric_scope 밖 → UNKNOWN)
CREATE VIEW v_metric_attempt AS
SELECT v.id AS verdict_id, v.run_id, v.verdict, v.initial_verdict, v.mttd_ms, v.late_detection,
       v.attacker_match, v.overestimate,
       CASE WHEN EXISTS (SELECT 1 FROM metric_scope s WHERE s.kind = 'SCENARIO' AND s.unit = v.scenario)
            THEN v.scenario ELSE 'UNKNOWN' END AS scenario_unit,
       CASE WHEN EXISTS (SELECT 1 FROM metric_scope s WHERE s.kind = 'TECHNIQUE' AND s.unit = v.technique_id)
            THEN v.technique_id ELSE 'UNKNOWN' END AS technique_unit
FROM verdict_result v
JOIN v_metric_run r ON r.run_id = v.run_id
WHERE v.attempt_role = 'ATTACK';

COMMENT ON VIEW v_metric_attempt IS '내부 — ADR-S4-01 v1.4 R6·D6·D7: 대상 run 의 ATTACK 시도. scenario·technique_id 가 NULL 이거나 '
    'metric_scope 밖이면 UNKNOWN';

-- 3) 분할 행 × 소속 시도 (D1: ALL 1행 + 범위 6단위 항상 + UNKNOWN 은 시도 ≥1 일 때만). 시도 0건 단위는 verdict_id NULL 1행
CREATE VIEW v_metric_split_attempt AS
WITH split AS (
    SELECT run_id, 'ALL'::text AS split_kind, 'ALL'::text AS split_unit FROM v_metric_run
    UNION ALL
    SELECT r.run_id, s.kind, s.unit FROM v_metric_run r CROSS JOIN metric_scope s
    UNION ALL
    SELECT DISTINCT run_id, 'SCENARIO', 'UNKNOWN' FROM v_metric_attempt WHERE scenario_unit = 'UNKNOWN'
    UNION ALL
    SELECT DISTINCT run_id, 'TECHNIQUE', 'UNKNOWN' FROM v_metric_attempt WHERE technique_unit = 'UNKNOWN'
)
SELECT sp.run_id, sp.split_kind, sp.split_unit,
       a.verdict_id, a.verdict, a.initial_verdict, a.mttd_ms, a.late_detection, a.attacker_match, a.overestimate
FROM split sp
LEFT JOIN v_metric_attempt a
       ON a.run_id = sp.run_id
      AND (sp.split_kind = 'ALL'
           OR (sp.split_kind = 'SCENARIO' AND a.scenario_unit = sp.split_unit)
           OR (sp.split_kind = 'TECHNIQUE' AND a.technique_unit = sp.split_unit));

COMMENT ON VIEW v_metric_split_attempt IS '내부 — ADR-S4-01 v1.4 D1: 분할 행(ALL·SCENARIO·TECHNIQUE) × 소속 시도. 범위 6단위(R12)는 '
    '시도 0건이어도 행(verdict_id NULL), UNKNOWN 은 시도 ≥1 일 때만. I6: 시나리오·기법 각각 시도는 정확히 1단위에 속한다';

-- 4) 분할 행별 verdict 집합 카운트 (S_ALL·F_ALL·CONCL 은 ADR 집합 약어, *_initial 은 initial_verdict 기준 — D4)
CREATE VIEW v_metric_split_count AS
SELECT run_id, split_kind, split_unit,
       count(verdict_id)                                                                          AS total,
       count(*) FILTER (WHERE verdict = 'UNCERTAIN')                                              AS uncertain,
       count(verdict_id) - count(*) FILTER (WHERE verdict = 'UNCERTAIN')                          AS concl,
       count(*) FILTER (WHERE verdict IN ('SUCCEEDED_MISSED', 'SUCCEEDED_DETECTED', 'SUCCEEDED_BLOCKED')) AS s_all,
       count(*) FILTER (WHERE verdict IN ('SUCCEEDED_DETECTED', 'SUCCEEDED_BLOCKED'))             AS s_detected,
       count(*) FILTER (WHERE verdict = 'SUCCEEDED_DETECTED')                                     AS sd,
       count(*) FILTER (WHERE verdict = 'SUCCEEDED_MISSED')                                       AS sm,
       count(*) FILTER (WHERE verdict IN ('FAILED_DETECTED', 'FAILED_UNSEEN'))                    AS f_all,
       count(*) FILTER (WHERE verdict = 'FAILED_UNSEEN')                                          AS fu,
       count(*) FILTER (WHERE verdict IN ('SUCCEEDED_DETECTED', 'FAILED_DETECTED'))               AS detected,
       count(*) FILTER (WHERE verdict IN ('SUCCEEDED_DETECTED', 'FAILED_DETECTED') AND late_detection) AS detected_late,
       count(*) FILTER (WHERE initial_verdict IN ('SUCCEEDED_MISSED', 'SUCCEEDED_DETECTED', 'SUCCEEDED_BLOCKED'))
                                                                                                  AS s_all_initial,
       count(*) FILTER (WHERE initial_verdict IN ('SUCCEEDED_DETECTED', 'SUCCEEDED_BLOCKED'))     AS s_detected_initial,
       count(*) FILTER (WHERE initial_verdict = 'SUCCEEDED_MISSED')                               AS sm_initial
FROM v_metric_split_attempt
GROUP BY run_id, split_kind, split_unit;

COMMENT ON VIEW v_metric_split_count IS '내부 — ADR-S4-01 v1.4 집합 약어(S_ALL·F_ALL·CONCL) 카운트, *_initial = initial_verdict 기준(D4)';

-- 5) 비율 지표 M01·M02·M03(+INITIAL)·M07b·M08·M10·M12
CREATE VIEW v_metric_rates AS
SELECT c.run_id, 'ADR-S4-01 v1.4'::text AS definition_version, m.metric_id, c.split_kind, c.split_unit,
       m.x, m.n, w.p, w.lo, w.hi,
       CASE WHEN m.n = 0 THEN 'NO_DATA' ELSE 'OK' END AS status
FROM v_metric_split_count c
CROSS JOIN LATERAL (VALUES
        ('M01',         c.s_all,              c.concl,         true),
        ('M02',         c.s_detected,         c.s_all,         true),
        ('M03',         c.sm,                 c.s_all,         true),
        ('M02_INITIAL', c.s_detected_initial, c.s_all_initial, true),
        ('M03_INITIAL', c.sm_initial,         c.s_all_initial, true),
        ('M07b',        c.fu,                 c.f_all,         c.split_kind = 'SCENARIO'),
        ('M08',         c.uncertain,          c.total,         true),
        ('M10',         c.detected_late,      c.detected,      c.split_kind <> 'TECHNIQUE')
    ) AS m (metric_id, x, n, applies)
CROSS JOIN LATERAL wilson_ci(m.x, m.n) w
WHERE m.applies
UNION ALL
SELECT r.run_id, 'ADR-S4-01 v1.4', 'M12', 'ALL', 'ALL',
       NULL::bigint, NULL::bigint, NULL::double precision, NULL::double precision, NULL::double precision,
       'NOT_APPLICABLE'
FROM v_metric_run r;

COMMENT ON VIEW v_metric_rates IS 'ADR-S4-01 v1.4 비율 지표 (R1·R2·R3·R4·R6·R10·D1·D6·D7). '
    'M01 S_ALL/CONCL, M02 (SD+SB)/S_ALL, M03 SM/S_ALL (전체·시나리오·기법, R5 최종 verdict 기준), '
    'M02_INITIAL·M03_INITIAL = 같은 식을 분자·분모 모두 initial_verdict 기준(R5 보조·D4), '
    'M07b FU/F_ALL (시나리오), M08 UNCERTAIN/전체 (전체·시나리오·기법 — D5, R2 예외), '
    'M10 late/(SD+FD) (전체·시나리오, late = verdict_result.late_detection), M12 Block Rate N/A 1행(R8). '
    'n=0 → p·lo·hi NULL·NO_DATA(R3), 구간 = wilson_ci';

-- 6) M04 MTTD — SUCCEEDED_DETECTED ∧ late=false 의 mttd_ms, type 8 p50·p95 (R11), n = mttd_ms NOT NULL 건수
CREATE VIEW v_metric_mttd AS
SELECT g.run_id, 'ADR-S4-01 v1.4'::text AS definition_version, g.split_kind, g.split_unit, g.n,
       quantile_t8(g.vals, 0.5)  AS p50_ms,
       quantile_t8(g.vals, 0.95) AS p95_ms,
       CASE WHEN g.n = 0 THEN 'NO_DATA' ELSE 'OK' END AS status
FROM (SELECT run_id, split_kind, split_unit,
             count(mttd_ms) FILTER (WHERE verdict = 'SUCCEEDED_DETECTED' AND NOT late_detection) AS n,
             array_agg(mttd_ms::double precision)
                 FILTER (WHERE verdict = 'SUCCEEDED_DETECTED' AND NOT late_detection AND mttd_ms IS NOT NULL) AS vals
      FROM v_metric_split_attempt
      GROUP BY run_id, split_kind, split_unit) g;

COMMENT ON VIEW v_metric_mttd IS 'ADR-S4-01 v1.4 M04 MTTD (R1·R4·R10·R11·D1·D6·D7): SUCCEEDED_DETECTED ∧ late_detection=false 의 '
    'mttd_ms p50·p95 (Hyndman & Fan type 8) + n(mttd_ms NOT NULL 건수). 늦은 탐지는 M10. n=0 → NULL·NO_DATA';

-- 7) M05 Correlation Success — 링크 ≥1 시도(UNCERTAIN 포함, R2 예외)의 best source 분포 (전체·시나리오)
CREATE VIEW v_metric_correlation AS
WITH linked AS (
    SELECT sa.run_id, sa.split_kind, sa.split_unit, sa.verdict_id,
           (SELECT c.correlation_source
            FROM verdict_member m
            JOIN correlation c ON c.id = m.correlation_id
            WHERE m.verdict_id = sa.verdict_id
            ORDER BY array_position(ARRAY['RID', 'HEADER', 'UA_FALLBACK', 'NONE']::text[], c.correlation_source)
            LIMIT 1) AS best_source
    FROM v_metric_split_attempt sa
    WHERE sa.split_kind IN ('ALL', 'SCENARIO')
      AND EXISTS (SELECT 1
                  FROM verdict_member m
                  JOIN detection_link l ON l.correlation_id = m.correlation_id
                  WHERE m.verdict_id = sa.verdict_id)
), agg AS (
    SELECT sp.run_id, sp.split_kind, sp.split_unit,
           count(l.verdict_id)                                 AS n,
           count(*) FILTER (WHERE l.best_source = 'RID')         AS src_rid,
           count(*) FILTER (WHERE l.best_source = 'HEADER')      AS src_header,
           count(*) FILTER (WHERE l.best_source = 'UA_FALLBACK') AS src_ua,
           count(*) FILTER (WHERE l.best_source = 'NONE')        AS src_none
    FROM (SELECT DISTINCT run_id, split_kind, split_unit
          FROM v_metric_split_attempt
          WHERE split_kind IN ('ALL', 'SCENARIO')) sp
    LEFT JOIN linked l USING (run_id, split_kind, split_unit)
    GROUP BY sp.run_id, sp.split_kind, sp.split_unit
)
SELECT a.run_id, 'ADR-S4-01 v1.4'::text AS definition_version, a.split_kind, a.split_unit, s.source,
       s.x, a.n, w.p, w.lo, w.hi,
       CASE WHEN a.n = 0 THEN 'NO_DATA' ELSE 'OK' END AS status
FROM agg a
CROSS JOIN LATERAL (VALUES ('RID', a.src_rid), ('HEADER', a.src_header), ('UA_FALLBACK', a.src_ua),
                           ('NONE', a.src_none)) AS s (source, x)
CROSS JOIN LATERAL wilson_ci(s.x, a.n) w;

COMMENT ON VIEW v_metric_correlation IS 'ADR-S4-01 v1.4 M05 source 분포 (R1·R2 예외·R3·R4·R10·D1·D6·D7): 멤버 correlation 에 '
    'detection_link ≥1 인 ATTACK 시도(UNCERTAIN 포함). best source = 멤버 correlation.correlation_source 중 최고 순위 '
    '(RID > HEADER > UA_FALLBACK > NONE). 전체(판정)·시나리오(보고)';

-- 8) H2 판정 (전체만): (RID+HEADER) Wilson 하한 ≥ 0.90 ∧ NONE Wilson 상한 ≤ 0.05, n < 73 → INCONCLUSIVE
CREATE VIEW v_metric_h2 AS
SELECT x.run_id, 'ADR-S4-01 v1.4'::text AS definition_version, x.n,
       x.rid_header_x, rh.p AS rid_header_p, rh.lo AS rid_header_lo, rh.hi AS rid_header_hi,
       x.none_x, nn.p AS none_p, nn.lo AS none_lo, nn.hi AS none_hi,
       CASE
           WHEN x.n < 73 THEN 'INCONCLUSIVE'
           WHEN rh.lo >= 0.90 AND nn.hi <= 0.05 THEN 'PASS'
           ELSE 'FAIL'
       END AS h2_status
FROM (SELECT run_id, max(n) AS n,
             sum(x) FILTER (WHERE source IN ('RID', 'HEADER'))::bigint AS rid_header_x,
             sum(x) FILTER (WHERE source = 'NONE')::bigint AS none_x
      FROM v_metric_correlation
      WHERE split_kind = 'ALL'
      GROUP BY run_id) x
CROSS JOIN LATERAL wilson_ci(x.rid_header_x, x.n) rh
CROSS JOIN LATERAL wilson_ci(x.none_x, x.n) nn;

COMMENT ON VIEW v_metric_h2 IS 'ADR-S4-01 v1.4 M05 H2 판정 (전체만, R3·D7): PASS = (RID+HEADER) Wilson 하한 ≥ 0.90 ∧ '
    'NONE Wilson 상한 ≤ 0.05, n < 73 → INCONCLUSIVE(0건일 때 상한 ≤ 5% 가 되는 최소 n), 그 외 FAIL';

-- 9) M06a·M06b Analytic Coverage — 분모 = metric_scope 고정 목록(R12), UNKNOWN 은 단위 아님
CREATE VIEW v_metric_coverage_unit AS
SELECT c.run_id, 'ADR-S4-01 v1.4'::text AS definition_version, c.split_kind, c.split_unit,
       c.s_all, c.sd, c.sm,
       c.sd >= 1                    AS present,
       (c.s_all >= 1 AND c.sm = 0)  AS consistent
FROM v_metric_split_count c
JOIN metric_scope s ON s.kind = c.split_kind AND s.unit = c.split_unit;

COMMENT ON VIEW v_metric_coverage_unit IS 'ADR-S4-01 v1.4 M06 단위별 상세 (R5·R12·D2·D7): present = SUCCEEDED_DETECTED ≥ 1 '
    '(최종 verdict — 늦은 탐지 포함), consistent = S_ALL ≥ 1 ∧ SUCCEEDED_MISSED = 0 (D2)';

CREATE VIEW v_metric_coverage AS
SELECT g.run_id, 'ADR-S4-01 v1.4'::text AS definition_version, m.metric_id, g.split_kind,
       m.x, g.n, w.p, w.lo, w.hi,
       CASE WHEN g.n = 0 THEN 'NO_DATA' ELSE 'OK' END AS status
FROM (SELECT run_id, split_kind, count(*) AS n,
             count(*) FILTER (WHERE present)    AS present_x,
             count(*) FILTER (WHERE consistent) AS consistent_x
      FROM v_metric_coverage_unit
      GROUP BY run_id, split_kind) g
CROSS JOIN LATERAL (VALUES ('M06a', g.present_x), ('M06b', g.consistent_x)) AS m (metric_id, x)
CROSS JOIN LATERAL wilson_ci(m.x, g.n) w;

COMMENT ON VIEW v_metric_coverage IS 'ADR-S4-01 v1.4 M06a·M06b (R3·R12·D2·D7): M06a = present 단위 수 / 범위 단위 수, '
    'M06b = consistent 단위 수 / 범위 단위 수 (기법 2·시나리오 4). I5: M06b ≤ M06a';

-- 10) M09 공격자 판정 정확도 (시나리오별) — GateEvaluator 와 같은 정의, criteria_met 은 측정값(D3)
CREATE VIEW v_metric_attacker AS
SELECT g.run_id, 'ADR-S4-01 v1.4'::text AS definition_version, g.split_kind, g.split_unit,
       g.x, g.n, w.p, w.lo, w.hi, g.overestimate, g.uncertain,
       CASE WHEN g.n >= 20
            THEN g.x::double precision / g.n >= 0.95::double precision AND g.overestimate = 0
            ELSE false END AS criteria_met,
       CASE WHEN g.n = 0 THEN 'NO_DATA' ELSE 'OK' END AS status
FROM (SELECT run_id, split_kind, split_unit,
             count(*) FILTER (WHERE verdict <> 'UNCERTAIN')                       AS n,
             count(*) FILTER (WHERE verdict <> 'UNCERTAIN' AND attacker_match)    AS x,
             count(*) FILTER (WHERE overestimate)                                 AS overestimate,
             count(*) FILTER (WHERE verdict = 'UNCERTAIN')                        AS uncertain
      FROM v_metric_split_attempt
      WHERE split_kind = 'SCENARIO'
      GROUP BY run_id, split_kind, split_unit) g
CROSS JOIN LATERAL wilson_ci(g.x, g.n) w;

COMMENT ON VIEW v_metric_attacker IS 'ADR-S4-01 v1.4 M09 (R1·R3·R6·D1·D3·D6·D7): n = conclusive(UNCERTAIN 제외), '
    'x = attacker_match TRUE(NULL 은 분모만), overestimate = 전체 시도 중 과대평가 수. criteria_met = n ≥ 20 ∧ x/n ≥ 0.95 ∧ '
    'overestimate = 0 (결정3, 점추정 — Wilson 은 병기만). D3: 측정값이며 게이트 전환 판정 기록이 아니다';
