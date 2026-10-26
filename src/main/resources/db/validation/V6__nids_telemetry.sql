-- validation schema v6 (S4-4) — NIDS 상관 입력·텔레메트리 기록·M07a·M13 (ADR-S4-01 v1.7 R14·R15·R16)
-- 1) detection_link.control: 링크를 낸 통제(APP_RULE·NIDS). 기존 행은 전부 앱 로그 룰이므로 APP_RULE 로 채운다.
-- 2) nids_sid_class: Suricata sid 분류표(R14 d) 시드 — 코드 상수 NidsSidCatalog.V1_7 과 같아야 한다(테스트로 고정).
-- 3) telemetry_observation: verdict 1건 × 센서(APP_LOG·NIDS) 1행 — M07a 원천(R15).
-- 4) nids_window_stat: op 창 1개의 NIDS 집계(orphan·분류별 수·http 연결 수). 행 존재 = 그 run 은 NIDS 를 수집했다.
-- 5) metric_scope kind CONTROL 3행(R16 통제 목록). 기존 분할 뷰는 SCENARIO·TECHNIQUE 만 분할 단위로 쓰도록 거른다.
-- 6) 기존 지표 뷰 7개: 본문은 V4 그대로, definition_version 상수만 'ADR-S4-01 v1.7'(R14 e — 입력 링크에 NIDS 추가).
-- 7) v_metric_m07a·v_metric_m13(+시도 단위 내부 뷰), v_nids_run_stat. 8) take_metric_snapshot 이 새 뷰도 복사.

-- 1) 링크 통제
ALTER TABLE detection_link ADD COLUMN control TEXT;
UPDATE detection_link SET control = 'APP_RULE';
ALTER TABLE detection_link ALTER COLUMN control SET NOT NULL;
ALTER TABLE detection_link
    ADD CONSTRAINT ck_detection_link_control CHECK (control IN ('APP_RULE', 'NIDS')),
    ADD CONSTRAINT ck_detection_link_nids_path CHECK (control <> 'NIDS' OR match_path = 'UA_FALLBACK');
COMMENT ON COLUMN detection_link.control IS 'ADR-S4-01 v1.7 R14: 링크를 낸 통제 — APP_RULE(Wazuh 앱 로그 룰, V6 이전 행 전부) | '
    'NIDS(Suricata alert 86601 → eve http (flow_id, tx_id) → 시도, ANALYTIC sid 만, match_path UA_FALLBACK·confidence 0.7)';

-- 2) sid 분류표 (ADR-S4-01 v1.7 "NIDS sid 분류표", local.rules 원문 기준)
CREATE TABLE nids_sid_class (
    sid       INTEGER PRIMARY KEY,
    class     TEXT    NOT NULL,
    scenario  TEXT,
    note      TEXT    NOT NULL,
    CONSTRAINT ck_nids_sid_class_class CHECK (class IN ('ANALYTIC', 'TELEMETRY', 'MARKER', 'UNDECIDED')),
    CONSTRAINT ck_nids_sid_class_scenario CHECK (scenario IN ('SQLI', 'PATH_TRAVERSAL', 'BRUTE_FORCE', 'SSRF')),
    CONSTRAINT ck_nids_sid_class_marker CHECK ((class = 'MARKER') = (scenario IS NULL))
);
COMMENT ON TABLE nids_sid_class IS 'ADR-S4-01 v1.7 R14 d: ANALYTIC 만 탐지·verdict·M13 반영, TELEMETRY 는 수만 기록, MARKER(Caldera 표식)는 '
    'technique-under-test 아님·B안으로 제외, UNDECIDED 는 판단 보류(링크 제외). 표 밖 sid 도 링크 제외. 변경은 ADR 개정 + 새 마이그레이션';

INSERT INTO nids_sid_class (sid, class, scenario, note) VALUES
    (1000001, 'MARKER', NULL, 'http.user_agent startswith Caldera/'),
    (1000002, 'MARKER', NULL, 'X-Caldera-Op-Id 헤더'),
    (1000003, 'MARKER', NULL, 'X-Caldera-Technique 헤더'),
    (1000004, 'MARKER', NULL, 'X-Caldera-Ability 헤더'),
    (1000030, 'TELEMETRY', 'BRUTE_FORCE', 'POST /api/auth/login 요청 자체(패턴·임계치 없음)'),
    (1000031, 'ANALYTIC', 'BRUTE_FORCE', 'threshold by_src 10/60s'),
    (1000032, 'ANALYTIC', 'BRUTE_FORCE', 'threshold by_src 5/180s'),
    (1000018, 'UNDECIDED', 'SQLI', '중복 keyword= 파라미터(HPP) — 정상 요청에서도 생길 수 있어 판단 보류'),
    (1000040, 'ANALYTIC', 'PATH_TRAVERSAL', '.ssh id_rsa'),
    (1000041, 'UNDECIDED', 'PATH_TRAVERSAL', 'download 경로의 config 문자열 — 정상 파일명에도 걸릴 수 있어 판단 보류'),
    (1000087, 'ANALYTIC', 'SSRF', 'url= 127.x 단축·0.0.0.0');
INSERT INTO nids_sid_class (sid, class, scenario, note)
SELECT sid, 'ANALYTIC', 'SQLI', 'SQLi 패턴(UNION SELECT·ORDER BY·%27·pg_sleep·'' --·OR 1=1·CHR()'
FROM generate_series(1000010, 1000019) AS sid WHERE sid <> 1000018
UNION ALL
SELECT sid, 'ANALYTIC', 'PATH_TRAVERSAL', '경로조작 패턴(../·인코딩 변형·/etc/passwd·/etc/shadow·usr/bin)'
FROM generate_series(1000020, 1000029) AS sid
UNION ALL
SELECT sid, 'ANALYTIC', 'SSRF', 'SSRF 대상 패턴(메타데이터 IP·loopback·사설 IP·인코딩 우회·위험 scheme)'
FROM generate_series(1000060, 1000069) AS sid;

-- 3) 시도별 텔레메트리 (R15)
CREATE TABLE telemetry_observation (
    id           BIGSERIAL   PRIMARY KEY,
    run_id       UUID        NOT NULL REFERENCES measurement_run (run_id),
    verdict_id   BIGINT      NOT NULL REFERENCES verdict_result (id) ON DELETE CASCADE,
    sensor       TEXT        NOT NULL,
    event_count  INTEGER     NOT NULL,
    recorded_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_telemetry_observation UNIQUE (verdict_id, sensor),
    CONSTRAINT ck_telemetry_observation_sensor CHECK (sensor IN ('APP_LOG', 'NIDS')),
    CONSTRAINT ck_telemetry_observation_count CHECK (event_count >= 0)
);
CREATE INDEX ix_telemetry_observation_run ON telemetry_observation (run_id);
COMMENT ON TABLE telemetry_observation IS 'ADR-S4-01 v1.7 R15: verdict 1건 × 센서 1행. APP_LOG = 멤버 correlation 이 묶은 앱 이벤트 수(시도 원천 — '
    'VALID run 에서 구조적으로 ≥ 1), NIDS = 멤버 이벤트에 연결된(R14 c) eve http 수. M07a 원천';

-- run_id 는 verdict 의 run 과 같아야 한다 (귀속 불일치 방지)
CREATE FUNCTION telemetry_observation_check_run() RETURNS trigger
    LANGUAGE plpgsql AS
$$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM validation.verdict_result v WHERE v.id = NEW.verdict_id AND v.run_id = NEW.run_id) THEN
        RAISE EXCEPTION 'telemetry_observation: run % 은 verdict % 의 run 이 아니다', NEW.run_id, NEW.verdict_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_telemetry_observation_check_run
    BEFORE INSERT OR UPDATE ON telemetry_observation
    FOR EACH ROW EXECUTE FUNCTION telemetry_observation_check_run();

-- 4) op 창 NIDS 집계 (R14 b orphan, R14 d 분류별 수, R14 c http 연결 수)
CREATE TABLE nids_window_stat (
    run_id               UUID        NOT NULL REFERENCES measurement_run (run_id) ON DELETE CASCADE,
    op_id                TEXT        NOT NULL,
    window_start         TIMESTAMPTZ NOT NULL,
    window_end           TIMESTAMPTZ NOT NULL,
    nids_alerts          INTEGER     NOT NULL,
    orphan_alerts        INTEGER     NOT NULL,
    analytic_alerts      INTEGER     NOT NULL,
    analytic_linked      INTEGER     NOT NULL,
    telemetry_alerts     INTEGER     NOT NULL,
    marker_alerts        INTEGER     NOT NULL,
    undecided_alerts     INTEGER     NOT NULL,
    unclassified_alerts  INTEGER     NOT NULL,
    http_events          INTEGER     NOT NULL,
    http_attributed      INTEGER     NOT NULL,
    recorded_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT pk_nids_window_stat PRIMARY KEY (run_id, op_id),
    CONSTRAINT ck_nids_window_stat_window CHECK (window_start <= window_end),
    CONSTRAINT ck_nids_window_stat_counts CHECK (
        orphan_alerts >= 0 AND analytic_linked >= 0 AND telemetry_alerts >= 0 AND marker_alerts >= 0
        AND undecided_alerts >= 0 AND unclassified_alerts >= 0 AND http_attributed >= 0
        AND orphan_alerts <= nids_alerts AND analytic_linked <= analytic_alerts AND http_attributed <= http_events
        AND analytic_alerts + telemetry_alerts + marker_alerts + undecided_alerts + unclassified_alerts = nids_alerts)
);
COMMENT ON TABLE nids_window_stat IS 'ADR-S4-01 v1.7 R14: op 창 1개의 NIDS 집계. orphan = eve http 와 (flow_id, tx_id) 로 연결되지 않은 86601 alert, '
    'analytic_linked = 시도까지 연결된 ANALYTIC alert, http_attributed = 시도에 연결된 eve http. 행 존재 = run 의 NIDS·텔레메트리 수집(R15)';

CREATE VIEW v_nids_run_stat AS
SELECT run_id, count(*) AS windows,
       sum(nids_alerts)::bigint AS nids_alerts, sum(orphan_alerts)::bigint AS orphan_alerts,
       sum(analytic_alerts)::bigint AS analytic_alerts, sum(analytic_linked)::bigint AS analytic_linked,
       sum(telemetry_alerts)::bigint AS telemetry_alerts, sum(marker_alerts)::bigint AS marker_alerts,
       sum(undecided_alerts)::bigint AS undecided_alerts, sum(unclassified_alerts)::bigint AS unclassified_alerts,
       sum(http_events)::bigint AS http_events, sum(http_attributed)::bigint AS http_attributed
FROM nids_window_stat
GROUP BY run_id;
COMMENT ON VIEW v_nids_run_stat IS 'ADR-S4-01 v1.7 R14: run 별 NIDS 창 집계 합계 (스모크 기준 orphan_alerts = 0)';

-- 5) R16 통제 목록 — 분할 뷰는 SCENARIO·TECHNIQUE 만 분할 단위로 쓴다
ALTER TABLE metric_scope DROP CONSTRAINT ck_metric_scope_kind;
ALTER TABLE metric_scope ADD CONSTRAINT ck_metric_scope_kind CHECK (kind IN ('TECHNIQUE', 'SCENARIO', 'CONTROL'));
INSERT INTO metric_scope (kind, unit) VALUES
    ('CONTROL', 'APP_RULE'),
    ('CONTROL', 'NIDS'),
    ('CONTROL', 'BACKEND_CORR');
COMMENT ON TABLE metric_scope IS 'ADR-S4-01 R12: Analytic Coverage(M06a·M06b) 분모 범위 단위 — 시도 0건 단위도 분모에 포함. '
    'v1.7 R16: kind CONTROL = M13 통제 목록(APP_RULE·NIDS·BACKEND_CORR), 분할 단위 아님';

-- 6) 기존 지표 뷰 — V4 본문 그대로, definition_version 상수만 v1.7 (v_metric_split_attempt 는 CONTROL 행 제외만)
CREATE OR REPLACE VIEW v_metric_split_attempt AS
WITH split AS (
    SELECT run_id, 'ALL'::text AS split_kind, 'ALL'::text AS split_unit FROM v_metric_run
    UNION ALL
    SELECT r.run_id, s.kind, s.unit FROM v_metric_run r CROSS JOIN metric_scope s WHERE s.kind IN ('SCENARIO', 'TECHNIQUE')
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

CREATE OR REPLACE VIEW v_metric_rates AS
SELECT c.run_id, 'ADR-S4-01 v1.7'::text AS definition_version, m.metric_id, c.split_kind, c.split_unit,
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
SELECT r.run_id, 'ADR-S4-01 v1.7', 'M12', 'ALL', 'ALL',
       NULL::bigint, NULL::bigint, NULL::double precision, NULL::double precision, NULL::double precision,
       'NOT_APPLICABLE'
FROM v_metric_run r;

CREATE OR REPLACE VIEW v_metric_mttd AS
SELECT g.run_id, 'ADR-S4-01 v1.7'::text AS definition_version, g.split_kind, g.split_unit, g.n,
       quantile_t8(g.vals, 0.5)  AS p50_ms,
       quantile_t8(g.vals, 0.95) AS p95_ms,
       CASE WHEN g.n = 0 THEN 'NO_DATA' ELSE 'OK' END AS status
FROM (SELECT run_id, split_kind, split_unit,
             count(mttd_ms) FILTER (WHERE verdict = 'SUCCEEDED_DETECTED' AND NOT late_detection) AS n,
             array_agg(mttd_ms::double precision)
                 FILTER (WHERE verdict = 'SUCCEEDED_DETECTED' AND NOT late_detection AND mttd_ms IS NOT NULL) AS vals
      FROM v_metric_split_attempt
      GROUP BY run_id, split_kind, split_unit) g;

CREATE OR REPLACE VIEW v_metric_correlation AS
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
SELECT a.run_id, 'ADR-S4-01 v1.7'::text AS definition_version, a.split_kind, a.split_unit, s.source,
       s.x, a.n, w.p, w.lo, w.hi,
       CASE WHEN a.n = 0 THEN 'NO_DATA' ELSE 'OK' END AS status
FROM agg a
CROSS JOIN LATERAL (VALUES ('RID', a.src_rid), ('HEADER', a.src_header), ('UA_FALLBACK', a.src_ua),
                           ('NONE', a.src_none)) AS s (source, x)
CROSS JOIN LATERAL wilson_ci(s.x, a.n) w;

CREATE OR REPLACE VIEW v_metric_h2 AS
SELECT x.run_id, 'ADR-S4-01 v1.7'::text AS definition_version, x.n,
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

CREATE OR REPLACE VIEW v_metric_coverage_unit AS
SELECT c.run_id, 'ADR-S4-01 v1.7'::text AS definition_version, c.split_kind, c.split_unit,
       c.s_all, c.sd, c.sm,
       c.sd >= 1                    AS present,
       (c.s_all >= 1 AND c.sm = 0)  AS consistent
FROM v_metric_split_count c
JOIN metric_scope s ON s.kind = c.split_kind AND s.unit = c.split_unit;

CREATE OR REPLACE VIEW v_metric_coverage AS
SELECT g.run_id, 'ADR-S4-01 v1.7'::text AS definition_version, m.metric_id, g.split_kind,
       m.x, g.n, w.p, w.lo, w.hi,
       CASE WHEN g.n = 0 THEN 'NO_DATA' ELSE 'OK' END AS status
FROM (SELECT run_id, split_kind, count(*) AS n,
             count(*) FILTER (WHERE present)    AS present_x,
             count(*) FILTER (WHERE consistent) AS consistent_x
      FROM v_metric_coverage_unit
      GROUP BY run_id, split_kind) g
CROSS JOIN LATERAL (VALUES ('M06a', g.present_x), ('M06b', g.consistent_x)) AS m (metric_id, x)
CROSS JOIN LATERAL wilson_ci(m.x, g.n) w;

CREATE OR REPLACE VIEW v_metric_attacker AS
SELECT g.run_id, 'ADR-S4-01 v1.7'::text AS definition_version, g.split_kind, g.split_unit,
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

DO $$
DECLARE
    v text;
BEGIN
    FOREACH v IN ARRAY ARRAY['v_metric_rates', 'v_metric_mttd', 'v_metric_correlation', 'v_metric_h2',
                             'v_metric_coverage_unit', 'v_metric_coverage', 'v_metric_attacker'] LOOP
        EXECUTE format('COMMENT ON VIEW validation.%I IS %L', v,
            replace(obj_description(('validation.' || v)::regclass, 'pg_class'), 'ADR-S4-01 v1.4', 'ADR-S4-01 v1.7')
            || ' — v1.7(V6): 식은 v1.4 와 같고 입력 링크에 NIDS 가 더해졌다(R14 e)');
    END LOOP;
END;
$$;
COMMENT ON VIEW v_metric_split_attempt IS '내부 — ADR-S4-01 v1.4 D1: 분할 행(ALL·SCENARIO·TECHNIQUE) × 소속 시도. 범위 6단위(R12)는 '
    '시도 0건이어도 행(verdict_id NULL), UNKNOWN 은 시도 ≥1 일 때만. I6: 시나리오·기법 각각 시도는 정확히 1단위에 속한다. '
    'v1.7(V6): metric_scope 의 CONTROL 행(R16)은 분할 단위가 아니므로 제외';

-- 7) M07a·M13 (ADR-S4-01 v1.7 R15·R16)

-- 시도 단위 통제 기여 (내부, I2 검사용): in_s_all = M02 분모, app_rule·nids = conf ≥ 0.7 ∧ technique 일치 링크
-- (VerdictEngine 단건 기준과 같은 조건), nids 는 ANALYTIC sid 만, backend_corr = BF 단위 판정 성립
CREATE VIEW v_metric_m13_attempt AS
SELECT a.run_id, a.verdict_id, a.scenario_unit, a.verdict,
       a.verdict IN ('SUCCEEDED_MISSED', 'SUCCEEDED_DETECTED', 'SUCCEEDED_BLOCKED') AS in_s_all,
       EXISTS (SELECT 1
               FROM verdict_member m
               JOIN detection_link l ON l.correlation_id = m.correlation_id
               WHERE m.verdict_id = a.verdict_id AND l.control = 'APP_RULE' AND l.confidence >= 0.7
                 AND l.technique IS NOT DISTINCT FROM v.technique_id) AS app_rule,
       EXISTS (SELECT 1
               FROM verdict_member m
               JOIN detection_link l ON l.correlation_id = m.correlation_id
               JOIN nids_sid_class k ON k.sid::text = l.rule_id AND k.class = 'ANALYTIC'
               WHERE m.verdict_id = a.verdict_id AND l.control = 'NIDS' AND l.confidence >= 0.7
                 AND l.technique IS NOT DISTINCT FROM v.technique_id) AS nids,
       (v.unit_type IN ('BF_SEQUENCE', 'SPRAY_CAMPAIGN') AND v.detection_status = 'DETECTED') AS backend_corr
FROM v_metric_attempt a
JOIN verdict_result v ON v.id = a.verdict_id;

COMMENT ON VIEW v_metric_m13_attempt IS '내부 — ADR-S4-01 v1.7 R16: 시도별 통제 기여. I2 시나리오별: SQLi·PT·SSRF (app_rule ∨ nids) ⇔ DETECTED, '
    'BF backend_corr ⇔ DETECTED (in_s_all 시도의 합집합 수 = M02 분자). NIDS × BF 는 I2 에 넣지 않는다';

-- M13 통제별 탐지율: 통제(metric_scope CONTROL) × 시나리오(범위 4종), 분모 = 시나리오 S_ALL (지표 카드 M13)
CREATE VIEW v_metric_m13 AS
WITH cell AS (
    SELECT r.run_id, c.unit AS control, s.unit AS scenario,
           EXISTS (SELECT 1 FROM nids_window_stat w WHERE w.run_id = r.run_id) AS collected
    FROM v_metric_run r
    CROSS JOIN metric_scope c
    CROSS JOIN metric_scope s
    WHERE c.kind = 'CONTROL' AND s.kind = 'SCENARIO'
), agg AS (
    SELECT cell.run_id, cell.control, cell.scenario, cell.collected,
           count(*) FILTER (WHERE t.in_s_all) AS n,
           count(*) FILTER (WHERE t.in_s_all AND CASE cell.control
                                                   WHEN 'APP_RULE' THEN t.app_rule
                                                   WHEN 'NIDS' THEN t.nids
                                                   ELSE t.backend_corr END) AS x
    FROM cell
    LEFT JOIN v_metric_m13_attempt t ON t.run_id = cell.run_id AND t.scenario_unit = cell.scenario
    GROUP BY cell.run_id, cell.control, cell.scenario, cell.collected
), judged AS (
    SELECT a.*,
           CASE
               WHEN a.control = 'APP_RULE' AND a.scenario = 'BRUTE_FORCE' THEN 'NOT_APPLICABLE'
               WHEN a.control = 'BACKEND_CORR' AND a.scenario <> 'BRUTE_FORCE' THEN 'NO_RULE'
               WHEN a.control = 'NIDS' AND NOT EXISTS (SELECT 1 FROM nids_sid_class k
                                                       WHERE k.class = 'ANALYTIC' AND k.scenario = a.scenario)
                   THEN 'NO_RULE'
               WHEN a.control = 'NIDS' AND NOT a.collected THEN 'NOT_COLLECTED'
               WHEN a.n = 0 THEN 'NO_DATA'
               ELSE 'OK'
           END AS status
    FROM agg a
)
SELECT j.run_id, 'ADR-S4-01 v1.7'::text AS definition_version, 'M13_' || j.control AS metric_id, j.control,
       'SCENARIO'::text AS split_kind, j.scenario AS split_unit,
       CASE WHEN j.status IN ('OK', 'NO_DATA') THEN j.x END AS x, j.n, w.p, w.lo, w.hi, j.status
FROM judged j
LEFT JOIN LATERAL wilson_ci(CASE WHEN j.status IN ('OK', 'NO_DATA') THEN j.x END, j.n) w ON true;

COMMENT ON VIEW v_metric_m13 IS 'ADR-S4-01 v1.7 M13 (R1·R3·R6·R16·D7): 통제 c 가 기여한 시나리오 S_ALL / 시나리오 S_ALL. '
    'APP_RULE = SQLi·PT·SSRF(BF 는 NOT_APPLICABLE), NIDS = ANALYTIC sid 가 있는 시나리오(없으면 NO_RULE, R14 이전 run 은 NOT_COLLECTED), '
    'BACKEND_CORR = BF(그 외 NO_RULE). NO_RULE·NOT_APPLICABLE·NOT_COLLECTED 는 x·p·lo·hi NULL(0% 표기 금지), n = 0 → NO_DATA';

-- M07a 텔레메트리 가시성: 센서 s 이벤트 ≥ 1 인 시도 / 전체 시도 (UNCERTAIN 포함 — R2 예외), 전체·시나리오
CREATE VIEW v_metric_m07a AS
WITH base AS (
    SELECT sa.run_id, sa.split_kind, sa.split_unit, sa.verdict_id, s.sensor,
           EXISTS (SELECT 1 FROM nids_window_stat w WHERE w.run_id = sa.run_id) AS collected,
           EXISTS (SELECT 1 FROM telemetry_observation t
                   WHERE t.verdict_id = sa.verdict_id AND t.sensor = s.sensor AND t.event_count >= 1) AS observed
    FROM v_metric_split_attempt sa
    CROSS JOIN (VALUES ('APP_LOG'::text), ('NIDS'::text)) AS s (sensor)
    WHERE sa.split_kind IN ('ALL', 'SCENARIO')
), agg AS (
    SELECT run_id, split_kind, split_unit, sensor, bool_and(collected) AS collected,
           count(verdict_id) AS n,
           count(*) FILTER (WHERE observed) AS x
    FROM base
    GROUP BY run_id, split_kind, split_unit, sensor
)
SELECT a.run_id, 'ADR-S4-01 v1.7'::text AS definition_version, 'M07a_' || a.sensor AS metric_id, a.sensor,
       a.split_kind, a.split_unit,
       CASE WHEN a.collected THEN a.x END AS x, a.n, w.p, w.lo, w.hi,
       CASE WHEN NOT a.collected THEN 'NOT_COLLECTED' WHEN a.n = 0 THEN 'NO_DATA' ELSE 'OK' END AS status
FROM agg a
LEFT JOIN LATERAL wilson_ci(CASE WHEN a.collected THEN a.x END, a.n) w ON true;

COMMENT ON VIEW v_metric_m07a IS 'ADR-S4-01 v1.7 M07a (R2 예외·R3·R15·D1·D7): 센서 이벤트 ≥ 1 시도 / 전체 ATTACK 시도(UNCERTAIN 포함), 전체·시나리오. '
    'APP_LOG 는 시도 원천이라 구조적으로 1(기록만, 해석 지표 아님), NIDS = 연결된 eve http ≥ 1. '
    'R14 이전 run(nids_window_stat 없음)은 NOT_COLLECTED(x·p NULL), n = 0 → NO_DATA';

-- 8) 스냅샷 — R13 그대로, 새 뷰(M07a·M13)도 복사. snapshot_rule_version 상수 유지, definition_version = 뷰 값
CREATE OR REPLACE FUNCTION take_metric_snapshot(p_run_id uuid) RETURNS integer
    LANGUAGE plpgsql AS
$$
DECLARE
    v_status text;
    v_reason text;
    v_kind   text;
    v_defs   text[];
    v_def    text;
    v_schema text;
    v_rows   integer;
BEGIN
    IF p_run_id IS NULL THEN
        RAISE EXCEPTION 'take_metric_snapshot: run_id 가 필요하다' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- 같은 run 의 동시 스냅샷을 직렬화 (중복 확인 ~ INSERT 사이 경합 방지)
    PERFORM 1 FROM validation.measurement_run WHERE run_id = p_run_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'measurement_run % 없음', p_run_id USING ERRCODE = 'no_data_found';
    END IF;

    SELECT r10_status, r10_reason, kind INTO v_status, v_reason, v_kind
    FROM validation.v_run_integrity WHERE run_id = p_run_id;
    IF v_status <> 'VALID' THEN
        RAISE EXCEPTION 'R10 % (%) — run % 스냅샷 거부 (ADR-S4-01 R13 a: VALID run 만)',
            v_status, coalesce(v_reason, '-'), p_run_id
            USING ERRCODE = 'check_violation';
    END IF;
    IF v_kind <> 'ATTACK' THEN
        RAISE EXCEPTION 'run % kind % — 공격 지표 스냅샷 대상 아님 (ADR-S4-01 D7: 지표 뷰는 ATTACK run 만)', p_run_id, v_kind
            USING ERRCODE = 'check_violation';
    END IF;

    -- R13 e: definition_version = 원 지표 뷰들의 값. 뷰마다 다르면(정의 개정 중 일부만 바뀜) 거부
    v_defs := ARRAY(
        SELECT DISTINCT d FROM (
            SELECT definition_version AS d FROM validation.v_metric_rates WHERE run_id = p_run_id
            UNION SELECT definition_version FROM validation.v_metric_mttd WHERE run_id = p_run_id
            UNION SELECT definition_version FROM validation.v_metric_correlation WHERE run_id = p_run_id
            UNION SELECT definition_version FROM validation.v_metric_h2 WHERE run_id = p_run_id
            UNION SELECT definition_version FROM validation.v_metric_coverage WHERE run_id = p_run_id
            UNION SELECT definition_version FROM validation.v_metric_attacker WHERE run_id = p_run_id
            UNION SELECT definition_version FROM validation.v_metric_m07a WHERE run_id = p_run_id
            UNION SELECT definition_version FROM validation.v_metric_m13 WHERE run_id = p_run_id
        ) x ORDER BY d);
    IF cardinality(v_defs) <> 1 THEN
        RAISE EXCEPTION 'run % 지표 뷰 definition_version 이 하나가 아니다 [%] — 스냅샷 거부 (R13 e)',
            p_run_id, array_to_string(v_defs, ', ')
            USING ERRCODE = 'check_violation';
    END IF;
    v_def := v_defs[1];

    IF EXISTS (SELECT 1 FROM validation.metric_snapshot WHERE run_id = p_run_id AND definition_version = v_def) THEN
        RAISE EXCEPTION 'run % definition_version % 스냅샷이 이미 있다 — 덮어쓰기 금지 (R13 d), 정의가 바뀌면 새 definition_version 으로 추가된다',
            p_run_id, v_def
            USING ERRCODE = 'unique_violation';
    END IF;

    SELECT version INTO v_schema
    FROM validation.flyway_schema_history
    WHERE success AND version IS NOT NULL
    ORDER BY installed_rank DESC
    LIMIT 1;
    IF v_schema IS NULL THEN
        RAISE EXCEPTION 'flyway_schema_history 에 적용된 version 이 없다 — schema_version 을 정할 수 없다';
    END IF;

    INSERT INTO validation.metric_snapshot (run_id, definition_version, metric_id, scope_kind, scope_key,
        numerator, denominator, point_estimate, ci_lower, ci_upper, p50_ms, p95_ms, overestimate_count, uncertain_count,
        criteria_met, status, source_view, snapshot_rule_version, schema_version, run_label, git_commit, git_dirty,
        rules_digest)
    SELECT p_run_id, o.def, o.metric_id, o.scope_kind, o.scope_key,
           o.numerator, o.denominator, o.p, o.lo, o.hi, o.p50, o.p95, o.overestimate, o.uncertain,
           o.criteria_met, o.status, o.source_view, 'ADR-S4-01 v1.6', v_schema, r.label, r.git_commit, r.git_dirty,
           r.rules_digest
    FROM (
        -- M01·M02·M03·M02_INITIAL·M03_INITIAL·M07b·M08·M10·M12 (M12 status = NOT_APPLICABLE 그대로)
        SELECT v.metric_id, v.split_kind AS scope_kind, v.split_unit AS scope_key, v.x AS numerator, v.n AS denominator,
               v.p, v.lo, v.hi, NULL::double precision AS p50, NULL::double precision AS p95,
               NULL::bigint AS overestimate, NULL::bigint AS uncertain, NULL::boolean AS criteria_met,
               v.status, 'v_metric_rates'::text AS source_view, v.definition_version AS def
        FROM validation.v_metric_rates v WHERE v.run_id = p_run_id
        UNION ALL
        -- M04 MTTD: p50·p95(type 8) + n
        SELECT 'M04', v.split_kind, v.split_unit, NULL, v.n, NULL, NULL, NULL, v.p50_ms, v.p95_ms, NULL, NULL, NULL,
               v.status, 'v_metric_mttd', v.definition_version
        FROM validation.v_metric_mttd v WHERE v.run_id = p_run_id
        UNION ALL
        -- M05 best source 분포
        SELECT 'M05_' || v.source, v.split_kind, v.split_unit, v.x, v.n, v.p, v.lo, v.hi, NULL, NULL, NULL, NULL, NULL,
               v.status, 'v_metric_correlation', v.definition_version
        FROM validation.v_metric_correlation v WHERE v.run_id = p_run_id
        UNION ALL
        -- M05 H2 판정 (ALL 1행 = 관측 2개, status = h2_status 그대로)
        SELECT 'M05_H2_RID_HEADER', 'ALL', 'ALL', v.rid_header_x, v.n, v.rid_header_p, v.rid_header_lo, v.rid_header_hi,
               NULL, NULL, NULL, NULL, NULL, v.h2_status, 'v_metric_h2', v.definition_version
        FROM validation.v_metric_h2 v WHERE v.run_id = p_run_id
        UNION ALL
        SELECT 'M05_H2_NONE', 'ALL', 'ALL', v.none_x, v.n, v.none_p, v.none_lo, v.none_hi,
               NULL, NULL, NULL, NULL, NULL, v.h2_status, 'v_metric_h2', v.definition_version
        FROM validation.v_metric_h2 v WHERE v.run_id = p_run_id
        UNION ALL
        -- M06a·M06b (범위 목록 전체)
        SELECT v.metric_id, v.split_kind, 'ALL', v.x, v.n, v.p, v.lo, v.hi, NULL, NULL, NULL, NULL, NULL,
               v.status, 'v_metric_coverage', v.definition_version
        FROM validation.v_metric_coverage v WHERE v.run_id = p_run_id
        UNION ALL
        -- M09 공격자 판정 정확도 (criteria_met 그대로)
        SELECT 'M09', v.split_kind, v.split_unit, v.x, v.n, v.p, v.lo, v.hi, NULL, NULL, v.overestimate, v.uncertain,
               v.criteria_met, v.status, 'v_metric_attacker', v.definition_version
        FROM validation.v_metric_attacker v WHERE v.run_id = p_run_id
        UNION ALL
        -- M07a 텔레메트리 가시성 (R15, status 그대로 — NOT_COLLECTED 포함)
        SELECT v.metric_id, v.split_kind, v.split_unit, v.x, v.n, v.p, v.lo, v.hi, NULL, NULL, NULL, NULL, NULL,
               v.status, 'v_metric_m07a', v.definition_version
        FROM validation.v_metric_m07a v WHERE v.run_id = p_run_id
        UNION ALL
        -- M13 통제별 탐지율 (R16, status 그대로 — NO_RULE·NOT_APPLICABLE·NOT_COLLECTED 포함)
        SELECT v.metric_id, v.split_kind, v.split_unit, v.x, v.n, v.p, v.lo, v.hi, NULL, NULL, NULL, NULL, NULL,
               v.status, 'v_metric_m13', v.definition_version
        FROM validation.v_metric_m13 v WHERE v.run_id = p_run_id
    ) o
    JOIN validation.measurement_run r ON r.run_id = p_run_id;

    GET DIAGNOSTICS v_rows = ROW_COUNT;
    IF v_rows = 0 THEN
        RAISE EXCEPTION 'run % 지표 뷰 행 0 — 스냅샷할 값이 없다', p_run_id;
    END IF;
    RETURN v_rows;
END;
$$;

COMMENT ON FUNCTION take_metric_snapshot(uuid) IS 'ADR-S4-01 v1.6 R13 (v1.7 V6: M07a·M13 포함): VALID ATTACK run 의 지표 뷰 결과 전부를 metric_snapshot 에 '
    '변환 없이 복사, 행 수 반환. definition_version = 원 뷰 값(뷰마다 다르면 거부). INVALID·INCOMPLETE·BENIGN·중복(run+definition_version) 은 예외';
