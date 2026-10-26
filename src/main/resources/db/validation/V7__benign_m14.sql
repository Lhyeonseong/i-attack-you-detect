-- validation schema v7 (S4-5) — BENIGN run(정상 코퍼스)·M14a·M14b (ADR-S4-01 v1.8 R17·R18)
-- 1) benign_endpoint: 정상 코퍼스 엔드포인트 ↔ 시나리오(M14a 분할). 웹 3종 시드, login 은 login run 작업 때 추가(R17 e)
-- 2) benign_request: 코퍼스 요청 1건 = 1행(전송·응답 시각, 상태, 앱 로그 대조 rid). benign_result: 요청 × 통제 판정(FP/TN)
--    benign_unlinked_alert: 측정 창 안 미연결 알림(기록만, R18 g). 모두 BENIGN·OPEN run 에만 INSERT
-- 3) v_run_integrity BENIGN 분기(R17 d) — ATTACK 행의 기존 10열은 V3 정의 그대로, 끝에 benign_loaded·benign_matched 열 추가
-- 4) v_metric_m14a·v_metric_m14b·v_metric_m14_rule (definition_version 'ADR-S4-01 v1.8')
-- 5) metric_snapshot.paired_run_id 추가(ADD COLUMN 만), BENIGN VALID run 스냅샷 허용 — ATTACK 경로는 V6 와 같다

-- 1) 엔드포인트
CREATE TABLE benign_endpoint (
    endpoint  TEXT PRIMARY KEY,
    scenario  TEXT NOT NULL,
    param     TEXT NOT NULL,
    CONSTRAINT ck_benign_endpoint_scenario CHECK (scenario IN ('SQLI', 'PATH_TRAVERSAL', 'BRUTE_FORCE', 'SSRF'))
);
COMMENT ON TABLE benign_endpoint IS 'ADR-S4-01 v1.8 R18 a: 정상 코퍼스 엔드포인트 → 시나리오(M14a 분할 = 엔드포인트). 행 추가는 새 마이그레이션으로';
INSERT INTO benign_endpoint (endpoint, scenario, param) VALUES
    ('/api/products/search', 'SQLI', 'keyword'),
    ('/api/files/download', 'PATH_TRAVERSAL', 'filename'),
    ('/api/preview', 'SSRF', 'url');

-- 2) 요청·판정·미연결 기록
CREATE TABLE benign_request (
    run_id        UUID        NOT NULL REFERENCES measurement_run (run_id) ON DELETE CASCADE,
    seq           INTEGER     NOT NULL,
    endpoint      TEXT        NOT NULL REFERENCES benign_endpoint (endpoint),
    args_digest   TEXT        NOT NULL,
    sent_at       TIMESTAMPTZ NOT NULL,
    responded_at  TIMESTAMPTZ NOT NULL,
    status        INTEGER     NOT NULL,
    matched_rid   TEXT,
    CONSTRAINT pk_benign_request PRIMARY KEY (run_id, seq),
    CONSTRAINT ck_benign_request_seq CHECK (seq >= 1),
    CONSTRAINT ck_benign_request_time CHECK (sent_at <= responded_at)
);
COMMENT ON TABLE benign_request IS 'ADR-S4-01 v1.8 R17: 정상 코퍼스 요청 1건. args_digest = sha256(앱 로그 args 형태 "param=value") — 값 원문은 manifest 에만. '
    'status = HTTP 상태(전송 실패 -1). matched_rid = 앱 로그 대조로 정한 rid(R17 c, 실패 NULL)';

CREATE TABLE benign_result (
    run_id             UUID    NOT NULL,
    seq                INTEGER NOT NULL,
    control            TEXT    NOT NULL,
    alerted            BOOLEAN NOT NULL,
    linked_rule_ids    TEXT[]  NOT NULL,
    alert_count        INTEGER NOT NULL,
    recorded_rule_ids  TEXT[]  NOT NULL,
    CONSTRAINT pk_benign_result PRIMARY KEY (run_id, seq, control),
    CONSTRAINT fk_benign_result_request FOREIGN KEY (run_id, seq) REFERENCES benign_request (run_id, seq) ON DELETE CASCADE,
    CONSTRAINT ck_benign_result_control CHECK (control IN ('APP_RULE', 'NIDS', 'BACKEND_CORR')),
    CONSTRAINT ck_benign_result_count CHECK (alert_count = cardinality(linked_rule_ids) AND alerted = (alert_count > 0))
);
COMMENT ON TABLE benign_result IS 'ADR-S4-01 v1.8 R18 a: 정상 요청 × 적용 통제 1행. alerted = 판정용 알림 ≥ 1(FP), linked_rule_ids = 판정용 알림 룰 ID(알림당 1개), '
    'recorded_rule_ids = 연결됐지만 판정 제외(NIDS TELEMETRY·MARKER·UNDECIDED·분류표 밖)';

CREATE TABLE benign_unlinked_alert (
    id          BIGSERIAL   PRIMARY KEY,
    run_id      UUID        NOT NULL REFERENCES measurement_run (run_id) ON DELETE CASCADE,
    sensor      TEXT        NOT NULL,
    rule_id     TEXT        NOT NULL,
    alert_time  TIMESTAMPTZ NOT NULL,
    reason      TEXT        NOT NULL,
    CONSTRAINT ck_benign_unlinked_alert_sensor CHECK (sensor IN ('APP_RULE', 'NIDS')),
    CONSTRAINT ck_benign_unlinked_alert_reason CHECK (reason IN ('NO_MATCH', 'NO_CANDIDATE', 'AMBIGUOUS'))
);
COMMENT ON TABLE benign_unlinked_alert IS 'ADR-S4-01 v1.8 R18 g: BENIGN run 창 안 미연결 알림(기록만, 판정 제외). NIDS 배경(fe80::/10·ff00::/8)은 넣지 않는다';

-- BENIGN·OPEN run 에만 쓴다 (ATTACK run·닫힌 run 에 정상 기록이 섞이지 않게)
CREATE FUNCTION benign_reject_non_benign_run() RETURNS trigger
    LANGUAGE plpgsql AS
$$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM validation.measurement_run r
                   WHERE r.run_id = NEW.run_id AND r.kind = 'BENIGN' AND r.status = 'OPEN') THEN
        RAISE EXCEPTION '% — run % 은 OPEN BENIGN run 이 아니다 (ADR-S4-01 R17)', TG_TABLE_NAME, NEW.run_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER trg_benign_request_benign_run BEFORE INSERT ON benign_request
    FOR EACH ROW EXECUTE FUNCTION benign_reject_non_benign_run();
CREATE TRIGGER trg_benign_result_benign_run BEFORE INSERT ON benign_result
    FOR EACH ROW EXECUTE FUNCTION benign_reject_non_benign_run();
CREATE TRIGGER trg_benign_unlinked_alert_benign_run BEFORE INSERT ON benign_unlinked_alert
    FOR EACH ROW EXECUTE FUNCTION benign_reject_non_benign_run();

-- 3) R10 BENIGN 분기 — ATTACK 행: 기존 열·사유 우선순위 V3 그대로
CREATE OR REPLACE VIEW v_run_integrity AS
SELECT x.run_id, x.label, x.kind, x.status,
       x.expected_attempts, x.expected_controls, x.actual_attack, x.actual_control,
       CASE
           WHEN x.r10_reason IS NULL THEN 'VALID'
           WHEN x.r10_reason = 'OPEN' THEN 'INCOMPLETE'
           ELSE 'INVALID'
       END AS r10_status,
       x.r10_reason, x.benign_loaded, x.benign_matched
FROM (SELECT r.run_id, r.label, r.kind, r.status, r.expected_attempts, r.expected_controls,
             c.actual_attack, c.actual_control,
             CASE
                 WHEN r.status = 'OPEN' THEN 'OPEN'
                 WHEN r.expected_attempts IS NULL OR r.expected_controls IS NULL THEN 'EXPECTED_MISSING'
                 WHEN r.kind = 'BENIGN' AND b.loaded <> r.expected_attempts THEN 'BENIGN_LOAD_MISMATCH'
                 WHEN r.kind = 'BENIGN' AND b.matched <> r.expected_attempts THEN 'BENIGN_MATCH_MISMATCH'
                 WHEN r.kind = 'BENIGN' THEN NULL
                 WHEN c.actual_attack <> r.expected_attempts THEN 'ATTACK_MISMATCH'
                 WHEN c.actual_control <> r.expected_controls THEN 'CONTROL_MISMATCH'
             END AS r10_reason,
             CASE WHEN r.kind = 'BENIGN' THEN b.loaded END AS benign_loaded,
             CASE WHEN r.kind = 'BENIGN' THEN b.matched END AS benign_matched
      FROM measurement_run r
      CROSS JOIN LATERAL (
          SELECT count(*) FILTER (WHERE v.attempt_role = 'ATTACK')  AS actual_attack,
                 count(*) FILTER (WHERE v.attempt_role = 'CONTROL') AS actual_control
          FROM verdict_result v
          WHERE v.run_id = r.run_id) c
      CROSS JOIN LATERAL (
          SELECT count(*) AS loaded, count(q.matched_rid) AS matched
          FROM benign_request q
          WHERE q.run_id = r.run_id) b) x;

COMMENT ON VIEW v_run_integrity IS 'ADR-S4-01 R10 (v1.8 R17 d BENIGN 분기): ATTACK — VALID = CLOSED ∧ ATTACK·CONTROL 실제 = 기대, '
    'BENIGN — VALID = CLOSED ∧ 기대 요청 수 = benign_request 적재 수 = 앱 로그 대조 수. INVALID = CLOSED ∧ (불일치 ∨ 기대 없음), INCOMPLETE = OPEN. '
    'r10_reason 은 첫 해당 1개. 지표는 VALID run 에서만 산출';
COMMENT ON COLUMN v_run_integrity.r10_reason IS 'OPEN | EXPECTED_MISSING | ATTACK_MISMATCH | CONTROL_MISMATCH | BENIGN_LOAD_MISMATCH | BENIGN_MATCH_MISMATCH | NULL(VALID)';

-- 4) M14 (R18)
CREATE VIEW v_benign_run AS
SELECT run_id FROM v_run_integrity WHERE kind = 'BENIGN' AND r10_status = 'VALID';
COMMENT ON VIEW v_benign_run IS '내부 — ADR-S4-01 v1.8 R17: M14 대상 run = kind BENIGN ∧ R10 VALID';

-- M14a FPR: 통제 × 엔드포인트(그 run 에 요청이 있는 엔드포인트만 — 없으면 행 없음 = 해당 없음(run 없음))
CREATE VIEW v_metric_m14a AS
WITH cell AS (
    SELECT r.run_id, c.unit AS control, e.endpoint, e.scenario
    FROM v_benign_run r
    CROSS JOIN metric_scope c
    JOIN benign_endpoint e ON EXISTS (SELECT 1 FROM benign_request q WHERE q.run_id = r.run_id AND q.endpoint = e.endpoint)
    WHERE c.kind = 'CONTROL'
), agg AS (
    SELECT cell.*,
           (SELECT count(*) FROM benign_request q
            WHERE q.run_id = cell.run_id AND q.endpoint = cell.endpoint AND q.matched_rid IS NOT NULL) AS n,
           (SELECT count(*) FROM benign_result b JOIN benign_request q ON q.run_id = b.run_id AND q.seq = b.seq
            WHERE b.run_id = cell.run_id AND q.endpoint = cell.endpoint AND b.control = cell.control AND b.alerted) AS x,
           (SELECT count(*) FROM benign_result b JOIN benign_request q ON q.run_id = b.run_id AND q.seq = b.seq
            WHERE b.run_id = cell.run_id AND q.endpoint = cell.endpoint AND b.control = cell.control) AS judged
    FROM cell
), judged AS (
    SELECT a.*,
           CASE
               WHEN a.control = 'APP_RULE' AND a.scenario = 'BRUTE_FORCE' THEN 'NOT_APPLICABLE'
               WHEN a.control = 'BACKEND_CORR' AND a.scenario <> 'BRUTE_FORCE' THEN 'NO_RULE'
               WHEN a.control = 'NIDS' AND NOT EXISTS (SELECT 1 FROM nids_sid_class k
                                                       WHERE k.class = 'ANALYTIC' AND k.scenario = a.scenario)
                   THEN 'NO_RULE'
               WHEN a.judged <> a.n THEN 'RESULT_MISMATCH'
               WHEN a.n = 0 THEN 'NO_DATA'
               ELSE 'OK'
           END AS status
    FROM agg a
)
SELECT j.run_id, 'ADR-S4-01 v1.8'::text AS definition_version, 'M14a_' || j.control AS metric_id, j.control,
       'SCENARIO'::text AS split_kind, j.scenario AS split_unit, j.endpoint,
       CASE WHEN j.status IN ('OK', 'NO_DATA') THEN j.x END AS x, j.n, w.p, w.lo, w.hi, j.status
FROM judged j
LEFT JOIN LATERAL wilson_ci(CASE WHEN j.status IN ('OK', 'NO_DATA') THEN j.x END, j.n) w ON true;

COMMENT ON VIEW v_metric_m14a IS 'ADR-S4-01 v1.8 M14a FPR (R3·R17·R18 a·b·d·f): FP 요청 / 대조된 정상 요청, 통제 × 엔드포인트(split_unit = 엔드포인트의 시나리오). '
    'NOT_APPLICABLE(APP_RULE × login)·NO_RULE(BACKEND_CORR × 웹, ANALYTIC sid 없는 NIDS)·RESULT_MISMATCH(결과 행 ≠ 요청 수)는 x·p NULL, n = 0 → NO_DATA';

-- M14b FDR: 짝 = 같은 rules_digest 의 VALID ATTACK run 중 스냅샷이 있는 가장 최근 run
CREATE VIEW v_metric_m14b AS
WITH pair AS (
    SELECT r.run_id,
           (SELECT a.run_id
            FROM v_run_integrity a
            JOIN measurement_run ma ON ma.run_id = a.run_id
            WHERE a.kind = 'ATTACK' AND a.r10_status = 'VALID' AND ma.rules_digest = mb.rules_digest
              AND EXISTS (SELECT 1 FROM metric_snapshot s WHERE s.run_id = a.run_id)
            ORDER BY ma.started_at DESC, a.run_id
            LIMIT 1) AS paired_run_id
    FROM v_benign_run r
    JOIN measurement_run mb ON mb.run_id = r.run_id
), cell AS (
    SELECT p.run_id, p.paired_run_id, c.unit AS control,
           (SELECT count(*) FROM benign_result b WHERE b.run_id = p.run_id AND b.control = c.unit) AS judged,
           (SELECT coalesce(sum(b.alert_count), 0) FROM benign_result b
            WHERE b.run_id = p.run_id AND b.control = c.unit) AS fp_alerts,
           (SELECT count(*)
            FROM verdict_result v
            JOIN verdict_member m ON m.verdict_id = v.id
            JOIN detection_link l ON l.correlation_id = m.correlation_id
            WHERE v.run_id = p.paired_run_id AND v.attempt_role = 'ATTACK' AND l.confidence >= 0.7
              AND l.technique IS NOT DISTINCT FROM v.technique_id
              AND CASE c.unit
                      WHEN 'APP_RULE' THEN l.control = 'APP_RULE'
                      WHEN 'NIDS' THEN l.control = 'NIDS'
                          AND l.rule_id IN (SELECT k.sid::text FROM nids_sid_class k WHERE k.class = 'ANALYTIC')
                      ELSE l.control = 'APP_RULE' AND v.unit_type IN ('BF_SEQUENCE', 'SPRAY_CAMPAIGN')
                          AND v.detection_status = 'DETECTED'
                  END) AS tp_alerts,
           EXISTS (SELECT 1 FROM nids_window_stat w WHERE w.run_id = p.paired_run_id) AS pair_nids_collected
    FROM pair p
    CROSS JOIN metric_scope c
    WHERE c.kind = 'CONTROL'
), judged AS (
    SELECT c.*, c.fp_alerts + c.tp_alerts AS n,
           CASE
               WHEN c.judged = 0 THEN 'NOT_APPLICABLE'
               WHEN c.paired_run_id IS NULL THEN 'NO_PAIR'
               WHEN c.control = 'NIDS' AND NOT c.pair_nids_collected THEN 'NOT_COLLECTED'
               WHEN c.fp_alerts + c.tp_alerts = 0 THEN 'NO_DATA'
               ELSE 'OK'
           END AS status
    FROM cell c
)
SELECT j.run_id, 'ADR-S4-01 v1.8'::text AS definition_version, 'M14b_' || j.control AS metric_id, j.control,
       'ALL'::text AS split_kind, 'ALL'::text AS split_unit, j.paired_run_id,
       CASE WHEN j.status IN ('OK', 'NO_DATA') THEN j.fp_alerts END AS x,
       CASE WHEN j.status IN ('OK', 'NO_DATA') THEN j.n END AS n,
       w.p, w.lo, w.hi, j.status
FROM judged j
LEFT JOIN LATERAL wilson_ci(CASE WHEN j.status IN ('OK', 'NO_DATA') THEN j.fp_alerts END,
                            CASE WHEN j.status IN ('OK', 'NO_DATA') THEN j.n END) w ON true;

COMMENT ON VIEW v_metric_m14b IS 'ADR-S4-01 v1.8 M14b FDR (R18 e): FP 알림 / (FP 알림 + 짝 run TP 알림), 통제별. 짝 없음 NO_PAIR, '
    '짝 run 이 NIDS 미수집이면 NIDS NOT_COLLECTED, 그 run 에 통제 적용 요청 없음 NOT_APPLICABLE — 모두 x·n·p NULL';

-- 룰 ID 별 기록 (판정 제외, R18 g)
CREATE VIEW v_metric_m14_rule AS
SELECT b.run_id, b.control AS sensor, r.rule_id, 'LINKED_COUNTED'::text AS kind, count(*) AS alerts
FROM benign_result b CROSS JOIN LATERAL unnest(b.linked_rule_ids) AS r (rule_id)
GROUP BY 1, 2, 3
UNION ALL
SELECT b.run_id, b.control, r.rule_id, 'LINKED_RECORDED', count(*)
FROM benign_result b CROSS JOIN LATERAL unnest(b.recorded_rule_ids) AS r (rule_id)
GROUP BY 1, 2, 3
UNION ALL
SELECT u.run_id, u.sensor, u.rule_id, 'UNLINKED_' || u.reason, count(*)
FROM benign_unlinked_alert u
GROUP BY 1, 2, 3, u.reason;

COMMENT ON VIEW v_metric_m14_rule IS 'ADR-S4-01 v1.8 R18 g: BENIGN run 룰 ID 별 알림 수(기록만) — LINKED_COUNTED(판정용) · LINKED_RECORDED(연결·판정 제외) · UNLINKED_<사유>';

-- 5) 스냅샷 — paired_run_id 추가, BENIGN VALID run 허용
ALTER TABLE metric_snapshot ADD COLUMN paired_run_id UUID;
COMMENT ON COLUMN metric_snapshot.paired_run_id IS 'ADR-S4-01 v1.8 R18 h: M14b 의 짝 ATTACK run(rules_digest 같음, 스냅샷 있는 가장 최근). 그 밖의 행은 NULL';

CREATE OR REPLACE FUNCTION metric_snapshot_require_valid_run() RETURNS trigger
    LANGUAGE plpgsql AS
$$
DECLARE
    v_status text;
    v_reason text;
    v_kind   text;
BEGIN
    SELECT r10_status, r10_reason, kind INTO v_status, v_reason, v_kind
    FROM validation.v_run_integrity WHERE run_id = NEW.run_id;
    IF v_status IS DISTINCT FROM 'VALID' OR v_kind NOT IN ('ATTACK', 'BENIGN') OR v_kind IS NULL THEN
        RAISE EXCEPTION 'R10 % (%) kind % — run % 스냅샷 거부 (ADR-S4-01 R13 a·v1.8 R18 h: VALID ATTACK·BENIGN run 만)',
            coalesce(v_status, '없음'), coalesce(v_reason, '-'), coalesce(v_kind, '-'), NEW.run_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

-- BENIGN run 스냅샷 (take_metric_snapshot 이 run 잠금·R10 VALID 확인 뒤 부른다)
CREATE FUNCTION take_benign_snapshot(p_run_id uuid) RETURNS integer
    LANGUAGE plpgsql AS
$$
DECLARE
    v_defs   text[];
    v_def    text;
    v_schema text;
    v_rows   integer;
BEGIN
    v_defs := ARRAY(
        SELECT DISTINCT d FROM (
            SELECT definition_version AS d FROM validation.v_metric_m14a WHERE run_id = p_run_id
            UNION SELECT definition_version FROM validation.v_metric_m14b WHERE run_id = p_run_id
        ) x ORDER BY d);
    IF cardinality(v_defs) <> 1 THEN
        RAISE EXCEPTION 'run % M14 뷰 definition_version 이 하나가 아니다 [%] — 스냅샷 거부 (R13 e)',
            p_run_id, array_to_string(v_defs, ', ')
            USING ERRCODE = 'check_violation';
    END IF;
    v_def := v_defs[1];

    IF EXISTS (SELECT 1 FROM validation.metric_snapshot WHERE run_id = p_run_id AND definition_version = v_def) THEN
        RAISE EXCEPTION 'run % definition_version % 스냅샷이 이미 있다 — 덮어쓰기 금지 (R13 d)', p_run_id, v_def
            USING ERRCODE = 'unique_violation';
    END IF;

    SELECT version INTO v_schema
    FROM validation.flyway_schema_history
    WHERE success AND version IS NOT NULL
    ORDER BY installed_rank DESC
    LIMIT 1;

    INSERT INTO validation.metric_snapshot (run_id, definition_version, metric_id, scope_kind, scope_key,
        numerator, denominator, point_estimate, ci_lower, ci_upper, status, source_view, snapshot_rule_version,
        schema_version, run_label, git_commit, git_dirty, rules_digest, paired_run_id)
    SELECT p_run_id, o.def, o.metric_id, o.scope_kind, o.scope_key, o.numerator, o.denominator, o.p, o.lo, o.hi,
           o.status, o.source_view, 'ADR-S4-01 v1.8', v_schema, r.label, r.git_commit, r.git_dirty, r.rules_digest,
           o.paired_run_id
    FROM (
        SELECT v.metric_id, v.split_kind AS scope_kind, v.split_unit AS scope_key, v.x AS numerator, v.n AS denominator,
               v.p, v.lo, v.hi, v.status, 'v_metric_m14a'::text AS source_view, v.definition_version AS def,
               NULL::uuid AS paired_run_id
        FROM validation.v_metric_m14a v WHERE v.run_id = p_run_id
        UNION ALL
        SELECT v.metric_id, v.split_kind, v.split_unit, v.x, v.n, v.p, v.lo, v.hi, v.status, 'v_metric_m14b',
               v.definition_version, v.paired_run_id
        FROM validation.v_metric_m14b v WHERE v.run_id = p_run_id
    ) o
    JOIN validation.measurement_run r ON r.run_id = p_run_id;

    GET DIAGNOSTICS v_rows = ROW_COUNT;
    IF v_rows = 0 THEN
        RAISE EXCEPTION 'run % M14 뷰 행 0 — 스냅샷할 값이 없다', p_run_id;
    END IF;
    RETURN v_rows;
END;
$$;
COMMENT ON FUNCTION take_benign_snapshot(uuid) IS 'ADR-S4-01 v1.8 R18 h: BENIGN VALID run 의 M14a·M14b 를 metric_snapshot 에 복사(snapshot_rule_version v1.8). take_metric_snapshot 에서만 부른다';
REVOKE ALL ON FUNCTION take_benign_snapshot(uuid) FROM PUBLIC;

-- 6) take_metric_snapshot — BENIGN 분기만 추가
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
    -- v1.8 R18 h: BENIGN VALID run 은 M14 만 (ATTACK 경로는 V6 와 같다)
    IF v_kind = 'BENIGN' THEN
        RETURN validation.take_benign_snapshot(p_run_id);
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

COMMENT ON FUNCTION take_metric_snapshot(uuid) IS 'ADR-S4-01 v1.6 R13 (v1.7: M07a·M13, v1.8: BENIGN run → M14a·M14b): VALID run 의 지표 뷰 결과를 '
    'metric_snapshot 에 변환 없이 복사, 행 수 반환. definition_version = 원 뷰 값(뷰마다 다르면 거부). INVALID·INCOMPLETE·중복(run+definition_version) 은 예외';
