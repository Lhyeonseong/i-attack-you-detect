-- V11 — 출처 보존 run_provenance_note (ADR-S4-02 D11) + API 노출 뷰 v_api_attempt (D4/C2)
-- Flyway defaultSchema=validation 이므로 이름은 비한정(기존 V 파일 관례).

-- ── D11 출처 보존 ───────────────────────────────────────────────────────────
-- measurement_run 은 수정하지 않는다. 스택 버전 등 출처는 이 append-only 표에만 쌓는다.
-- 커밋된 증거 로그에 있는 값만 INSERT(seed: db/provenance/*). 원천 없으면 넣지 않고 화면 "기록 없음".
CREATE TABLE run_provenance_note (
    note_id      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id       UUID NOT NULL REFERENCES measurement_run(run_id),
    item         TEXT NOT NULL,              -- 예: wazuh, suricata, spring_boot, caldera, postgresql
    value        TEXT NOT NULL,              -- 예: 4.14.9
    source_file  TEXT NOT NULL,              -- detections/measurements/evidence/<파일>
    source_line  INTEGER,                    -- 증거 로그 줄 번호(없으면 NULL)
    recorded_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- 멱등 재삽입용 유니크(표현식: source_line NULL 도 같은 행으로 취급 → stack_basis 중복 방지).
CREATE UNIQUE INDEX uq_run_provenance
    ON run_provenance_note (run_id, item, source_file, COALESCE(source_line, -1));
COMMENT ON TABLE run_provenance_note IS
  'ADR-S4-02 D11 출처 보존(append-only). 커밋된 증거 로그에 있는 값만 INSERT. UPDATE/DELETE/TRUNCATE 차단.';

-- append-only: UPDATE/DELETE(행)·TRUNCATE(문장) 차단. metric_snapshot(V5) 와 같은 방식.
CREATE FUNCTION run_provenance_note_reject_change() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'run_provenance_note 는 append-only 입니다 (%)', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END; $$;

CREATE TRIGGER trg_run_provenance_reject_change
    BEFORE UPDATE OR DELETE ON run_provenance_note
    FOR EACH ROW EXECUTE FUNCTION run_provenance_note_reject_change();
CREATE TRIGGER trg_run_provenance_reject_truncate
    BEFORE TRUNCATE ON run_provenance_note
    FOR EACH STATEMENT EXECUTE FUNCTION run_provenance_note_reject_change();

-- 트리거 함수 PUBLIC EXECUTE 회수(최소권한). 트리거는 소유자 맥락으로 실행되므로 동작엔 영향 없음.
-- 이로써 validation_ro 가 PUBLIC 경유로 EXECUTE 를 상속받지 않는다(V12 허용목록 = 통계 3개뿐).
REVOKE ALL ON FUNCTION run_provenance_note_reject_change() FROM PUBLIC;

-- ── API 노출 뷰 v_api_attempt (ADR-S4-02 D4 / Step1 C2 허용 컬럼만) ──────────
-- 노출: verdict_result 판정 컬럼 + correlation 의 식별 메타(op_id·rid·ability_id·attack_time·source).
-- 미노출: 자격증명·원본 로그·payload(스키마에 없음) + username·src_ip(식별자, C2 제외 결정).
-- security_invoker 기본(false) → validation_ro 는 이 뷰에만 SELECT 받고 기반 테이블 권한은 없음.
CREATE VIEW v_api_attempt AS
SELECT
    v.run_id,
    v.id               AS attempt_id,
    v.unit_key,
    v.scenario,
    v.technique_id,
    v.attempt_role,
    v.gt_outcome,
    v.attacker_verdict,
    v.attacker_match,
    v.verdict,
    v.initial_verdict,
    v.detection_status,
    v.mttd_ms,
    v.best_confidence,
    v.late_detection,
    v.engine_version,
    v.decided_at,
    c.op_id,
    c.rid,
    c.ability_id,
    c.attack_time,
    c.correlation_source
FROM verdict_result v
LEFT JOIN LATERAL (
    SELECT co.op_id, co.rid, co.ability_id, co.attack_time, co.correlation_source
    FROM verdict_member vm
    JOIN correlation co ON co.id = vm.correlation_id
    WHERE vm.verdict_id = v.id
    ORDER BY co.attack_time NULLS LAST, co.id
    LIMIT 1
) c ON true;
COMMENT ON VIEW v_api_attempt IS
  'validation-api 시도 목록(ADR-S4-02 D4/C2). username·src_ip·원본로그·payload 미노출. attempt 당 대표 correlation 1건.';

-- ── API 연결 경보 표 v_api_alert_link (화면 ④ "연결된 경보 표": 경보 수 ≠ 탐지된 시도 수) ──
-- detection_link 를 시도(verdict_result)·run 에 연결해 노출. username·src_ip·alert_ref 미노출.
CREATE VIEW v_api_alert_link AS
SELECT
    vr.run_id,
    vr.id            AS attempt_id,     -- 연결된 시도(verdict_result.id)
    co.rid,                             -- 시도 연결키(correlation rid)
    dl.rule_id,
    dl.control,
    dl.alert_time,
    dl.match_path,
    dl.confidence
FROM detection_link dl
JOIN correlation co   ON co.id = dl.correlation_id
JOIN verdict_member vm ON vm.correlation_id = dl.correlation_id
JOIN verdict_result vr ON vr.id = vm.verdict_id;
COMMENT ON VIEW v_api_alert_link IS
  'validation-api 연결 경보(ADR-S4-02 D4·ADR-S4-04 화면④). username·src_ip·alert_ref 미노출. 경보 1건이 여러 시도에 연결되면 행 분리.';
