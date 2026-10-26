-- validation schema v1 (S3-5a) — 상관분석·판정 결과 저장
-- 저장 금지: 비밀번호·요청 본문·응답 본문·Mock IMDS 값 (B안·민감정보 미복제). 원본은 참조 id(rid, alert_ref)만 둔다.

CREATE TABLE correlation (
    id                    BIGSERIAL        PRIMARY KEY,
    correlation_key       TEXT             NOT NULL,
    op_id                 UUID,
    op_id_resolved        BOOLEAN          NOT NULL,
    paw                   TEXT,
    ability_id            TEXT,
    rid                   TEXT,
    scenario              TEXT             NOT NULL,
    technique_id          TEXT,
    src_ip                TEXT,
    username              TEXT,
    segment_id            TEXT,
    attack_time           TIMESTAMPTZ      NOT NULL,
    last_attack_time      TIMESTAMPTZ      NOT NULL,
    observed_until        TIMESTAMPTZ      NOT NULL,
    gt_outcome            TEXT,
    attacker_verdict      TEXT,
    best_confidence       DOUBLE PRECISION NOT NULL,
    correlation_source    TEXT             NOT NULL,
    detection_status_raw  TEXT,
    mttd_ms_raw           BIGINT,
    ingestion_lag_ms      BIGINT,
    bf_failure_count      INTEGER          NOT NULL,
    bf_sequence           BOOLEAN          NOT NULL,
    spray                 BOOLEAN          NOT NULL,
    spray_account_count   INTEGER          NOT NULL,
    created_at            TIMESTAMPTZ      NOT NULL DEFAULT now(),
    CONSTRAINT uq_correlation_key UNIQUE (correlation_key),
    CONSTRAINT ck_correlation_gt_outcome CHECK (gt_outcome IN ('SUCCEEDED', 'FAILED', 'UNKNOWN')),
    CONSTRAINT ck_correlation_attacker_verdict CHECK (attacker_verdict IN ('SUCCEEDED', 'FAILED', 'EXECUTED', 'UNKNOWN')),
    CONSTRAINT ck_correlation_source CHECK (correlation_source IN ('RID', 'HEADER', 'UA_FALLBACK', 'NONE')),
    CONSTRAINT ck_correlation_detection_status_raw CHECK (detection_status_raw IN ('DETECTED', 'NOT_DETECTED', 'BLOCKED'))
);

COMMENT ON TABLE correlation IS '공격 1건(BF 는 srcIp+username 시퀀스) ↔ 탐지 알림 상관 결과';
COMMENT ON COLUMN correlation.correlation_key IS '가장 이른 이벤트 rid (rid 없으면 scenario|src_ip|attack_time epoch ms) — 재실행 시 upsert 키';
COMMENT ON COLUMN correlation.op_id IS 'Caldera operation UUID — OperationResolver 로 해석된 경우만, 아니면 NULL';
COMMENT ON COLUMN correlation.paw IS '로그 원본 correlation.op_id (= Caldera agent paw)';
COMMENT ON COLUMN correlation.attacker_verdict IS '공격자 측 판정 원본 AttackOutcome (EXECUTED 포함, 정규화 전)';
COMMENT ON COLUMN correlation.detection_status_raw IS '링크 기반 원시값 (S3-2: 관찰기간 내 usable 링크 유무) — 디버깅·Gap 분석용. 지표는 verdict_result.detection_status';
COMMENT ON COLUMN correlation.mttd_ms_raw IS '링크 기반 원시값 (S3-2: 관찰기간 내 첫 usable 링크) — 디버깅·Gap 분석용. 지표는 verdict_result.mttd_ms';

CREATE TABLE detection_link (
    id              BIGSERIAL        PRIMARY KEY,
    correlation_id  BIGINT           NOT NULL REFERENCES correlation (id) ON DELETE CASCADE,
    rule_id         TEXT             NOT NULL,
    technique       TEXT,
    alert_time      TIMESTAMPTZ      NOT NULL,
    match_path      TEXT             NOT NULL,
    confidence      DOUBLE PRECISION NOT NULL,
    src_ip          TEXT,
    username        TEXT,
    late            BOOLEAN          NOT NULL,
    alert_ref       TEXT,
    CONSTRAINT ck_detection_link_match_path CHECK (match_path IN ('RID', 'HEADER', 'UA_FALLBACK', 'TIME_ONLY'))
);

CREATE INDEX ix_detection_link_correlation ON detection_link (correlation_id);
COMMENT ON COLUMN detection_link.late IS 'alert_time > correlation.observed_until';
COMMENT ON COLUMN detection_link.alert_ref IS '원본 alert 참조 id (Wazuh alert id 등) — alert 본문은 저장하지 않는다';

CREATE TABLE verdict_result (
    id                     BIGSERIAL        PRIMARY KEY,
    unit_key               TEXT             NOT NULL,
    unit_type              TEXT             NOT NULL,
    scenario               TEXT,
    technique_id           TEXT,
    verdict                TEXT             NOT NULL,
    initial_verdict        TEXT             NOT NULL,
    uncertain_reason       TEXT,
    detection_status       TEXT             NOT NULL,
    gt_outcome             TEXT             NOT NULL,
    attacker_verdict       TEXT,
    attacker_match         BOOLEAN,
    overestimate           BOOLEAN          NOT NULL,
    best_confidence        DOUBLE PRECISION NOT NULL,
    mttd_ms                BIGINT,
    late_detection         BOOLEAN          NOT NULL,
    compromise_detected    BOOLEAN,
    compromise_alert_time  TIMESTAMPTZ,
    spray_account_count    INTEGER          NOT NULL,
    engine_version         TEXT             NOT NULL,
    run_id                 TEXT,
    decided_at             TIMESTAMPTZ      NOT NULL DEFAULT now(),
    CONSTRAINT uq_verdict_result_unit_key UNIQUE (unit_key),
    CONSTRAINT ck_verdict_result_unit_type CHECK (unit_type IN ('SINGLE', 'BF_SEQUENCE', 'SPRAY_CAMPAIGN')),
    CONSTRAINT ck_verdict_result_verdict CHECK (verdict IN ('SUCCEEDED_MISSED', 'SUCCEEDED_DETECTED', 'SUCCEEDED_BLOCKED',
        'BLOCKED', 'FAILED_DETECTED', 'FAILED_UNSEEN', 'UNCERTAIN')),
    CONSTRAINT ck_verdict_result_initial_verdict CHECK (initial_verdict IN ('SUCCEEDED_MISSED', 'SUCCEEDED_DETECTED',
        'SUCCEEDED_BLOCKED', 'BLOCKED', 'FAILED_DETECTED', 'FAILED_UNSEEN', 'UNCERTAIN')),
    CONSTRAINT ck_verdict_result_uncertain_reason CHECK (uncertain_reason IN ('GT_UNKNOWN', 'LOW_CONFIDENCE', 'NO_EVIDENCE')),
    CONSTRAINT ck_verdict_result_uncertain_consistency CHECK ((verdict = 'UNCERTAIN') = (uncertain_reason IS NOT NULL)),
    CONSTRAINT ck_verdict_result_detection_status CHECK (detection_status IN ('DETECTED', 'NOT_DETECTED', 'BLOCKED')),
    CONSTRAINT ck_verdict_result_gt_outcome CHECK (gt_outcome IN ('SUCCEEDED', 'FAILED', 'UNKNOWN')),
    CONSTRAINT ck_verdict_result_attacker_verdict CHECK (attacker_verdict IN ('SUCCEEDED', 'FAILED', 'UNKNOWN'))
);

COMMENT ON TABLE verdict_result IS 'Verdict 단위(SINGLE / BF_SEQUENCE / SPRAY_CAMPAIGN) 판정 — S4 지표는 이 테이블의 detection_status·mttd_ms 만 사용';
COMMENT ON COLUMN verdict_result.unit_key IS 'SINGLE/BF_SEQUENCE = unit:<correlation_key>, SPRAY_CAMPAIGN = spray:<segment_id> — upsert 키';
COMMENT ON COLUMN verdict_result.initial_verdict IS '관찰기간 내 alert 만으로 낸 최초 판정 — 갱신 시에도 보존';
COMMENT ON COLUMN verdict_result.attacker_verdict IS '정규화된 공격자 측 판정 (EXECUTED→UNKNOWN), fact 누락이면 NULL';
COMMENT ON COLUMN verdict_result.engine_version IS 'VerdictEngine 판정 규칙 버전 (S5 재검증 Before/After 비교용)';
COMMENT ON COLUMN verdict_result.run_id IS '검증 실행 회차 (S3-5b 에서 채움)';

CREATE TABLE verdict_member (
    verdict_id      BIGINT NOT NULL REFERENCES verdict_result (id) ON DELETE CASCADE,
    correlation_id  BIGINT NOT NULL REFERENCES correlation (id),
    PRIMARY KEY (verdict_id, correlation_id)
);

CREATE TABLE verdict_history (
    id            BIGSERIAL   PRIMARY KEY,
    verdict_id    BIGINT      NOT NULL REFERENCES verdict_result (id),
    from_verdict  TEXT        NOT NULL,
    to_verdict    TEXT        NOT NULL,
    reason        TEXT        NOT NULL,
    changed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ck_verdict_history_from_verdict CHECK (from_verdict IN ('SUCCEEDED_MISSED', 'SUCCEEDED_DETECTED',
        'SUCCEEDED_BLOCKED', 'BLOCKED', 'FAILED_DETECTED', 'FAILED_UNSEEN', 'UNCERTAIN')),
    CONSTRAINT ck_verdict_history_to_verdict CHECK (to_verdict IN ('SUCCEEDED_MISSED', 'SUCCEEDED_DETECTED',
        'SUCCEEDED_BLOCKED', 'BLOCKED', 'FAILED_DETECTED', 'FAILED_UNSEEN', 'UNCERTAIN')),
    CONSTRAINT ck_verdict_history_reason CHECK (reason IN ('LATE_ALERT', 'RECOMPUTED'))
);

COMMENT ON TABLE verdict_history IS 'verdict 변경 이력 — append-only (UPDATE/DELETE 트리거로 차단)';

CREATE FUNCTION verdict_history_append_only() RETURNS trigger
    LANGUAGE plpgsql AS
$$
BEGIN
    RAISE EXCEPTION 'verdict_history 는 append-only 입니다';
END;
$$;

CREATE TRIGGER trg_verdict_history_append_only
    BEFORE UPDATE OR DELETE ON verdict_history
    FOR EACH ROW EXECUTE FUNCTION verdict_history_append_only();
