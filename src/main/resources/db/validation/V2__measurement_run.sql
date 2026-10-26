-- validation schema v2 (S4-1) — 측정 run 차원 + 시도 역할 (ADR-S4-01 v1.1 R4·R6·R10)
-- run_id 는 백필 확인 후 S4-2 첫 마이그레이션에서 NOT NULL 로 전환한다.

CREATE TABLE measurement_run (
    run_id             UUID        PRIMARY KEY,
    label              TEXT        NOT NULL,
    kind               TEXT        NOT NULL,
    status             TEXT        NOT NULL,
    started_at         TIMESTAMPTZ NOT NULL,
    ended_at           TIMESTAMPTZ,
    git_commit         TEXT        NOT NULL,
    git_dirty          BOOLEAN,
    rules_digest       JSONB       NOT NULL,
    expected_attempts  INTEGER,
    expected_controls  INTEGER,
    notes              TEXT,
    CONSTRAINT ck_measurement_run_kind CHECK (kind IN ('ATTACK', 'BENIGN')),
    CONSTRAINT ck_measurement_run_status CHECK (status IN ('OPEN', 'CLOSED')),
    CONSTRAINT ck_measurement_run_closed_has_end CHECK ((status = 'CLOSED') = (ended_at IS NOT NULL))
);

COMMENT ON TABLE measurement_run IS '측정 실행 1회(run) — 지표는 run 단위로만 계산한다 (R4)';
COMMENT ON COLUMN measurement_run.git_dirty IS '측정 시 작업 트리 변경 여부. NULL = 알 수 없음(백필 run 전용) — 하네스가 여는 run 은 NULL 금지(코드 강제)';
COMMENT ON COLUMN measurement_run.rules_digest IS '{wazuh_rules, suricata_rules, caldera_adversary, caldera_abilities:{ability_id:sha256}} — 저장소 파일 sha256 (R9 Before/After 구분)';
COMMENT ON COLUMN measurement_run.expected_attempts IS 'R10: Σ(ability별 공격 시도 단위) × operation 수';
COMMENT ON COLUMN measurement_run.expected_controls IS 'R10: Σ(ability별 대조 요청 수) × operation 수';

ALTER TABLE verdict_result ALTER COLUMN run_id TYPE UUID USING run_id::uuid;
ALTER TABLE verdict_result
    ADD CONSTRAINT fk_verdict_result_run FOREIGN KEY (run_id) REFERENCES measurement_run (run_id);
CREATE INDEX ix_verdict_result_run ON verdict_result (run_id);
COMMENT ON COLUMN verdict_result.run_id IS '측정 run (measurement_run) — S4-1 부터 하네스가 INSERT 시 채운다. 갱신(UPDATE) 경로는 유지';

ALTER TABLE verdict_result
    ADD COLUMN attempt_role TEXT NOT NULL DEFAULT 'ATTACK',
    ADD CONSTRAINT ck_verdict_result_attempt_role CHECK (attempt_role IN ('ATTACK', 'CONTROL'));
COMMENT ON COLUMN verdict_result.attempt_role IS 'ATTACK = 공격 시도, CONTROL = 공격 ability 내 대조 요청 — CONTROL 은 공격 지표 분모 제외 (R6)';

-- CLOSED run 에는 새 verdict 를 넣지 않는다. 늦은 alert 에 의한 기존 verdict 갱신(UPDATE)·백필 귀속은 허용.
CREATE FUNCTION verdict_result_reject_closed_run() RETURNS trigger
    LANGUAGE plpgsql AS
$$
BEGIN
    IF NEW.run_id IS NOT NULL AND EXISTS (
            SELECT 1 FROM validation.measurement_run r WHERE r.run_id = NEW.run_id AND r.status = 'CLOSED') THEN
        RAISE EXCEPTION 'measurement_run % 은 CLOSED — 새 verdict INSERT 불가', NEW.run_id;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_verdict_result_reject_closed_run
    BEFORE INSERT ON verdict_result
    FOR EACH ROW EXECUTE FUNCTION verdict_result_reject_closed_run();
