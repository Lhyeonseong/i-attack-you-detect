-- validation schema v5 (S4-3) — metric_snapshot: 측정 시점 지표 값을 복사·고정하는 기록 층 (ADR-S4-01 v1.6 R13)
-- 라이브 뷰(V4)는 볼 때마다 현재 정의로 재계산한다. 스냅샷은 그와 별개 층이며 덮어쓰지 않고 누적한다.
-- 불변: UPDATE·DELETE 행 트리거 + BEFORE TRUNCATE 문장 트리거 + REVOKE UPDATE, DELETE, TRUNCATE (run_id 컬럼 UPDATE 만 FK 확인용으로 허용, R13 d).
-- 한계: 테이블 소유자(validation_rw)는 ALTER TABLE … DISABLE TRIGGER·재GRANT 가 가능 — 불변 보장은 일반 DML 에 한정
-- (detections/known-gaps.md Gap #8). 잘못된 스냅샷은 DELETE 대신 metric_snapshot_withdrawal 에 철회 사유를 남긴다(R13 d').

-- 1) 기록 층 — 1행 = 관측 1개 (R13 b, Tidy Data). denominator = n(표본 수): 비율은 분모, MTTD·H2 는 표본 수
CREATE TABLE metric_snapshot (
    snapshot_id               BIGSERIAL        PRIMARY KEY,
    run_id                    UUID             NOT NULL REFERENCES measurement_run (run_id) ON DELETE RESTRICT,
    definition_version        TEXT             NOT NULL,
    metric_id                 TEXT             NOT NULL,
    scope_kind                TEXT             NOT NULL,
    scope_key                 TEXT             NOT NULL,
    numerator                 BIGINT,
    denominator               BIGINT,
    point_estimate            DOUBLE PRECISION,
    ci_lower                  DOUBLE PRECISION,
    ci_upper                  DOUBLE PRECISION,
    p50_ms                    DOUBLE PRECISION,
    p95_ms                    DOUBLE PRECISION,
    overestimate_count        BIGINT,
    uncertain_count           BIGINT,
    criteria_met              BOOLEAN,
    status                    TEXT             NOT NULL,
    source_view               TEXT             NOT NULL,
    snapshot_rule_version     TEXT             NOT NULL,
    schema_version            TEXT             NOT NULL,
    run_label                 TEXT             NOT NULL,
    git_commit                TEXT             NOT NULL,
    git_dirty                 BOOLEAN,
    rules_digest              JSONB            NOT NULL,
    snapshot_at               TIMESTAMPTZ      NOT NULL DEFAULT now(),
    CONSTRAINT uq_metric_snapshot_observation UNIQUE (run_id, definition_version, metric_id, scope_kind, scope_key),
    CONSTRAINT ck_metric_snapshot_definition_version CHECK (btrim(definition_version) <> ''),
    CONSTRAINT ck_metric_snapshot_scope_kind CHECK (scope_kind IN ('ALL', 'SCENARIO', 'TECHNIQUE')),
    CONSTRAINT ck_metric_snapshot_counts CHECK (
        (numerator IS NULL OR numerator >= 0) AND (denominator IS NULL OR denominator >= 0)
        AND (numerator IS NULL OR denominator IS NULL OR numerator <= denominator)),
    CONSTRAINT ck_metric_snapshot_interval CHECK (
        (point_estimate IS NULL AND ci_lower IS NULL AND ci_upper IS NULL)
        OR (0 <= ci_lower AND ci_lower <= point_estimate AND point_estimate <= ci_upper AND ci_upper <= 1)),
    CONSTRAINT ck_metric_snapshot_empty_is_null CHECK (
        denominator IS DISTINCT FROM 0 OR (point_estimate IS NULL AND p50_ms IS NULL AND p95_ms IS NULL))
);

COMMENT ON TABLE metric_snapshot IS 'ADR-S4-01 v1.6 R13: 측정 시점 지표 값의 불변 기록(라이브 뷰와 별개 층, 값은 변환 없이 복사). 1행 = 관측 1개 '
    '(run_id, definition_version, metric_id, scope_kind, scope_key). VALID run 만, UPDATE·DELETE·TRUNCATE 거부(트리거 + 권한), 철회는 metric_snapshot_withdrawal';
COMMENT ON COLUMN metric_snapshot.definition_version IS 'R13 e: 원 지표 뷰들의 definition_version 값 그대로(V4 = ADR-S4-01 v1.4). 뷰마다 다르면 스냅샷 거부. '
    '지표 정의가 바뀌면(R7) 새 값의 행으로 추가된다(R13 d)';
COMMENT ON COLUMN metric_snapshot.metric_id IS 'V4 지표 id. M05 분포는 M05_<source>, H2 는 M05_H2_RID_HEADER·M05_H2_NONE (뷰 1행 = 관측 2개)';
COMMENT ON COLUMN metric_snapshot.scope_key IS '분할 단위(split_unit). M06a·M06b 는 단위가 아닌 범위 목록 전체라 ALL';
COMMENT ON COLUMN metric_snapshot.denominator IS 'n — 비율의 분모, M04 는 mttd 표본 수, H2 는 링크 시도 수. M12 는 NULL';
COMMENT ON COLUMN metric_snapshot.status IS 'R13 c: 원 뷰 값 그대로 복사, 변환 금지 — 뷰 status(OK·NO_DATA·NOT_APPLICABLE), H2 는 h2_status(PASS·FAIL·INCONCLUSIVE)';
COMMENT ON COLUMN metric_snapshot.criteria_met IS 'M09 만 — v_metric_attacker.criteria_met 그대로(측정값, D3). 그 밖의 지표는 NULL';
COMMENT ON COLUMN metric_snapshot.snapshot_rule_version IS 'R13 e: 스냅샷 규칙 버전 상수 ADR-S4-01 v1.6';
COMMENT ON COLUMN metric_snapshot.schema_version IS 'R13 e: 스냅샷 시점 Flyway 최신 version';
COMMENT ON COLUMN metric_snapshot.git_dirty IS 'run 값 복사 — 백필 run(S3-GATE-dc66322) 은 NULL(알 수 없음) 그대로';

-- 2) 철회 기록 — append-only, 원 스냅샷 행은 그대로 (R13 d', OSF registration 의 withdrawal)
CREATE TABLE metric_snapshot_withdrawal (
    withdrawal_id      BIGSERIAL   PRIMARY KEY,
    run_id             UUID        NOT NULL REFERENCES measurement_run (run_id) ON DELETE RESTRICT,
    definition_version TEXT        NOT NULL,
    reason             TEXT        NOT NULL,
    withdrawn_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_metric_snapshot_withdrawal UNIQUE (run_id, definition_version),
    CONSTRAINT ck_metric_snapshot_withdrawal_reason CHECK (btrim(reason) <> '')
);

COMMENT ON TABLE metric_snapshot_withdrawal IS 'ADR-S4-01 v1.6 R13 d'': 스냅샷(run_id, definition_version) 철회 사유 — append-only, 원 행은 삭제하지 않는다';

-- 3) 불변 트리거 — 행(UPDATE·DELETE) + 문장(TRUNCATE, PostgreSQL 은 TRUNCATE 를 문장 트리거로만 받는다)
CREATE FUNCTION metric_snapshot_reject_change() RETURNS trigger
    LANGUAGE plpgsql AS
$$
BEGIN
    RAISE EXCEPTION '% 는 불변 (ADR-S4-01 R13 d) — % 거부. 잘못된 스냅샷은 validation.withdraw_metric_snapshot 으로 철회',
        TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER trg_metric_snapshot_reject_change
    BEFORE UPDATE OR DELETE ON metric_snapshot
    FOR EACH ROW EXECUTE FUNCTION metric_snapshot_reject_change();
CREATE TRIGGER trg_metric_snapshot_reject_truncate
    BEFORE TRUNCATE ON metric_snapshot
    FOR EACH STATEMENT EXECUTE FUNCTION metric_snapshot_reject_change();
CREATE TRIGGER trg_metric_snapshot_withdrawal_reject_change
    BEFORE UPDATE OR DELETE ON metric_snapshot_withdrawal
    FOR EACH ROW EXECUTE FUNCTION metric_snapshot_reject_change();
CREATE TRIGGER trg_metric_snapshot_withdrawal_reject_truncate
    BEFORE TRUNCATE ON metric_snapshot_withdrawal
    FOR EACH STATEMENT EXECUTE FUNCTION metric_snapshot_reject_change();

-- 4) INSERT 조건 — 함수를 거치지 않은 직접 INSERT 에도 R13 a(VALID ATTACK run 만)·철회 대상 존재를 강제
CREATE FUNCTION metric_snapshot_require_valid_run() RETURNS trigger
    LANGUAGE plpgsql AS
$$
DECLARE
    v_status text;
    v_reason text;
    v_kind   text;
BEGIN
    SELECT r10_status, r10_reason, kind INTO v_status, v_reason, v_kind
    FROM validation.v_run_integrity WHERE run_id = NEW.run_id;
    IF v_status IS DISTINCT FROM 'VALID' OR v_kind IS DISTINCT FROM 'ATTACK' THEN
        RAISE EXCEPTION 'R10 % (%) kind % — run % 스냅샷 거부 (ADR-S4-01 R13 a: VALID ATTACK run 만)',
            coalesce(v_status, '없음'), coalesce(v_reason, '-'), coalesce(v_kind, '-'), NEW.run_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_metric_snapshot_require_valid_run
    BEFORE INSERT ON metric_snapshot
    FOR EACH ROW EXECUTE FUNCTION metric_snapshot_require_valid_run();

CREATE FUNCTION metric_snapshot_withdrawal_require_snapshot() RETURNS trigger
    LANGUAGE plpgsql AS
$$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM validation.metric_snapshot s
                   WHERE s.run_id = NEW.run_id AND s.definition_version = NEW.definition_version) THEN
        RAISE EXCEPTION 'run % definition_version % 스냅샷 없음 — 철회할 대상이 없다', NEW.run_id, NEW.definition_version
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_metric_snapshot_withdrawal_require_snapshot
    BEFORE INSERT ON metric_snapshot_withdrawal
    FOR EACH ROW EXECUTE FUNCTION metric_snapshot_withdrawal_require_snapshot();

-- 5) 권한 — 소유자 자신도 일반 DML 로는 고칠 수 없게 (소유자는 재GRANT 가능: Gap #8)
REVOKE UPDATE, DELETE, TRUNCATE ON metric_snapshot, metric_snapshot_withdrawal FROM PUBLIC, validation_rw;
-- run_id 컬럼 UPDATE 만 다시 허용 — measurement_run 삭제 때 FK 확인 쿼리(SELECT … FOR KEY SHARE)가 이 테이블 소유자 권한으로 돌고,
-- 잠금 절은 최소 한 컬럼의 UPDATE 권한이 필요하다(PostgreSQL 16 SELECT 문서). 실제 수정은 위 불변 트리거가 막는다.
-- 이로써 스냅샷 없는 run 은 삭제 가능, 스냅샷 있는 run 은 FK ON DELETE RESTRICT 로 삭제 불가 (ADR-S4-01 R13 d)
GRANT UPDATE (run_id) ON metric_snapshot TO validation_rw;
GRANT UPDATE (run_id) ON metric_snapshot_withdrawal TO validation_rw;

-- 6) 스냅샷 실행 — VALID 확인 → 뷰 definition_version 일치 확인 → 중복 확인 → 각 지표 뷰에서 INSERT … SELECT → 행 수
--    값 계산은 뷰가 하고 여기는 복사만 한다(R13 c: 변환 금지)
CREATE FUNCTION take_metric_snapshot(p_run_id uuid) RETURNS integer
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
    ) o
    JOIN validation.measurement_run r ON r.run_id = p_run_id;

    GET DIAGNOSTICS v_rows = ROW_COUNT;
    IF v_rows = 0 THEN
        RAISE EXCEPTION 'run % 지표 뷰 행 0 — 스냅샷할 값이 없다', p_run_id;
    END IF;
    RETURN v_rows;
END;
$$;

COMMENT ON FUNCTION take_metric_snapshot(uuid) IS 'ADR-S4-01 v1.6 R13: VALID ATTACK run 의 S4-2 지표 뷰 결과 전부를 metric_snapshot 에 변환 없이 복사, 행 수 반환. '
    'definition_version = 원 뷰 값(뷰마다 다르면 거부). INVALID·INCOMPLETE·BENIGN·중복(run+definition_version) 은 예외';

-- 7) 철회 — 사유 기록만, 원 행 유지
CREATE FUNCTION withdraw_metric_snapshot(p_run_id uuid, p_definition_version text, p_reason text) RETURNS bigint
    LANGUAGE plpgsql AS
$$
DECLARE
    v_id bigint;
BEGIN
    IF p_reason IS NULL OR btrim(p_reason) = '' THEN
        RAISE EXCEPTION 'withdraw_metric_snapshot: 철회 사유가 필요하다' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF EXISTS (SELECT 1 FROM validation.metric_snapshot_withdrawal
               WHERE run_id = p_run_id AND definition_version = p_definition_version) THEN
        RAISE EXCEPTION 'run % definition_version % 는 이미 철회됐다', p_run_id, p_definition_version
            USING ERRCODE = 'unique_violation';
    END IF;
    INSERT INTO validation.metric_snapshot_withdrawal (run_id, definition_version, reason)
    VALUES (p_run_id, p_definition_version, p_reason)
    RETURNING withdrawal_id INTO v_id;
    RETURN v_id;
END;
$$;

COMMENT ON FUNCTION withdraw_metric_snapshot(uuid, text, text) IS 'ADR-S4-01 v1.6 R13 d'': 스냅샷 철회 사유 기록(append-only). 원 스냅샷 행은 그대로, 없는 스냅샷·중복 철회는 예외';

REVOKE ALL ON FUNCTION take_metric_snapshot(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION withdraw_metric_snapshot(uuid, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION take_metric_snapshot(uuid) TO validation_rw;
GRANT EXECUTE ON FUNCTION withdraw_metric_snapshot(uuid, text, text) TO validation_rw;
