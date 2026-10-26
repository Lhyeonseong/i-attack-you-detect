-- validation_ro 읽기 전용 role 부트스트랩 (S4-6) — DB 관리자(POSTGRES_USER)로 실행, 재실행해도 안전
--
-- 사용(운영 — 비밀번호를 argv 에 노출하지 않음):
--   VALIDATION_RO_PASSWORD="$ROPW" docker exec -i -e PGPASSWORD -e VALIDATION_RO_PASSWORD postgres \
--     psql -U <관리자> -d vulndb -v dbname=vulndb -f /tmp/validation_ro_role.sql
--   (테스트 등에서는 -v ropw=<pw> 로 넘겨도 됨 — 그 경우 env 보다 -v 가 우선)
--   (-v dbname 생략 시 vulndb)
--
-- 비밀번호는 환경변수 또는 psql 변수로만 받는다 — 파일 하드코딩·argv 노출 금지 (CWE-798/CWE-214)
-- 객체 권한(USAGE/SELECT/EXECUTE)은 여기서 주지 않는다 — V12__validation_ro_grants.sql 이 허용 목록대로 부여.
-- ADR-S4-02 D2: LOGIN·NOSUPERUSER·NOCREATEDB·NOCREATEROLE·default_transaction_read_only=on.

\set ON_ERROR_STOP on

-- ropw: -v 로 안 주어졌으면 VALIDATION_RO_PASSWORD 환경변수에서 읽는다(인자 노출 방지)
\if :{?ropw}
\else
\getenv ropw VALIDATION_RO_PASSWORD
\endif
\if :{?ropw}
\else
DO $$ BEGIN RAISE EXCEPTION 'ropw 가 필요합니다: VALIDATION_RO_PASSWORD 환경변수 또는 -v ropw='; END $$;
\endif
-- 빈/짧은 비밀번호는 오류로 멈춘다(\quit 아님)
SELECT CASE WHEN length(:'ropw') >= 8 THEN 'yes' ELSE 'no' END AS ropw_ok \gset
\if :ropw_ok
\else
DO $$ BEGIN RAISE EXCEPTION 'VALIDATION_RO_PASSWORD 가 비었거나 8자 미만입니다'; END $$;
\endif

\if :{?dbname}
\else
\set dbname vulndb
\endif

-- role: 없을 때만 생성, 속성·비밀번호는 매번 맞춘다 (ADR-S4-02 D2)
SELECT 'CREATE ROLE validation_ro'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'validation_ro') \gexec
ALTER ROLE validation_ro WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION
    CONNECTION LIMIT 6 PASSWORD :'ropw';

-- 읽기 전용 보조장치(보안 경계는 '쓰기 권한 없음'; 세션에서 해제 가능하므로 경계 아님 — ADR-S4-02 D2)
ALTER ROLE validation_ro SET default_transaction_read_only = on;

-- statement_timeout: S4-6 Step1 공개 뷰 8개 EXPLAIN ANALYZE 최대 실행시간(v_metric_h2 3960.586ms) ×10 올림 = 40s.
--   근거 로그: detections/measurements/evidence/2026-10-22_s4-6-check.log (D2). 역할별 짧은 timeout 권고(CYBERTEC).
ALTER ROLE validation_ro SET statement_timeout = '40s';

-- DB 접속만 허용(스키마·객체 권한은 V12). CONNECT 는 DB 레벨이라 허용 목록 테스트 범위 밖.
GRANT CONNECT ON DATABASE :"dbname" TO validation_ro;
