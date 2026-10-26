-- validation schema 부트스트랩 (S3-5a) — DB 관리자(POSTGRES_USER)로 실행, 재실행해도 안전
--
-- 사용:
--   docker exec -i postgres psql -U <관리자> -d vulndb -v valpw="$VALIDATION_DB_PASSWORD" < db/bootstrap/validation_role.sql
--   (-v app_role=<취약 앱 role> 생략 시 vulnuser)
--
-- 비밀번호는 psql 변수로만 받는다 — 파일에 하드코딩 금지 (CWE-798)
-- 주의: 현재 취약 앱 role(vulnuser)은 슈퍼유저라 아래 REVOKE 가 실효가 없다 (detections/known-gaps.md Gap #3)

\set ON_ERROR_STOP on

\if :{?valpw}
\else
DO $$ BEGIN RAISE EXCEPTION 'psql 변수 valpw 가 필요합니다: -v valpw="$VALIDATION_DB_PASSWORD"'; END $$;
\endif

\if :{?app_role}
\else
\set app_role vulnuser
\endif

-- role: 없을 때만 생성, 속성·비밀번호는 매번 맞춘다
SELECT 'CREATE ROLE validation_rw'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'validation_rw') \gexec
ALTER ROLE validation_rw WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD :'valpw';

-- schema: validation_rw 소유
CREATE SCHEMA IF NOT EXISTS validation AUTHORIZATION validation_rw;
ALTER SCHEMA validation OWNER TO validation_rw;

-- 취약 앱·PUBLIC 차단 (스키마 + 기존/향후 테이블)
REVOKE ALL ON SCHEMA validation FROM PUBLIC;
REVOKE ALL ON SCHEMA validation FROM :"app_role";
REVOKE ALL ON ALL TABLES IN SCHEMA validation FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA validation FROM :"app_role";
ALTER DEFAULT PRIVILEGES FOR ROLE validation_rw IN SCHEMA validation REVOKE ALL ON TABLES FROM PUBLIC;
