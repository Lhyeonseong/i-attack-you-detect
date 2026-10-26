-- 취약 앱 전용 non-superuser role (S3-INFRA, Gap #3 해소) — DB 관리자(POSTGRES_USER)로 실행, 재실행해도 안전
--
-- 사용 (target-web 를 vuln_app 으로 재생성하기 전에 실행):
--   docker exec -i postgres psql -U <관리자> -d vulndb -v apppw="$VULN_APP_DB_PASSWORD" < db/bootstrap/app_role.sql
--
-- 비밀번호는 psql 변수로만 받는다 — 파일에 하드코딩 금지 (CWE-798)
-- 앱은 기동마다 schema.sql 로 users/products 를 DROP 후 CREATE 하므로, 기존 객체 소유권을 vuln_app 으로 넘겨야 한다.

\set ON_ERROR_STOP on

\if :{?apppw}
\else
DO $$ BEGIN RAISE EXCEPTION 'psql 변수 apppw 가 필요합니다: -v apppw="$VULN_APP_DB_PASSWORD"'; END $$;
\endif

-- role: 없을 때만 생성, 속성·비밀번호는 매번 맞춘다
SELECT 'CREATE ROLE vuln_app'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vuln_app') \gexec
ALTER ROLE vuln_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'apppw';

-- 접속·public schema 권한 (schema.sql 의 DROP/CREATE 에 CREATE 필요)
SELECT current_database() AS dbname \gset
GRANT CONNECT ON DATABASE :"dbname" TO vuln_app;
GRANT USAGE, CREATE ON SCHEMA public TO vuln_app;

-- schema.sql 이 DROP/CREATE 하는 객체: users, products (+ SERIAL 시퀀스 users_id_seq/products_id_seq,
-- 인덱스 users_pkey/users_username_key/products_pkey). 테이블 소유권 변경은 소유 시퀀스·인덱스에도 따라간다.
ALTER TABLE IF EXISTS public.users OWNER TO vuln_app;
ALTER TABLE IF EXISTS public.products OWNER TO vuln_app;

-- 서버 파일/프로그램 role 미부여 확인 (COPY ... TO PROGRAM 등 차단) — 소속돼 있으면 중단
SELECT count(*) = 0 AS no_server_roles
FROM pg_auth_members m
JOIN pg_roles granted ON granted.oid = m.roleid
JOIN pg_roles member ON member.oid = m.member
WHERE member.rolname = 'vuln_app'
  AND granted.rolname IN ('pg_execute_server_program', 'pg_read_server_files', 'pg_write_server_files',
                          'pg_read_all_data', 'pg_write_all_data', 'pg_signal_backend') \gset
\if :no_server_roles
\else
DO $$ BEGIN RAISE EXCEPTION 'vuln_app 이 서버 파일/프로그램 role 에 소속돼 있습니다 — 수동 확인 필요'; END $$;
\endif

-- 결과 확인 (비밀번호 없음)
SELECT r.rolname, r.rolsuper, r.rolcreatedb, r.rolcreaterole, r.rolreplication, r.rolbypassrls
FROM pg_roles r WHERE r.rolname = 'vuln_app';
SELECT c.relname, c.relkind, pg_get_userbyid(c.relowner) AS owner
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' ORDER BY c.relname;
