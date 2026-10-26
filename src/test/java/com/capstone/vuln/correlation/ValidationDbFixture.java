package com.capstone.vuln.correlation;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.MountableFile;

import javax.sql.DataSource;
import java.util.UUID;

/**
 * S4-2 지표 기반 테스트 공용 — postgres 컨테이너(PostgresTestImage) 1개를 클래스 간 공유(싱글턴, 정리는 Ryuk).
 * 부트스트랩 SQL(validation_role.sql) + ValidationSchemaMigrator 로 운영과 같은 경로로 최신 버전까지 올린다.
 */
public abstract class ValidationDbFixture {

    protected static final PostgreSQLContainer<?> PG = new PostgreSQLContainer<>(PostgresTestImage.IMAGE);
    protected static final DataSource DS;
    protected static final JdbcTemplate JDBC;

    static {
        PG.start();
        DS = bootstrap(PG);
        JDBC = new JdbcTemplate(DS);
    }

    /**
     * 시작된 컨테이너에 부트스트랩 SQL 로 validation_rw·schema 를 만들고 최신 버전까지 migrate 한 validation_rw DataSource.
     * 불변 행(metric_snapshot)을 남기는 테스트는 공유 컨테이너 대신 자기 컨테이너에 이걸 쓴다.
     */
    public static DataSource bootstrap(PostgreSQLContainer<?> pg) {
        DataSource ds = bootstrapUnmigrated(pg);
        ValidationSchemaMigrator.migrate(ds);
        return ds;
    }

    /** 부트스트랩 후 Flyway target 버전까지만 migrate (V5 → V6 이행 검사용) */
    public static DataSource bootstrap(PostgreSQLContainer<?> pg, String targetVersion) {
        DataSource ds = bootstrapUnmigrated(pg);
        migrateTo(ds, targetVersion);
        return ds;
    }

    /** ValidationSchemaMigrator 와 같은 설정 + target (null = 최신) */
    public static void migrateTo(DataSource ds, String targetVersion) {
        org.flywaydb.core.api.configuration.FluentConfiguration c = org.flywaydb.core.Flyway.configure()
                .dataSource(ds)
                .schemas(ValidationSchemaMigrator.SCHEMA)
                .defaultSchema(ValidationSchemaMigrator.SCHEMA)
                .createSchemas(false)
                .locations("classpath:db/validation");
        if (targetVersion != null) {
            c.target(targetVersion);
        }
        c.load().migrate();
    }

    private static DataSource bootstrapUnmigrated(PostgreSQLContainer<?> pg) {
        DataSource ds;
        try {
            ExecResult role = pg.execInContainer("psql", "-v", "ON_ERROR_STOP=1", "-U", pg.getUsername(),
                    "-d", pg.getDatabaseName(), "-c", "CREATE ROLE vulnapp LOGIN NOSUPERUSER");
            check(role);
            pg.copyFileToContainer(MountableFile.forHostPath("db/bootstrap/validation_role.sql"), "/tmp/validation_role.sql");
            String password = UUID.randomUUID().toString();
            check(pg.execInContainer("psql", "-U", pg.getUsername(), "-d", pg.getDatabaseName(),
                    "-v", "valpw=" + password, "-v", "app_role=vulnapp", "-f", "/tmp/validation_role.sql"));
            ds = new DriverManagerDataSource(pg.getJdbcUrl(), "validation_rw", password);
        } catch (Exception e) {
            throw new IllegalStateException("validation DB 부트스트랩 실패", e);
        }
        return ds;
    }

    private static void check(ExecResult r) {
        if (r.getExitCode() != 0) {
            throw new IllegalStateException(r.getStderr());
        }
    }

    /**
     * verdict·run 테이블 비우기 (metric_scope 같은 시드는 유지). measurement_run 은 DELETE 로 지운다 —
     * TRUNCATE … CASCADE 는 FK 로 묶인 metric_snapshot·metric_snapshot_withdrawal(V5, TRUNCATE 거부)까지 닿는다.
     * 스냅샷 없는 run 의 DELETE 는 V5 run_id 컬럼 UPDATE 권한으로 FK 확인이 통과한다(ADR-S4-01 R13 d).
     */
    protected static void truncateRunData() {
        JDBC.execute("TRUNCATE validation.verdict_history, validation.verdict_member, validation.verdict_result, "
                + "validation.detection_link, validation.correlation RESTART IDENTITY CASCADE");
        JDBC.update("DELETE FROM validation.measurement_run");
    }
}
