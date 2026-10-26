package com.capstone.vuln.measure;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * NIDS sid 분류표 (ADR-S4-01 v1.7 "NIDS sid 분류표", docker/config/suricata/local.rules 원문 기준).
 *
 * <p>코드 상수로 둔다(AttemptManifest 와 같은 방식): 상관은 DB 조회 없이 이 표로 거르고,
 * V6 시드(validation.nids_sid_class)와의 일치는 NidsSidCatalogSeedTest 가 검사한다. 표 밖 sid 는 분류 없음(링크 제외).
 */
public final class NidsSidCatalog {

    /** scenario = metric_scope SCENARIO 단위, MARKER 는 null */
    public record Entry(int sid, NidsSidClass sidClass, String scenario) {
    }

    public static final NidsSidCatalog V1_7 = new NidsSidCatalog(build());

    private final Map<Integer, Entry> bySid = new LinkedHashMap<>();

    public NidsSidCatalog(List<Entry> entries) {
        for (Entry e : entries) {
            if (bySid.put(e.sid(), e) != null) {
                throw new IllegalArgumentException("sid 중복: " + e.sid());
            }
        }
    }

    public Optional<Entry> entry(int sid) {
        return Optional.ofNullable(bySid.get(sid));
    }

    public List<Entry> entries() {
        return Collections.unmodifiableList(new ArrayList<>(bySid.values()));
    }

    private static List<Entry> build() {
        List<Entry> e = new ArrayList<>();
        for (int sid = 1000001; sid <= 1000004; sid++) {
            e.add(new Entry(sid, NidsSidClass.MARKER, null));
        }
        e.add(new Entry(1000030, NidsSidClass.TELEMETRY, "BRUTE_FORCE"));
        e.add(new Entry(1000031, NidsSidClass.ANALYTIC, "BRUTE_FORCE"));
        e.add(new Entry(1000032, NidsSidClass.ANALYTIC, "BRUTE_FORCE"));
        for (int sid = 1000010; sid <= 1000019; sid++) {
            e.add(new Entry(sid, sid == 1000018 ? NidsSidClass.UNDECIDED : NidsSidClass.ANALYTIC, "SQLI"));
        }
        for (int sid = 1000020; sid <= 1000029; sid++) {
            e.add(new Entry(sid, NidsSidClass.ANALYTIC, "PATH_TRAVERSAL"));
        }
        e.add(new Entry(1000040, NidsSidClass.ANALYTIC, "PATH_TRAVERSAL"));
        e.add(new Entry(1000041, NidsSidClass.UNDECIDED, "PATH_TRAVERSAL"));
        for (int sid = 1000060; sid <= 1000069; sid++) {
            e.add(new Entry(sid, NidsSidClass.ANALYTIC, "SSRF"));
        }
        e.add(new Entry(1000087, NidsSidClass.ANALYTIC, "SSRF"));
        return e;
    }
}
