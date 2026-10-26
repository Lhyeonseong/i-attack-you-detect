package com.capstone.vuln.measure;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** S4-1b — 본측정 엔트리포인트는 MEASURE_LABEL(= measurement_run.label) 없이 돌지 않는다 (기본값 없음) */
class CampaignRunnerLabelTest {

    @Test
    void labelIsTakenFromEnv() {
        assertEquals("S4-1b-SMOKE", CampaignRunnerIT.requireLabel(Map.of("MEASURE_LABEL", "S4-1b-SMOKE")));
    }

    @Test
    void missingOrBlankLabelFails() {
        assertThrows(IllegalStateException.class, () -> CampaignRunnerIT.requireLabel(Map.of()));
        assertThrows(IllegalStateException.class, () -> CampaignRunnerIT.requireLabel(Map.of("MEASURE_LABEL", "  ")));
    }
}
