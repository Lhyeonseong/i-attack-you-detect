package com.capstone.vuln.correlation;

/** Verdict 1개가 대표하는 공격 단위 */
public enum UnitType {
    /** 단건형 (SQLi·PT·SSRF) */
    SINGLE,
    /** BF 계정 집중형 — 같은 srcIp+username 시퀀스 (AN1275/AN1276) */
    BF_SEQUENCE,
    /** BF 스프레이 — 같은 srcIp 구간의 여러 계정을 1건으로 접음 (AN1277) */
    SPRAY_CAMPAIGN
}
