package com.capstone.vuln.correlation;

public class CorrelationInfo {
    private final String opId;
    private final String techniqueId;
    private final String abilityId;
    private final CorrelationSource source;
    private final String sourceIp;
    private final String userAgent;

    public CorrelationInfo(String opId, String techniqueId, String abilityId,
                           CorrelationSource source, String sourceIp, String userAgent) {
        this.opId = opId;
        this.techniqueId = techniqueId;
        this.abilityId = abilityId;
        this.source = source;
        this.sourceIp = sourceIp;
        this.userAgent = userAgent;
    }

    public String getOpId() { return opId; }
    public String getTechniqueId() { return techniqueId; }
    public String getAbilityId() { return abilityId; }
    public CorrelationSource getSource() { return source; }
    public String getSourceIp() { return sourceIp; }
    public String getUserAgent() { return userAgent; }

    public boolean isResolved() {
        return source != CorrelationSource.NONE && opId != null;
    }

    @Override
    public String toString() {
        return String.format("CorrelationInfo{opId=%s, tech=%s, ability=%s, source=%s, ip=%s}",
                opId, techniqueId, abilityId, source, sourceIp);
    }
}