export interface ReportScenarioMeta {
  key: 'SQLI' | 'PATH_TRAVERSAL' | 'SSRF' | 'BRUTE_FORCE';
  name: string;
  technique: string;
  detection: string;
  kisa: string;
  remediation: string;
  followup: string;
}

export const REPORT_SCENARIOS: ReportScenarioMeta[] = [
  {
    key: 'SQLI',
    name: 'SQL 인젝션',
    technique: 'T1190',
    detection: 'DET0080',
    kisa: 'SI (상)',
    remediation: '입력값 바인딩(Prepared Statement) 적용',
    followup: '네트워크 탐지 룰 보완 후 재검증',
  },
  {
    key: 'PATH_TRAVERSAL',
    name: '경로 조작',
    technique: 'T1190',
    detection: 'DET0080',
    kisa: 'FD (상)',
    remediation: '파일명 DB 매칭 · 경로 문자 필터링',
    followup: '인코딩 우회 변형 추가 측정',
  },
  {
    key: 'SSRF',
    name: 'SSRF',
    technique: 'T1190',
    detection: 'AN0222',
    kisa: 'SF (상)',
    remediation: '허용 URL · IP 목록 검증 · 내부 주소 차단',
    followup: '대조 요청 판정과 내부 서비스 도달을 재검증',
  },
  {
    key: 'BRUTE_FORCE',
    name: '무차별 대입',
    technique: 'T1110',
    detection: 'DET0463',
    kisa: 'AU (상)',
    remediation: '로그인 시도 횟수 제한 · 비밀번호 정책 강화 · 추가 인증',
    followup: '원시 NIDS 경보와 최종 상관 판정을 분리해 추적',
  },
];

export const FINDING_SCENARIO: Record<string, ReportScenarioMeta['key']> = {
  'V-01': 'SQLI',
  'V-02': 'PATH_TRAVERSAL',
  'V-03': 'SSRF',
  'V-04': 'BRUTE_FORCE',
};
