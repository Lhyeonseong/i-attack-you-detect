# ADR-S4-04: 검증 대시보드 표시 규칙 (dashboard-display)

- 상태: Accepted (2026-10-22, DRI 이현성)
- 개정 v1.0 (2026-10-22): 오전 설계안을 커밋. R-b 초안(막대 금지·점+선)은 커밋 전 현성 결정(10/22 12:45, v8)으로 대체됨.
- DRI: 이현성 / C: 없음(ADR-S4-02 D7 독립 검토로 대체)
- 기준 커밋: develop-v2 (S5-SQLI ④ 이후), ADR-S4-02 v1.3 과 한 커밋
- 근거 등급: (확인)=원문 확인 / (해석)=우리 적용

## 맥락
- 검증 대시보드는 ADR-S4-02 validation-api 가 반환하는 "측정 당시" 값을 사람이 읽는 화면이다. 측정값을 왜곡 없이, 불확실성과 출처를 함께 보여야 한다.
- 지표 정의·n=0 규칙·Wilson/Newcombe 는 ADR-S4-01, API 계약·권한·CSP·프런트 빌드는 ADR-S4-02. 이 ADR 은 **표시 규칙**만 정한다.

## 결정 (표시 규칙)

### R-a 확정(스냅샷) 기본
- 기본 표시는 **확정(metric_snapshot)** 값. 라이브(라이브 뷰 재계산)는 **"라이브(재계산)" 배지**로 구분. 캡처(스크린샷·보고)는 **확정만** 담는다.

### R-b 비율 표시
- 측정값 **%를 크게**, 바로 아래 보조로 **"x건 중 y건 · 95% 범위 a–b%"**(Wilson, z=1.959964). **%만 단독 표기 금지**.
- 개수 지표(예: 2/2 기법)는 **구간 없음**. 도넛·건수 막대 **허용**. 단, **막대 위에 오차막대를 얹지 않는다**(Correll & Gleicher 2014).

### R-c 특수 상태
- n=0 → **"해당 없음(n=0)"**. 차단(BLOCKED류) → **"N/A(IDS 모드)"**. (0%·빈 막대로 그리지 않는다 — ADR-S4-01 n=0 규칙.)

### R-d 비-VALID run
- 비-VALID run 은 **무결성 상태만** 표시(지표 값 미표시, API 409 와 일치).

### R-e Before/After
- 주 표시 = **차이 + Newcombe 95% 범위**(예: `−100%p · 95% 범위 −100 ~ −77.2%p`). Before·After 두 값은 **보조**.

### R-f 색 사용
- **색만으로 상태를 구분하지 않는다** — 배지·표에 **텍스트 병기**(R-j 접근성과 같은 축).

### R-g 출처 줄 (모든 화면 하단)
- run 라벨 · run id 앞 8자 · commit · rules_digest 앞 12자 · engine_version · definition_version · snapshot_rule_version · 캡처 시각(KST).

### R-h 신뢰도·심각도
- 신뢰도와 심각도는 **별도 열**. 혼합 점수·종합 점수·등급(A/B/C 등)은 **만들지 않는다**.

### R-i 화면 용어
- `Run` → **"측정"**. "관제 탐지" → **"탐지"**(단, 센서 이름 "앱 로그 관제"·"네트워크 관제"는 유지).
- 한계 문구·칸을 따로 두지 않는다(출처 줄 R-g 로 갈음).
- **공격 시도 140**과 **대조 요청 20**을 분리해 표시. **요청 기록 160**은 "기록 일치" 표시에만 쓴다(지표 분모 아님).

### R-j 접근성
- 기준 **WCAG 2.2 AA**(글자 대비 4.5:1, UI 요소 3:1, 모든 조작 키보드 가능, 초점 표시가 가려지지 않음) + **KWCAG**.
- 도넛·막대에 `role="img"`, `aria-label` 에 "x건 중 y건".
- 스모크(ADR-S4-02 Part 5)에서 **Playwright + @axe-core/playwright 로 8화면 검사 — 위반 0이어야 통과**.

## 화면 (8개)
1. 개요
2. 공격 결과
3. 공격 검증 상세
4. 탐지 분석
5. ATT&CK 검증
6. 시스템 상태
7. 공백 · 재검증 (한 화면)
8. 검증 결과
- **배치·문구의 원본은 현성이 전달할 v8 HTML**이며, 이 ADR 은 표시 규칙만 고정한다.

## 범주·수식어
- 탐지 범주: **None / Telemetry / Analytic** + 수식어 **Delayed · Configuration Change**.
- **DeTT&CT 식 가시성·탐지 분리**(예: 네트워크 SQLi = "로그만 · 경보 0/20").

## 프런트 스택
- React + TypeScript + Vite + **vega-lite(`ast:true` interpreter)**(ADR-S4-02 D9 CSP: `unsafe-eval` 없음과 정합). 버전은 구현 **Step 1에서 실측 고정**.

## 근거
- (확인) Correll & Gleicher 2014 — 막대 위 오차막대의 지각 왜곡(R-b).
- (확인) Hofman·Goldstein·Hullman, CHI 2020 — 불확실성 표현(구간 병기, R-b·R-e).
- (확인) ATT&CK Navigator v4.5 레이어 형식(ATT&CK 검증 화면·ADR-S4-02 /navigator-layer).
- (확인) DeTT&CT — 가시성·탐지 분리(범주·R-i).
- (해석) Picus·AttackIQ·Cymulate 벤더 자료 — 검증 결과 표시 관행(종합 등급은 R-h 로 배제).
- (확인) Kohavi 외·Dmitriev 외(KDD 2017)·Wilson/Newcombe — 비율은 분자·분모·구간 병기(R-b·R-e).
- (확인) Shneiderman 1996 — overview first, details on demand(화면 구성).
- (확인) WCAG 2.2(W3C 권고 2024-12-12) + KWCAG — 접근성(R-j).
- (확인) OWASP WSTG·PTES — 결과 보고 형식(성공 수준·증거).
- (해석) Gartner 2026 Digital Provenance — 출처 줄(R-g).

## 하지 않은 것
- 혼합/종합 점수·등급(R-h). 색 단독 구분(R-f). %만 단독·막대 오차막대(R-b). 라이브 값 캡처(R-a).
- 화면 배치·문구 확정(v8 HTML 원본 대기). 프런트 버전 고정(구현 Step 1).
