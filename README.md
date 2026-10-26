# I Attack, You Detect

## MITRE ATT&CK 기반 자동화 보안 검증 및 방어 통제 평가 플랫폼

> **취약점을 찾는 데서 끝나지 않습니다. 실제 공격을 실행하고 성공 여부를 판정하며, 방어 통제가 이를 탐지했는지 확인한 뒤 탐지 공백을 개선하고 동일한 기준으로 다시 검증합니다.**

---

## Why

취약점이 존재한다는 사실만으로 현재의 방어 통제가 실제 공격을 식별할 수 있는지는 알 수 없습니다.

실제 운영에서는 다음 질문까지 확인할 수 있어야 합니다.

- 발견된 취약점은 실제로 악용 가능한가?
- 공격이 성공했을 때 보안 통제가 이를 탐지하는가?
- 공격과 탐지 이벤트를 정확히 연결할 수 있는가?
- 탐지하지 못한 구간은 어디인가?
- 탐지 룰이나 상관 로직을 개선한 뒤 실제 효과가 있었는가?
- 탐지 성능을 높이는 과정에서 정상 트래픽 오탐은 증가하지 않았는가?

I Attack, You Detect는 이 질문들을 하나의 자동화 검증 사이클로 연결합니다.

```text
취약점 / 노출 분석
        ↓
공격 가능성 판단
        ↓
자동 공격 실행
        ↓
실제 공격 성공 여부 판정
        ↓
보안 탐지 확인
        ↓
공격 · 탐지 상관분석
        ↓
최종 판정 · 정량 지표
        ↓
탐지 공백 / 오탐 분석
        ↓
개선 후 재검증
```

---

## Final Validation

최종 기준 측정: `FINAL-BASELINE-2026-10-26`

| 검증 항목 | 결과 |
| --- | ---: |
| 공격 시도 | 140건 |
| 공격 탐지 | 140 / 140 |
| 판정 가능 | 140 / 140 |
| 판정 불가 | 0건 |
| SQL Injection NIDS | 20 / 20 |
| 정상 로그인 최종 FP | 0 / 300 |
| 정상 로그인 Raw NIDS | 2 / 300 |

### Before → After

```text
SQL Injection Network Detection
Before   0 / 20
After   20 / 20
```

```text
Benign Login False Positive
Initial          76 / 300
Raw NIDS          2 / 300
Final Verdict     0 / 300
```

원시 경보를 삭제하거나 숨기지 않고 보존합니다.

센서에서 발생한 원시 경보와 최종 상관 판정을 분리해 관측 결과와 최종 오탐 판정을 각각 확인할 수 있도록 구성했습니다.

---

## What Makes It Different

### 1. 명령 실행 성공과 실제 공격 성공을 구분

Caldera에서 명령이 정상적으로 실행되었다는 사실만으로 공격 성공으로 판단하지 않습니다.

대상 시스템의 실제 HTTP 응답과 시나리오별 성공 기준을 이용해 취약점이 실제로 악용되었는지 별도로 판정합니다.

---

### 2. 공격 성공과 탐지를 별도 지표로 측정

```text
M01  →  실제 공격 성공 여부
M02  →  성공한 공격의 탐지 여부
```

공격이 실제로 성공했는지와 성공한 공격을 방어 시스템이 탐지했는지를 서로 다른 지표로 평가합니다.

이 구조를 통해 공격 실행 결과와 방어 통제의 탐지 성능이 하나의 수치로 섞이지 않도록 했습니다.

---

### 3. Multi-Layer Detection

| Layer | 역할 |
| --- | --- |
| Application Rule | 애플리케이션 로그 기반 탐지 |
| NIDS | 네트워크 트래픽 기반 탐지 |
| Backend Correlation | 여러 관측 결과를 연결한 최종 상관 판정 |

단순히 경보 발생 여부만 확인하지 않습니다.

어느 탐지 계층에서 공격을 식별했고 어느 계층에 공백이 있었는지 분리해 확인합니다.

---

### 4. Attack–Detection Correlation

자동 공격 요청에 검증 식별 정보를 전달합니다.

```text
X-Caldera-Op-Id
X-Caldera-Technique
X-Caldera-Ability
```

필요한 경우 User-Agent fallback을 사용해 공격 요청, 애플리케이션 로그, 네트워크 경보, 최종 판정 결과를 연결합니다.

---

### 5. False Positive Validation

공격 탐지율이 높다는 사실만으로 탐지 품질이 충분하다고 판단하지 않습니다.

정상 트래픽 corpus를 별도로 실행해 탐지 개선이 실제 사용자 요청에 오탐을 발생시키는지도 함께 측정합니다.

```text
Raw Sensor Alert
       ↓
Backend Correlation
       ↓
Final False Positive Verdict
```

---

### 6. Revalidation

탐지 공백을 발견한 뒤 룰이나 상관 로직을 수정하는 데서 끝내지 않습니다.

```text
Before
   ↓
Gap Analysis
   ↓
Detection / Correlation Improvement
   ↓
After
   ↓
Regression Guardrail
```

동일한 기준으로 다시 측정해 개선 효과와 부작용을 함께 검증합니다.

---

## Attack Scenarios

| Scenario | MITRE ATT&CK | Target |
| --- | --- | --- |
| SQL Injection | T1190 | Product Search API |
| Path Traversal | T1190 | File Download API |
| SSRF | T1190 | Preview API / Mock IMDS |
| Brute Force | T1110 | Login API |

각 시나리오는 공격 실행에서 끝나지 않고 성공 판정, 탐지, 상관분석, 재검증까지 하나의 흐름으로 연결됩니다.

---

## Architecture

```text
                  ┌─────────────────────┐
                  │    MITRE Caldera    │
                  │  Automated Attacks  │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │     Target Web      │
                  │   Vulnerable APIs   │
                  └──────┬──────┬───────┘
                         │      │
                App Logs │      │ Network Traffic
                         │      │
                         ▼      ▼
                  ┌─────────┐ ┌──────────┐
                  │  Wazuh  │ │ Suricata │
                  └────┬────┘ └────┬─────┘
                       │           │
                       └─────┬─────┘
                             ▼
                  ┌─────────────────────┐
                  │   Validation API    │
                  │                     │
                  │ · Verdict           │
                  │ · Correlation       │
                  │ · Metrics           │
                  │ · Gap Analysis      │
                  │ · Revalidation      │
                  └──────────┬──────────┘
                             │
                ┌────────────┴────────────┐
                ▼                         ▼
        ┌──────────────┐          ┌───────────────┐
        │ PostgreSQL   │          │ React         │
        │ Measurement  │          │ Dashboard     │
        │ Database     │          │ + PDF Report  │
        └──────────────┘          └───────────────┘
```

---

## Dashboard

각 화면은 같은 숫자를 반복하는 대신 서로 다른 판단 질문에 답하도록 역할을 분리했습니다.

| Screen | 핵심 질문 |
| --- | --- |
| Overview | 현재 검증 상태는 정상인가? |
| Attacks | 어떤 공격이 실행됐고 실제로 성공했는가? |
| Detection | 어느 탐지 계층에서 공격을 식별했고 오탐은 발생했는가? |
| ATT&CK | 어떤 Technique을 검증했는가? |
| System | 어떤 환경과 버전에서 측정했는가? |
| Revalidate | 개선 전보다 실제로 좋아졌는가? |
| Report | 최종 결과와 근거는 무엇인가? |

대시보드의 결과값은 임의의 숫자를 사용하지 않고 측정 DB와 metric snapshot을 결과의 기준 데이터로 사용합니다.

---

## Measurement Reliability

검증 결과에서 중요한 것은 높은 숫자 자체보다 그 결과를 설명하고 다시 검증할 수 있는지입니다.

다음 정보를 측정 provenance로 관리합니다.

- Measurement Run ID
- Git Commit
- Definition Version
- Rule Digest
- Metric Snapshot
- Expected Attack / Control Count
- Integrity Status
- Verdict Engine Version

다음 원칙도 함께 적용합니다.

- 공격 성공과 탐지 성공을 별도 측정
- 판정 불가 결과를 명시적으로 관리
- 정상 트래픽으로 False Positive 검증
- 개선 전·후 동일 기준 재측정
- 과거 baseline과 측정 근거 보존
- 현재 결과와 과거 결과 분리
- Dashboard와 PDF의 기준 데이터 통일

---

## Evidence Preservation

현재 상태를 좋게 보이게 만들기 위해 과거 실패 결과를 제거하지 않습니다.

```text
SQLi NIDS
Initial Evidence   0 / 20
Final Result      20 / 20
```

```text
Benign Login
Initial Evidence  76 / 300
Raw NIDS           2 / 300
Final FP            0 / 300
```

과거 값은 개선 과정을 설명하는 측정 근거로 유지하고, 현재 Dashboard의 상태는 최신 측정값을 기준으로 계산합니다.

---

## Report

Dashboard와 PDF 보고서는 동일한 측정 데이터와 공통 scenario metadata를 사용합니다.

주요 보고 항목은 다음과 같습니다.

- 공격 성공 결과
- 탐지 결과
- 센서별 탐지 상태
- False Positive
- 탐지 공백
- 개선 이력
- 공격자 판정 일치
- 측정 신뢰 정보
- 조치 권고

---

## Technology Stack

### Security Validation

- MITRE Caldera
- Suricata
- Wazuh

### Backend

- Java 17
- Spring Boot
- Gradle
- PostgreSQL

### Frontend

- React
- TypeScript
- Vite

### Infrastructure

- Docker
- Docker Compose
- Ubuntu Linux

---

## Repository Structure

```text
.
├── db/                  # Database schema & migrations
├── detections/          # Detection rules & measurement artifacts
├── docker/              # Security validation environment
├── docs/                # Architecture & validation documentation
├── src/                 # Core application / validation logic
└── validation-api/
    ├── src/             # Validation backend
    └── ui/              # React dashboard
```

---

## Demo Flow

```text
1. Final measurement 선택
        ↓
2. 실제 공격 결과 확인
        ↓
3. 공격 성공 판정 확인
        ↓
4. 탐지 계층별 결과 확인
        ↓
5. 탐지 공백 / 오탐 확인
        ↓
6. Before / After 재검증
        ↓
7. ATT&CK 검증 범위 확인
        ↓
8. 최종 Report / PDF 확인
```

---

## Core Principle

> **Attack execution is not the final result.**

공격을 실행했다는 사실보다 중요한 것은 공격이 실제로 성공했는지, 방어 통제가 이를 탐지했는지, 탐지하지 못했다면 개선 후 실제로 좋아졌는지를 확인하는 것입니다.

I Attack, You Detect는 이 전체 과정을 하나의 측정 가능한 보안 검증 사이클로 구현합니다.

---

## Team

공격은 내가 탐지는 너가해조
I Attack, You Detect

MITRE ATT&CK Based Automated Security Validation Platform
