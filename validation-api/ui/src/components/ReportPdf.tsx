import type { AttackerRow, Finding, GapItem, RateRow, RunDetail, SnapshotRow } from '../api/types';
import { NO_RECORD } from '../lib/ratio';

interface Props {
  run: RunDetail | null;
  displayName: string;
  findings: Finding[];
  gaps: GapItem[];
  rates: RateRow[];
  snapshot: SnapshotRow[];
  snapshotBefore: SnapshotRow[];
  attacker: AttackerRow | undefined;
  benignLogin: SnapshotRow[];
}

const SCENARIOS = [
  {
    key: 'SQLI',
    name: 'SQL 인젝션',
    kisa: 'SI (상)',
    technique: 'T1190',
    remediation: '입력값 바인딩(Prepared Statement) 적용',
    followup: 'Suricata SQL 인젝션 탐지 룰 보완',
  },
  {
    key: 'PATH_TRAVERSAL',
    name: '경로 조작',
    kisa: 'FD (상)',
    technique: 'T1190',
    remediation: '파일명 DB 매칭 · 확장자 허용 목록 · 경로 문자 필터링',
    followup: '인코딩 우회 변형 추가 측정',
  },
  {
    key: 'SSRF',
    name: '서버 측 요청 위조 (SSRF)',
    kisa: 'SF (상)',
    technique: 'T1190',
    remediation: '허용 URL · IP 목록 검증 · 내부 주소 차단 · 네트워크 분리',
    followup: 'SSRF 탐지 및 내부 서비스 도달 검증 유지',
  },
  {
    key: 'BRUTE_FORCE',
    name: '인증 시도 제한 없음 · 약한 비밀번호',
    kisa: 'AU (상)',
    technique: 'T1110',
    remediation: '로그인 시도 횟수 제한 · 비밀번호 정책 강화 · 추가 인증',
    followup: '정상 로그인 오탐 조건 보완',
  },
] as const;

function rate(rows: RateRow[], metricId: string, scopeKey: string) {
  return rows.find(
    (r) => r.metric_id === metricId && r.scope_kind === 'SCENARIO' && r.scope_key === scopeKey,
  );
}

function text(v: unknown) {
  return v == null || v === '' ? NO_RECORD : String(v);
}

export function ReportPdf({
  run,
  displayName,
  findings,
  gaps,
  rates,
  snapshot,
  snapshotBefore,
  attacker,
  benignLogin,
}: Props) {
  const currentAll = snapshot.find((r) => r.metric_id === 'M02' && r.scope_key === 'ALL');
  const beforeAll = snapshotBefore.find((r) => r.metric_id === 'M02' && r.scope_key === 'ALL');
  const scenarios = rates.filter((r) => r.metric_id === 'M01' && r.scope_kind === 'SCENARIO');
  const successCount = scenarios.filter((r) => r.n > 0 && r.x === r.n).length;
  const loginNids = benignLogin.find(
    (r) => r.metric_id === 'M14a_NIDS' && r.scope_key === 'BRUTE_FORCE',
  );

  return (
    <article className="pdf-report">
      <section className="pdf-cover">
        <div className="pdf-kicker">AUTOMATED SECURITY VALIDATION REPORT</div>
        <h1>보안 검증 결과 보고서</h1>
        <p className="pdf-subtitle">MITRE ATT&amp;CK 기반 자동화 보안 검증 및 방어 통제 평가</p>

        <div className="pdf-meta-grid">
          <div><span>측정명</span><b>{displayName}</b></div>
          <div><span>검증 대상</span><b>Target Web</b></div>
          <div><span>측정 시작</span><b>{text(run?.started_at)}</b></div>
          <div><span>측정 종료</span><b>{text(run?.ended_at)}</b></div>
          <div><span>판정 상태</span><b>확정</b></div>
          <div><span>기록 검증</span><b>{run?.integrity_status === 'VALID' ? '일치' : text(run?.integrity_status)}</b></div>
        </div>
      </section>

      <section className="pdf-section">
        <h2>1. 검증 요약</h2>
        <div className="pdf-summary-grid">
          <div><span>시나리오 성공</span><b>{successCount} / {scenarios.length}</b><small>정답지 기준</small></div>
          <div><span>전체 탐지</span><b>{currentAll ? `${currentAll.x} / ${currentAll.n}` : NO_RECORD}</b><small>현재 측정</small></div>
          <div><span>개선 전 탐지</span><b>{beforeAll ? `${beforeAll.x} / ${beforeAll.n}` : NO_RECORD}</b><small>Before 기준</small></div>
          <div><span>판정 일치</span><b>{attacker ? `${attacker.x} / ${attacker.n}` : NO_RECORD}</b><small>공격자 판정 = 정답지</small></div>
        </div>

        <table className="pdf-table compact">
          <tbody>
            <tr><th>공격 기대 건수</th><td>{text(run?.expected_attempts)}</td><th>대조 기대 건수</th><td>{text(run?.expected_controls)}</td></tr>
            <tr><th>전체 기대 요청</th><td>{(run?.expected_attempts ?? 0) + (run?.expected_controls ?? 0)}</td><th>판정 불가</th><td>{text(attacker?.uncertain)}</td></tr>
            <tr><th>관찰 시간</th><td>30초 (실측 지연 p95 × 2)</td><th>과대평가</th><td>{text(attacker?.overestimate)}</td></tr>
          </tbody>
        </table>
      </section>

      <section className="pdf-section pdf-page-start pdf-page-2">
        <h2>2. 발견 취약점</h2>
        <table className="pdf-table">
          <thead>
            <tr>
              <th>ID</th><th>취약점</th><th>위치</th><th>KISA</th><th>대상 상태</th><th>탐지</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.id}>
                <td>{f.id}</td>
                <td><b>{f.title}</b></td>
                <td>{f.location}</td>
                <td>{f.kisa}</td>
                <td>{f.target_status}</td>
                <td>{f.detection}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="pdf-section pdf-page-start pdf-page-3">
        <h2>3. 취약점별 상세</h2>
        <div className="pdf-findings">
          {Array.from({ length: Math.ceil(findings.length / 2) }, (_, rowIndex) => {
            const pair = findings.slice(rowIndex * 2, rowIndex * 2 + 2);

            return (
              <div className="pdf-finding-row" key={`finding-row-${rowIndex}`}>
                {pair.map((f) => (
                  <div className="pdf-finding" key={f.id}>
                    <div className="pdf-finding-head">
                      <span>{f.id}</span>
                      <h3>{f.title}</h3>
                    </div>
                    <dl>
                      <div><dt>위치</dt><dd>{f.location}</dd></div>
                      <div><dt>설명</dt><dd>{f.description}</dd></div>
                      <div><dt>확인된 영향</dt><dd>{f.impact}</dd></div>
                      <div><dt>분류</dt><dd>{f.tags.join(' · ')}</dd></div>
                      <div><dt>ATT&amp;CK</dt><dd>{f.technique_id}</dd></div>
                      <div><dt>탐지</dt><dd>{f.detection}</dd></div>
                      <div><dt>취약점 조치</dt><dd>{f.remediation}</dd></div>
                      <div><dt>탐지 보완</dt><dd>{f.detection_followup}</dd></div>
                    </dl>
                  </div>
                ))}
              </div>
            );
          })}
        </div>
      </section>

      <section className="pdf-section pdf-page-start pdf-page-4">
        <h2>4. 시나리오별 탐지 결과</h2>
        <table className="pdf-table">
          <thead>
            <tr>
              <th>시나리오</th><th>ATT&amp;CK</th><th>KISA</th><th>탐지 건수</th><th>탐지율</th><th>조치 권고</th><th>탐지 보완</th>
            </tr>
          </thead>
          <tbody>
            {SCENARIOS.map((s) => {
              const r = rate(rates, 'M02', s.key);
              const pct = r?.p != null ? `${(r.p * 100).toFixed(1)}%` : NO_RECORD;
              const followup = s.key === 'BRUTE_FORCE' && loginNids
                ? `${s.followup} · 정상 로그인 네트워크 오탐 ${loginNids.x ?? 0}/${loginNids.n}`
                : s.followup;
              return (
                <tr key={s.key}>
                  <td><b>{s.name}</b></td>
                  <td>{s.technique}</td>
                  <td>{s.kisa}</td>
                  <td>{r ? `${r.x}/${r.n}` : NO_RECORD}</td>
                  <td>{pct}</td>
                  <td>{s.remediation}</td>
                  <td>{followup}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </section>

      <section className="pdf-section pdf-page-start pdf-page-5">
        <h2>5. 개선 및 재검증 이력</h2>
        <table className="pdf-table">
          <thead>
            <tr>
              <th>Gap</th><th>제목</th><th>발견 결과</th><th>개선 내용</th><th>재검증 결과</th><th>상태</th>
            </tr>
          </thead>
          <tbody>
            {gaps.filter((g) => g.status !== '발견').map((g) => (
              <tr key={g.id}>
                <td>{g.id}</td>
                <td>{g.title}</td>
                <td>{g.found_note}</td>
                <td>{g.fix !== '—' ? `${g.fix} ${g.fix_note ? `(${g.fix_note})` : ''}` : '—'}</td>
                <td>{g.reval_note}</td>
                <td>{g.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="pdf-section">
        <h2>6. 측정 근거</h2>
        <table className="pdf-table compact">
          <tbody>
            <tr>
              <th>공격자 판정</th>
              <td>{attacker ? `${attacker.x}/${attacker.n} 일치` : NO_RECORD}</td>
            </tr>
            <tr>
              <th>요청 기록</th>
              <td>기대 {(run?.expected_attempts ?? 0) + (run?.expected_controls ?? 0)}건 · 기록 검증 {run?.integrity_status === 'VALID' ? '일치' : text(run?.integrity_status)}</td>
            </tr>
            <tr>
              <th>판정 불가</th>
              <td>{text(attacker?.uncertain)}건</td>
            </tr>
            <tr>
              <th>관찰 시간</th>
              <td>30초 (실측 지연 p95 × 2)</td>
            </tr>
          </tbody>
        </table>
      </section>

      <section className="pdf-section pdf-conclusion">
        <h2>7. 결론</h2>
        <p>
          본 측정에서는 {scenarios.length}개 공격 시나리오를 대상으로 자동 공격, 성공 여부 판정,
          관제 탐지 및 상관분석을 수행했습니다. 현재 측정 기준 탐지는
          {' '}
          <b>{currentAll ? `${currentAll.x}/${currentAll.n}` : NO_RECORD}</b>
          이며, 발견된 탐지 공백과 오탐 항목은 개선·재검증 이력으로 관리합니다.
        </p>
      </section>

      <footer className="pdf-footer">
        <span>보안 검증 결과 보고서</span>
        <span>{displayName}</span>
        <span>판정 상태 · 확정</span>
      </footer>
    </article>
  );
}
