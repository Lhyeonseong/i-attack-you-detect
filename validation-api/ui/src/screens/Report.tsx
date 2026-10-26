import { Link } from 'react-router-dom';
import html2pdf from 'html2pdf.js';
import { Layout } from '../components/Layout';
import { BadgeText } from '../components/Badge';
import { RatioBlock } from '../components/RatioBlock';
import { ReportPdf } from '../components/ReportPdf';
import '../styles/report-pdf.css';
import { useDashboard } from '../components/DashboardContext';
import { useAsync } from '../lib/useAsync';
import { api } from '../api';
import { byMetricScope, byScope } from '../lib/select';
import { NO_RECORD } from '../lib/ratio';
import type { SnapshotRow, RateRow, AttackerRow } from '../api/types';
import '../styles/report.css';

interface ScenarioMetaRow {
  status: 'OK' | 'PARTIAL';
  name: string; det: string; kisa: string; scope: string;
  app: { t: string; cls: string }; net: { t: string; cls: string }; backend: string;
  key: string; remediation: string; followup: string;
}

const SCEN_ROWS: ScenarioMetaRow[] = [
  { status: 'PARTIAL', name: 'SQL 인젝션', det: 'T1190 · DET0080', kisa: 'SI (상)', scope: '취약 · 성공 20/20', app: { t: '탐지', cls: 'b-ok' }, net: { t: '로그만 · 경보 0/20', cls: 'b-at' }, backend: '대상 아님', key: 'SQLI', remediation: '입력값 바인딩(Prepared Statement) 적용', followup: 'Suricata 1000013을 디코딩된 따옴표까지 검사하도록 보완' },
  { status: 'OK', name: '경로 조작', det: 'T1190 · DET0080', kisa: 'FD (상)', scope: '취약 · 성공', app: { t: '탐지', cls: 'b-ok' }, net: { t: '탐지', cls: 'b-ok' }, backend: '대상 아님', key: 'PATH_TRAVERSAL', remediation: '파일명 DB 매칭 · 경로 문자 필터링', followup: '인코딩 우회 변형 추가 측정 (Gap #2)' },
  { status: 'OK', name: 'SSRF', det: 'T1190 · AN0222', kisa: 'SF (상)', scope: '취약 · 성공', app: { t: '탐지', cls: 'b-ok' }, net: { t: '탐지', cls: 'b-ok' }, backend: '대상 아님', key: 'SSRF', remediation: '허용 URL · IP 화이트리스트 검증', followup: '대조 요청 오판(측정 도구) 별도 수정' },
  { status: 'PARTIAL', name: '무차별 대입', det: 'T1110 · DET0463', kisa: 'AU (상)', scope: '취약 · 성공', app: { t: '탐지', cls: 'b-ok' }, net: { t: NO_RECORD, cls: 'b-nu' }, backend: '탐지', key: 'BRUTE_FORCE', remediation: '로그인 시도 횟수 제한 · 추가 인증', followup: '1000031 · 1000032 실패 조건 추가' },
];

const FINDING_BADGE: Record<string, { t: string; cls: string }> = {
  'V-01': { t: '앱 로그 탐지 · 네트워크 로그만', cls: 'b-at' },
  'V-02': { t: '탐지', cls: 'b-ok' },
  'V-03': { t: '탐지', cls: 'b-ok' },
  'V-04': { t: '탐지 · 정상 로그인 오탐 있음', cls: 'b-at' },
};

export default function Report() {
  const { runIds, runAfter, displayName, runs } = useDashboard();
  const snap = useAsync(() => api.getSnapshot('', runIds.after), [runIds.after]);
  const snapB = useAsync(() => api.getSnapshot('', runIds.before), [runIds.before]);
  const benignLogin = useAsync(() => api.getSnapshot('', runIds.benignLogin), [runIds.benignLogin]);
  const rates = useAsync(() => api.getRates(runIds.after), [runIds.after]);
  const findings = useAsync(() => api.getFindings(), []);
  const gaps = useAsync(() => api.getGaps(), []);
  const attacker = useAsync(() => api.getAttacker(runIds.after), [runIds.after]);

  const def = snap.data?.[0]?.definition_version ?? '';
  const m02 = byMetricScope<SnapshotRow>(snap.data, 'M02', 'ALL');
  const m02b = byMetricScope<SnapshotRow>(snapB.data, 'M02', 'ALL');
  // v_metric_attacker에는 ALL 행이 없으므로,
  // 존재하는 SCENARIO 행을 합산해 전체 판정 값을 동적으로 구성합니다.
  const atk = byScope<AttackerRow>(attacker.data, 'ALL') ?? (() => {
    const rows = (attacker.data ?? []).filter((r) => r.scope_kind === 'SCENARIO');
    if (rows.length === 0) return undefined;

    const x = rows.reduce((sum, r) => sum + (r.x ?? 0), 0);
    const n = rows.reduce((sum, r) => sum + r.n, 0);

    return {
      ...rows[0],
      scope_kind: 'ALL',
      scope_key: 'ALL',
      x,
      n,
      p: n > 0 ? x / n : null,
      lo: null,
      hi: null,
      overestimate: rows.reduce((sum, r) => sum + r.overestimate, 0),
      uncertain: rows.reduce((sum, r) => sum + r.uncertain, 0),
      criteria_met: rows.every((r) => r.criteria_met),
    };
  })();
  const loginNids = (benignLogin.data ?? []).find(
    (r) => r.metric_id === 'M14a_NIDS' && r.scope_key === 'BRUTE_FORCE'
  );
  const findingList = findings.data ?? [];
  const benignLoginRun = runs.find((r) => r.run_id === runIds.benignLogin);
  const gapList = (gaps.data ?? []).map((g) =>
    g.id === 'Gap-login' && loginNids
      ? {
          ...g,
          reval_run: benignLoginRun?.label ?? NO_RECORD,
          reval_note: `${loginNids.x ?? 0} / ${loginNids.n}`,
          status: (loginNids.x ?? 0) === 0 ? '해결' : '잔존',
        }
      : g
  );
  const attackScenarioRows = (rates.data ?? []).filter(
    (r) => r.metric_id === 'M01' && r.scope_kind === 'SCENARIO'
  );
  const successfulScenarioN = attackScenarioRows.filter(
    (r) => r.n > 0 && r.x === r.n
  ).length;
  const scenarioN = attackScenarioRows.length;

  // 시나리오별 탐지율 = M02 SCENARIO.
  const rateFor = (key: string): RateRow | undefined =>
    (rates.data ?? []).find((r) => r.metric_id === 'M02' && r.scope_kind === 'SCENARIO' && r.scope_key === key);

  async function downloadPdf() {
    const report = document.querySelector<HTMLElement>('#pdf-report-root .pdf-report');

    if (!report) {
      return;
    }

    try {
      await html2pdf()
        .set({
          margin: [8, 8, 8, 8],
          filename: `validation-report-${runAfter?.label ?? 'run'}.pdf`,
          image: {
            type: 'jpeg',
            quality: 0.98,
          },
          html2canvas: {
            scale: 2,
            useCORS: true,
            backgroundColor: '#ffffff',
          },
          jsPDF: {
            unit: 'mm',
            format: 'a4',
            orientation: 'landscape',
          },
          pagebreak: {
            mode: ['css', 'legacy'],
            before: ['.pdf-page-start'],
            avoid: ['.pdf-finding-row', '.pdf-finding', '.pdf-summary-grid', '.pdf-table tr'],
          },
        })
        .from(report)
        .save();
    } finally {
      // PDF 전용 DOM은 화면에서 숨겨진 상태를 유지합니다.
    }
  }

  return (
    <Layout screenId="report" title="검증 결과" topNote={`${displayName(runAfter?.label ?? '')} · 확정 결과`}>
      <div className="heading">
        <div className="eyebrow">보안 검증 결과</div>
        <h1>검증 결과</h1>
        <p>측정한 공격 시나리오별로 대상 시스템의 취약 여부, 관제의 탐지 여부, 조치 권고를 정리합니다.</p>
      </div>
      <div className="toprow">
        <span className="tnote">{displayName(runAfter?.label ?? '')} · {runAfter?.label ?? ''} · 확정 결과</span>
        <span className="tnote">측정 범위 · 웹 취약점 4종 · 공격 {m02?.n ?? NO_RECORD}건</span>
        <div className="export-actions spacer">
          <button type="button" className="link" onClick={downloadPdf}>PDF 보고서 다운로드 →</button>
        </div>
      </div>

      <section className="sum">
        <div className="sc2"><span>대상 시스템 취약점</span><b className="t-danger">{scenarioN ? `${successfulScenarioN} / ${scenarioN} 시나리오 성공` : NO_RECORD}</b><small>공격 {m02?.n ?? NO_RECORD}건 모두 성공 · 정답지 기준</small></div>
        <div className="sc2"><span>탐지</span><b className="t-det">{m02 ? `${m02.x} / ${m02.n} 탐지` : NO_RECORD}</b><small>개선 전 측정 (10/21) {m02b ? `${m02b.x} / ${m02b.n}` : NO_RECORD}</small></div>
        <div className="sc2"><span>남은 탐지 공백</span><b className="t-warn">{gapList.filter((g) => g.status === '잔존').length}건 잔존</b><small>네트워크 SQL 인젝션 · 정상 로그인 오탐</small></div>
        <div className="sc2"><span>측정 신뢰</span><b>통과</b><small>판정 일치 {atk ? `${atk.x} / ${atk.n}` : NO_RECORD} · 기대 요청 {((runAfter?.expected_attempts ?? 0) + (runAfter?.expected_controls ?? 0))}건 · 기록 검증 {runAfter?.integrity_status === 'VALID' ? '일치' : (runAfter?.integrity_status ?? NO_RECORD)}</small></div>
      </section>

      <section className="panel">
        <div className="ph"><div><div className="ctx">발견된 취약점</div><h2>발견 요약</h2></div><span className="pm">KISA 2026 상세가이드 항목 중요도 · 발견별 위험도(가능성 × 영향) 아님</span></div>
        <div className="tw"><table className="rt">
          <thead><tr><th>ID</th><th>취약점</th><th>위치</th><th>KISA 중요도</th><th>대상 시스템</th><th>탐지</th></tr></thead>
          <tbody>
            {findingList.map((f) => {
              const db = FINDING_BADGE[f.id] ?? { t: f.detection, cls: 'b-ok' };
              return (
                <tr key={f.id}>
                  <td><b>{f.id}</b></td><td><b>{f.title}</b></td><td>{f.location}</td>
                  <td><BadgeText cls="b-nu">{f.kisa}</BadgeText></td>
                  <td><BadgeText cls="b-dg">{f.target_status}</BadgeText></td>
                  <td><BadgeText cls={db.cls}>{db.t}</BadgeText></td>
                </tr>
              );
            })}
          </tbody>
        </table></div>
      </section>

      <section>
        <div className="ph"><div><div className="ctx">취약점별</div><h2>발견 상세</h2></div><span className="pm">공격 방법 세부와 원본 요청은 표시하지 않습니다</span></div>
        <div className="fd">
          {findingList.map((f) => (
            <div className="fcard" key={f.id}>
              <div className="id">{f.id}</div><h3>{f.title}</h3>
              <dl>
                <div><dt>위치</dt><dd>{f.location}</dd></div>
                <div><dt>설명</dt><dd>{f.description}</dd></div>
                <div><dt>확인된 영향</dt><dd>{f.impact}</dd></div>
                <div><dt>분류</dt><dd>{f.tags.map((t) => <span className="tag" key={t}>{t}</span>)}</dd></div>
                <div><dt>탐지</dt><dd>{f.detection}</dd></div>
                <div><dt>취약점 조치</dt><dd>{f.remediation}</dd></div>
                <div><dt>탐지 보완</dt><dd>{f.detection_followup}</dd></div>
              </dl>
            </div>
          ))}
        </div>
      </section>

      <section className="panel">
        <div className="ph"><div><div className="ctx">시나리오별</div><h2>탐지 결과</h2></div><span className="pm">OK 모든 관제에서 탐지 · PARTIAL 일부 관제 공백 또는 오탐</span></div>
        <div className="tw"><table className="rt">
          <thead><tr><th>상태</th><th>시나리오</th><th>KISA 항목</th><th>대상 시스템</th><th>앱 로그</th><th>네트워크</th><th>백엔드 상관</th><th>탐지율</th><th>취약점 조치 권고</th><th>탐지 보완 권고</th></tr></thead>
          <tbody>
            {SCEN_ROWS.map((s) => {
              const r = rateFor(s.key);
              return (
                <tr key={s.key}>
                  <td><span className={`st2 ${s.status === 'OK' ? 'ok2' : 'pa2'}`}>{s.status}</span></td>
                  <td><b>{s.name}</b><small>{s.det}</small></td>
                  <td>{s.kisa}</td>
                  <td><BadgeText cls="b-dg">{s.scope}</BadgeText></td>
                  <td><BadgeText cls={s.app.cls}>{s.app.t}</BadgeText></td>
                  <td><BadgeText cls={s.net.cls}>{s.net.t}</BadgeText></td>
                  <td>{s.backend === '대상 아님' ? <span className="t-unk">대상 아님</span> : <BadgeText cls="b-ok">{s.backend}</BadgeText>}</td>
                  <td className="cellrate">{r ? <RatioBlock label={`${s.name} 탐지율`} x={r.x} n={r.n} lo={r.lo} hi={r.hi} status={r.status} /> : NO_RECORD}</td>
                  <td><small>{s.remediation}</small></td>
                  <td><small>{s.key === 'BRUTE_FORCE'
                    ? `정상 로그인 오탐 ${loginNids?.p != null ? `${(loginNids.p * 100).toFixed(1)}%` : NO_RECORD} (${loginNids ? `${loginNids.n}건 중 ${loginNids.x ?? 0}건` : NO_RECORD}) · ${s.followup}`
                    : s.followup}</small></td>
                </tr>
              );
            })}
          </tbody>
        </table></div>
        <p className="foot">취약점 조치 권고는 KISA 2026 상세가이드 조치 기준입니다. 이 플랫폼에서 대상 시스템의 취약점은 시험 대상으로 그대로 두고, 탐지를 개선합니다.</p>
      </section>

      <div className="two">
        <section className="panel">
          <div className="ph"><h2>개선 이력</h2><Link className="link2" to="/revalidate">공백 · 재검증 →</Link></div>
          <div className="gaps">
            {gapList.filter((g) => g.status !== '발견').map((g) => (
              <div className="gap" key={g.id}>
                <div><b>{g.title}</b><span className="s">{g.fix !== '—' ? `${g.fix}${g.fix_note ? ` (${g.fix_note})` : ''} · ` : ''}{g.reval_note || g.found_note}</span></div>
                <BadgeText cls={g.status === '해결' ? 'b-ok' : g.status === '잔존' ? 'b-dg' : 'b-at'}>{g.status === '해결' ? '해소' : g.status}</BadgeText>
              </div>
            ))}
          </div>
        </section>
        <section className="panel">
          <div className="ph"><h2>측정 근거</h2><Link className="link2" to="/system">시스템 상태 →</Link></div>
          <dl className="legend">
            <div><dt>공격자 판정 = 정답지</dt><dd>{scenarioN ? `${successfulScenarioN} / ${scenarioN} 유형` : NO_RECORD} · 과대평가 {atk?.overestimate ?? NO_RECORD}</dd></div>
            <div><dt>요청 기록</dt><dd>기대 {((runAfter?.expected_attempts ?? 0) + (runAfter?.expected_controls ?? 0))}건 (공격 {runAfter?.expected_attempts ?? NO_RECORD} · 대조 {runAfter?.expected_controls ?? NO_RECORD}) · 검증 {runAfter?.integrity_status === 'VALID' ? '일치' : (runAfter?.integrity_status ?? NO_RECORD)}</dd></div>
            <div><dt>판정 불가</dt><dd>{atk?.uncertain ?? NO_RECORD}건</dd></div>
            <div><dt>관찰 시간</dt><dd>30초 (실측 지연 p95 × 2)</dd></div>
          </dl>
        </section>
      </div>

      <p className="foot">측정 {runAfter?.label ?? ''} · {runAfter?.git_commit ?? ''} · 정의 {def || NO_RECORD} · 판정 엔진 s4-v1 · 확정 결과는 저장 후 수정할 수 없습니다</p>

      <div id="pdf-report-root" className="pdf-report-root" aria-hidden="true">
        <ReportPdf
          run={runAfter}
          displayName={displayName(runAfter?.label ?? '')}
          findings={findingList}
          gaps={gapList}
          rates={rates.data ?? []}
          snapshot={snap.data ?? []}
          snapshotBefore={snapB.data ?? []}
          attacker={atk}
          benignLogin={benignLogin.data ?? []}
        />
      </div>
    </Layout>
  );
}
