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
import { REPORT_SCENARIOS, FINDING_SCENARIO } from '../lib/reportScenarioMeta';
import type { SnapshotRow, RateRow, AttackerRow } from '../api/types';
import '../styles/report.css';

const SCEN_ROWS = REPORT_SCENARIOS.map((s) => ({
  ...s,
  det: `${s.technique} · ${s.detection}`,
}));

export default function Report() {
  const { runIds, runAfter, displayName, runs } = useDashboard();
  const snap = useAsync(() => api.getSnapshot('', runIds.after), [runIds.after]);
  const snapB = useAsync(() => api.getSnapshot('', runIds.before), [runIds.before]);
  const benignLogin = useAsync(() => api.getSnapshot('', runIds.benignLogin), [runIds.benignLogin]);
  const rates = useAsync(() => api.getRates(runIds.after), [runIds.after]);
  const findings = useAsync(() => api.getFindings(), []);
  const gaps = useAsync(() => api.getGaps(), []);
  const attacker = useAsync(() => api.getAttacker(runIds.after), [runIds.after]);
  const attempts = useAsync(() => api.getAttempts(runIds.after), [runIds.after]);

  const def = snap.data?.[0]?.definition_version ?? '';
  const m02 = byMetricScope<SnapshotRow>(snap.data, 'M02', 'ALL');
  const m01 = byMetricScope<RateRow>(rates.data, 'M01', 'ALL');
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
  const loginBackend = (benignLogin.data ?? []).find(
    (r) => r.metric_id === 'M14a_BACKEND_CORR' && r.scope_key === 'BRUTE_FORCE'
  );
  const sqliNids = (snap.data ?? []).find(
    (r) => r.metric_id === 'M13_NIDS'
      && r.scope_kind === 'SCENARIO'
      && r.scope_key === 'SQLI'
  );
  const findingList = findings.data ?? [];
  const benignLoginRun = runs.find((r) => r.run_id === runIds.benignLogin);

  const controlAttempts = (attempts.data ?? []).filter(
    (a) => a.attempt_role === 'CONTROL'
  );
  const validControls = controlAttempts.filter(
    (a) => a.gt_outcome === 'FAILED' && a.verdict === 'FAILED_UNSEEN'
  );
  const controlStatusOk =
    controlAttempts.length > 0 && validControls.length === controlAttempts.length;

  const engineVersions = Array.from(new Set((attempts.data ?? []).map((a) => a.engine_version).filter(Boolean))).join(', ');

  const gapList = (gaps.data ?? []).map((g) => {
    if (g.id === 'Gap #7n' && sqliNids) {
      return {
        ...g,
        reval_run: runAfter?.label ?? g.reval_run,
        reval_note: `${sqliNids.x ?? 0} / ${sqliNids.n}`,
        status: sqliNids.status === 'OK'
          && sqliNids.n > 0
          && (sqliNids.x ?? 0) === sqliNids.n
          ? '해결'
          : '확인 필요',
      };
    }

    if (g.id === 'Gap-login' && loginBackend) {
      return {
        ...g,
        reval_run: benignLoginRun?.label ?? NO_RECORD,
        reval_note: `최종 FP ${loginBackend.x ?? 0} / ${loginBackend.n}`
          + (loginNids ? ` · 원시 NIDS ${loginNids.x ?? 0} / ${loginNids.n}` : ''),
        status: (loginBackend.x ?? 0) === 0 ? '해결' : '확인 필요',
      };
    }

    if (g.id === 'Gap-ssrf-ctrl' && controlAttempts.length > 0) {
      return {
        ...g,
        reval_run: runAfter?.label ?? g.reval_run,
        reval_note: `${validControls.length} / ${controlAttempts.length} 정상 판정`,
        status: controlStatusOk ? '해결' : '확인 필요',
      };
    }

    return g;
  });

  const detectionGaps = gapList.filter((g) => g.control !== '측정 도구');
  const openDetectionGaps = detectionGaps.filter(
    (g) => g.status !== '해결' && g.status !== '해소'
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

  const sensorFor = (metricId: string, key: string): SnapshotRow | undefined =>
    (snap.data ?? []).find(
      (r) => r.metric_id === metricId
        && r.scope_kind === 'SCENARIO'
        && r.scope_key === key
    );

  const sensorBadge = (row: SnapshotRow | undefined) => {
    if (!row || row.n <= 0 || row.status === 'NOT_APPLICABLE' || row.status === 'NO_RULE') {
      return { t: '대상 아님', cls: 'b-nu' };
    }
    if (row.status === 'OK' && (row.x ?? 0) === row.n) {
      return { t: `탐지 ${row.x ?? 0}/${row.n}`, cls: 'b-ok' };
    }
    return { t: `${row.x ?? 0}/${row.n}`, cls: 'b-at' };
  };

  const scenarioStatus = (key: string) => {
    const rows = [
      sensorFor('M13_APP_RULE', key),
      sensorFor('M13_NIDS', key),
      sensorFor('M13_BACKEND_CORR', key),
    ].filter((r): r is SnapshotRow => !!r && r.n > 0 && r.status !== 'NOT_APPLICABLE' && r.status !== 'NO_RULE');

    return rows.length > 0
      && rows.every((r) => r.status === 'OK' && (r.x ?? 0) === r.n)
      ? 'OK'
      : 'PARTIAL';
  };

  const findingBadge = (id: string) => {
    const key = FINDING_SCENARIO[id];
    if (!key) return { t: NO_RECORD, cls: 'b-nu' };

    const status = scenarioStatus(key);
    return status === 'OK'
      ? { t: '탐지 확인', cls: 'b-ok' }
      : { t: '일부 관제 확인 필요', cls: 'b-at' };
  };

  const findingDetectionText = (id: string) => {
    const key = FINDING_SCENARIO[id];
    if (!key) return NO_RECORD;

    const app = sensorBadge(sensorFor('M13_APP_RULE', key)).t;
    const nids = sensorBadge(sensorFor('M13_NIDS', key)).t;
    const backend = sensorBadge(sensorFor('M13_BACKEND_CORR', key)).t;

    const parts = [`앱 로그 ${app}`, `네트워크 ${nids}`];

    if (backend !== '대상 아님') {
      parts.push(`백엔드 상관 ${backend}`);
    }

    if (key === 'BRUTE_FORCE') {
      parts.push(
        `최종 FP ${loginBackend ? `${loginBackend.x ?? 0}/${loginBackend.n}` : NO_RECORD}`
      );
      if (loginNids) {
        parts.push(`원시 NIDS ${loginNids.x ?? 0}/${loginNids.n}`);
      }
    }

    return parts.join(' · ');
  };

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
        <span className="tnote">측정 범위 · 웹 취약점 {scenarioN || NO_RECORD}종 · 공격 {m01?.n ?? NO_RECORD}건</span>
        <div className="export-actions spacer">
          <button type="button" className="link" onClick={downloadPdf}>PDF 보고서 다운로드 →</button>
        </div>
      </div>

      <section className="sum">
        <div className="sc2"><span>대상 시스템 취약점</span><b className="t-danger">{scenarioN ? `${successfulScenarioN} / ${scenarioN} 시나리오 성공` : NO_RECORD}</b><small>공격 {m01?.n ?? NO_RECORD}건 중 {m01?.x ?? NO_RECORD}건 성공 · 정답지 기준</small></div>
        <div className="sc2"><span>탐지</span><b className="t-det">{m02 ? `${m02.x} / ${m02.n} 탐지` : NO_RECORD}</b><small>개선 전 측정 {m02b ? `${m02b.x} / ${m02b.n}` : NO_RECORD}</small></div>
        <div className="sc2"><span>현재 탐지 공백</span><b className={openDetectionGaps.length === 0 ? 't-det' : 't-warn'}>{openDetectionGaps.length}건</b><small>최신 공격·정상 트래픽 실측 기준</small></div>
        <div className="sc2"><span>측정 신뢰</span><b>{runAfter?.integrity_status === 'VALID' ? '통과' : (runAfter?.integrity_status ?? NO_RECORD)}</b><small>판정 일치 {atk ? `${atk.x} / ${atk.n}` : NO_RECORD} · 기대 요청 {((runAfter?.expected_attempts ?? 0) + (runAfter?.expected_controls ?? 0))}건 · 기록 검증 {runAfter?.integrity_status === 'VALID' ? '일치' : (runAfter?.integrity_status ?? NO_RECORD)}</small></div>
      </section>

      <section className="panel">
        <div className="ph"><div><div className="ctx">발견된 취약점</div><h2>발견 요약</h2></div><span className="pm">KISA 2026 상세가이드 항목 중요도 · 발견별 위험도(가능성 × 영향) 아님</span></div>
        <div className="tw"><table className="rt">
          <thead><tr><th>ID</th><th>취약점</th><th>위치</th><th>KISA 중요도</th><th>대상 시스템</th><th>탐지</th></tr></thead>
          <tbody>
            {findingList.map((f) => {
              const db = findingBadge(f.id);
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
                <div><dt>탐지</dt><dd>{findingDetectionText(f.id)}</dd></div>
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
              const attack = attackScenarioRows.find((x) => x.scope_key === s.key);
              const app = sensorBadge(sensorFor('M13_APP_RULE', s.key));
              const net = sensorBadge(sensorFor('M13_NIDS', s.key));
              const backend = sensorBadge(sensorFor('M13_BACKEND_CORR', s.key));
              const status = scenarioStatus(s.key);

              return (
                <tr key={s.key}>
                  <td><span className={`st2 ${status === 'OK' ? 'ok2' : 'pa2'}`}>{status}</span></td>
                  <td><b>{s.name}</b><small>{s.det}</small></td>
                  <td>{s.kisa}</td>
                  <td><BadgeText cls="b-dg">{attack ? `취약 · 성공 ${attack.x ?? 0}/${attack.n}` : NO_RECORD}</BadgeText></td>
                  <td><BadgeText cls={app.cls}>{app.t}</BadgeText></td>
                  <td><BadgeText cls={net.cls}>{net.t}</BadgeText></td>
                  <td>{backend.t === '대상 아님' ? <span className="t-unk">대상 아님</span> : <BadgeText cls={backend.cls}>{backend.t}</BadgeText>}</td>
                  <td className="cellrate">{r ? <RatioBlock label={`${s.name} 탐지율`} x={r.x} n={r.n} lo={r.lo} hi={r.hi} status={r.status === 'OK' ? 'VALID' : r.status} /> : NO_RECORD}</td>
                  <td><small>{s.remediation}</small></td>
                  <td><small>{s.key === 'BRUTE_FORCE'
                    ? `최종 FP ${loginBackend ? `${loginBackend.x ?? 0}/${loginBackend.n}` : NO_RECORD}`
                      + (loginNids ? ` · 원시 NIDS ${loginNids.x ?? 0}/${loginNids.n}` : '')
                      + ` · ${s.followup}`
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
                <BadgeText cls={g.status === '해결' ? 'b-ok' : g.status === '확인 필요' ? 'b-dg' : 'b-at'}>{g.status === '해결' ? '해소' : g.status}</BadgeText>
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

      <p className="foot">측정 {runAfter?.label ?? ''} · {runAfter?.git_commit ?? ''} · 정의 {def || NO_RECORD} · 판정 엔진 {engineVersions || NO_RECORD} · 확정 결과는 저장 후 수정할 수 없습니다</p>

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
