import { Link } from 'react-router-dom';
import { Layout } from '../components/Layout';
import { Badge } from '../components/Badge';
import { useDashboard } from '../components/DashboardContext';
import { useAsync } from '../lib/useAsync';
import { api } from '../api';
import { byMetricScope } from '../lib/select';
import { msToSec, NO_RECORD } from '../lib/ratio';
import { kst } from '../lib/format';
import { scenarioMeta, gtBadge, detectionBadge, verdictBadge } from '../lib/labels';
import type { SnapshotRow } from '../api/types';
import '../styles/overview.css';

const num = (v: number | null | undefined) => (v == null ? NO_RECORD : String(v));

export default function Overview() {
  const { runIds, displayName, runAfter } = useDashboard();
  const snapA = useAsync(() => api.getSnapshot('', runIds.after), [runIds.after]);
  const snapB = useAsync(() => api.getSnapshot('', runIds.before), [runIds.before]);
  const attempts = useAsync(() => api.getAttempts(runIds.after), [runIds.after]);
  const gaps = useAsync(() => api.getGaps(), []);
  const benignLogin = useAsync(() => api.getSnapshot('', runIds.benignLogin), [runIds.benignLogin]);

  const sA = snapA.data;
  const sB = snapB.data;
  const m01 = byMetricScope<SnapshotRow>(sA, 'M01', 'ALL');
  const m02 = byMetricScope<SnapshotRow>(sA, 'M02', 'ALL');
  const m08 = byMetricScope<SnapshotRow>(sA, 'M04', 'ALL');
  const m02b = byMetricScope<SnapshotRow>(sB, 'M02', 'ALL');
  const m08b = byMetricScope<SnapshotRow>(sB, 'M04', 'ALL');

  const attackN = m01?.n ?? 0;
  const success = m01?.x ?? 0;
  const controlN = runAfter?.expected_controls ?? 0;
  const detected = m02?.x ?? 0;
  const missed = m02 ? m02.n - (m02.x ?? 0) : 0;
  const beforeMissed = m02b ? m02b.n - (m02b.x ?? 0) : null;
  const chip = (status: string) => {
    switch (status) {
      case '해결': case '해소': return 'c-al';
      case '확인 필요': return 'c-no';
      case '개선 예정': return 'c-lo';
      default: return 'c-na';
    }
  };
  const chipLabel = (status: string) => (status === '해결' ? '해소' : status);
  const loginBackend = (benignLogin.data ?? []).find(
    (r) => r.metric_id === 'M14a_BACKEND_CORR' && r.scope_key === 'BRUTE_FORCE'
  );
  const sqliNids = (sA ?? []).find(
    (r) => r.metric_id === 'M13_NIDS' && r.scope_kind === 'SCENARIO' && r.scope_key === 'SQLI'
  );

  const controlAttempts = (attempts.data ?? []).filter(
    (a) => a.attempt_role === 'CONTROL'
  );
  const validControls = controlAttempts.filter(
    (a) => a.gt_outcome === 'FAILED' && a.verdict === 'FAILED_UNSEEN'
  );
  const controlStatusOk =
    controlAttempts.length > 0 && validControls.length === controlAttempts.length;

  // gaps.json은 발견 이력/설명을 보존하고,
  // 현재 상태는 최신 실측 snapshot으로 덮어쓴다.
  const gapList = (gaps.data ?? []).map((g) => {
    if (g.id === 'Gap #7n' && sqliNids) {
      return {
        ...g,
        status: sqliNids.status === 'OK' && sqliNids.n > 0 && (sqliNids.x ?? 0) === sqliNids.n
          ? '해결'
          : '확인 필요',
        reval_run: runAfter?.label ?? g.reval_run,
        reval_note: `${sqliNids.x ?? 0} / ${sqliNids.n}`,
      };
    }

    if (g.id === 'Gap-login' && loginBackend) {
      return {
        ...g,
        status: (loginBackend.x ?? 0) === 0 ? '해결' : '확인 필요',
        reval_note: `${loginBackend.x ?? 0} / ${loginBackend.n}`,
      };
    }

    if (g.id === 'Gap-ssrf-ctrl' && controlAttempts.length > 0) {
      return {
        ...g,
        status: controlStatusOk ? '해결' : '확인 필요',
        reval_run: runAfter?.label ?? g.reval_run,
        reval_note: `${validControls.length} / ${controlAttempts.length} 정상 판정`,
      };
    }

    return g;
  });

  const detectionGaps = gapList.filter((g) => g.control !== '측정 도구');
  const openDetectionGaps = detectionGaps.filter(
    (g) => g.status !== '해결' && g.status !== '해소'
  );
  const resolved = detectionGaps.filter(
    (g) => g.status === '해결' || g.status === '해소'
  ).length;

  // 최근 공격은 동일 시나리오 5건이 연속 노출되지 않도록
  // 현재 확정 측정에서 SQLi / Path Traversal / Brute Force / SSRF의 최신 1건씩 표시한다.
  const attackAttempts = (attempts.data ?? []).filter((a) => a.attempt_role === 'ATTACK');
  const failedAttempts = attackAttempts.filter((a) => a.gt_outcome !== 'SUCCEEDED');
  const uncertainAttempts = attackAttempts.filter(
    (a) => a.verdict.includes('UNCERTAIN') || a.attacker_verdict === 'UNCERTAIN'
  );
  const lateDetectedAttempts = attackAttempts.filter(
    (a) => a.late_detection || a.detection_status === 'LATE'
  );

  const recentScenarioNames = new Set(['SQL 인젝션', '경로 조작', '무차별 대입', 'SSRF']);
  const recentAttempts = attackAttempts.filter((a, index, all) => {
    const name = scenarioMeta(a).name;
    return recentScenarioNames.has(name)
      && all.findIndex((x) => scenarioMeta(x).name === name) === index;
  }).slice(0, 4);

  return (
    <Layout screenId="overview" title="개요" topNote={`${displayName(runAfter?.label ?? '')} · 확정 결과`}>
      <div className="intro">
        <div>
          <h1>공격은 내가 탐지는 너가</h1>
          <p>공격 시도 한 건의 결과를 정답지와 관제 두 기준으로 대조하고 증거까지 확인합니다.</p>
        </div>
        <span>집계 기준 · 선택한 확정 측정의 공격 시도</span>
      </div>

      <section className="overview-summary" aria-label="핵심 검증 지표">
        <div className="summary-card primary">
          <span className="summary-label">공격 검증</span>
          <strong>{success} / {attackN}</strong>
          <small>정답지 기준 성공 · 대조 요청 {controlN}건 별도</small>
        </div>
        <div className="summary-card">
          <span className="summary-label">탐지</span>
          <strong className="t-det">{detected} / {m02?.n ?? attackN}</strong>
          <small>개선 전 {m02b ? `${m02b.x} / ${m02b.n}` : NO_RECORD}</small>
        </div>
        <div className="summary-card">
          <span className="summary-label">현재 확인 필요</span>
          <strong className={openDetectionGaps.length === 0 ? 't-det' : 't-warn'}>{openDetectionGaps.length}건</strong>
          <small>최신 실측 탐지 공백 기준</small>
        </div>
        <div className="summary-card">
          <span className="summary-label">탐지 시간 (MTTD)</span>
          <strong>{msToSec(m08?.p50_ms)}</strong>
          <small>중앙값 · 개선 전 {msToSec(m08b?.p50_ms)}</small>
        </div>
      </section>

      <section className="validation-path" aria-label="검증 흐름">
        <Link to="/attacks"><span>01</span><b>공격 실행</b><small>{num(attackN)}건</small></Link>
        <Link to="/attacks"><span>02</span><b>성공 판정</b><small>{success}/{attackN}</small></Link>
        <Link to="/detection"><span>03</span><b>탐지 확인</b><small>{detected}/{m02?.n ?? attackN}</small></Link>
        <Link to="/revalidate"><span>04</span><b>공백 분석</b><small>{openDetectionGaps.length}건</small></Link>
        <Link to="/revalidate"><span>05</span><b>재검증</b><small>{resolved}건 해소</small></Link>
      </section>

      <div className="board">
        <div className="bh"><div><div className="ctx">공격 시도 {attackN}건</div><h2>공격 결과와 탐지 결과</h2></div><Link className="link" to="/attacks">시도별로 보기 →</Link></div>
        <div className="vc">
          <div className="vcol"><h3>공격 결과<small>정답지 기준 · Target Web</small></h3><dl>
            <div><dt>성공</dt><dd className="t-attack">{success}</dd></div>
            <div><dt>실패</dt><dd>{failedAttempts.length}</dd></div>
            <div><dt>판정 불가</dt><dd>{uncertainAttempts.length}</dd></div>
          </dl></div>
          <div className="vcol"><h3>탐지 결과<small>관제 기준 · 정답지 미참조</small></h3><dl>
            <div><dt>탐지됨</dt><dd className="t-det">{detected}</dd></div>
            <div><dt>놓침</dt><dd>{missed}</dd></div>
            <div><dt>늦은 탐지</dt><dd>{lateDetectedAttempts.length}</dd></div>
          </dl></div>
        </div>
        <p className="bnote">두 결과는 서로 보지 않고 따로 계산합니다. 기대 요청 {((runAfter?.expected_attempts ?? 0) + (runAfter?.expected_controls ?? 0))}건 · 기록 검증 {runAfter?.integrity_status === 'VALID' ? '일치' : (runAfter?.integrity_status ?? NO_RECORD)}(공격 {attackN} · 대조 {controlN})으로 이 측정의 수치를 확정했습니다.</p>
      </div>

      <div className="gapbar">
        <b>현재 탐지 공백 {openDetectionGaps.length}건</b>
        {detectionGaps.map((g) => <span key={g.id} className={`chip ${chip(g.status)}`}>{chipLabel(g.status)}</span>)}
        <span className="gapbar-note">최신 실측 기준 · 놓친 공격 {beforeMissed ?? NO_RECORD} → {missed}</span>
        <Link className="link spacer" to="/revalidate">공백 · 재검증 →</Link>
      </div>

      <div className="tablewrap">
        <div className="sh"><div><h2>최근 공격 시도</h2><p>각 시도의 공격 결과와 탐지 결과, 판정을 함께 확인합니다.</p></div><Link className="link" to="/attacks">모든 결과 보기 →</Link></div>
        <div className="tw">
          <table>
            <thead><tr><th>관찰 시각</th><th>Operation / 시도</th><th>공격 내용</th><th>Technique</th><th>공격 결과</th><th>탐지 결과</th><th>판정</th><th></th></tr></thead>
            <tbody>
              {recentAttempts.map((a) => {
                const m = scenarioMeta(a);
                return (
                  <tr key={a.attempt_id}>
                    <td>{kst(a.attack_time)}</td>
                    <td><span className="pc">{a.op_id}</span><span className="sc">rid {a.rid}</span></td>
                    <td><span className="pc">{m.name}</span><span className="sc">{m.desc}</span></td>
                    <td><span className="pc tech">{a.technique_id}</span><span className="sc">{a.ability_id}</span></td>
                    <td><Badge model={gtBadge(a)} /></td>
                    <td><Badge model={detectionBadge(a)} /></td>
                    <td><Badge model={verdictBadge(a)} /></td>
                    <td><Link className="link" to={`/attempts/${a.attempt_id}`}>상세 보기 →</Link></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </Layout>
  );
}
