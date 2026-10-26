import { Link } from 'react-router-dom';
import { Layout } from '../components/Layout';
import { Donut, Bar } from '../components/primitives';
import { Badge } from '../components/Badge';
import { useDashboard } from '../components/DashboardContext';
import { useAsync } from '../lib/useAsync';
import { api } from '../api';
import { byMetricScope } from '../lib/select';
import { pct, pctRange, wilson, msToSec, NO_RECORD } from '../lib/ratio';
import { kst } from '../lib/format';
import { scenarioMeta, gtBadge, detectionBadge, verdictBadge } from '../lib/labels';
import type { SnapshotRow } from '../api/types';
import '../styles/overview.css';

const num = (v: number | null | undefined) => (v == null ? NO_RECORD : String(v));

export default function Overview() {
  const { runIds, displayName, runAfter } = useDashboard();
  const snapA = useAsync(() => api.getSnapshot('', runIds.after), [runIds.after]);
  const snapB = useAsync(() => api.getSnapshot('', runIds.before), [runIds.before]);
  const attempts = useAsync(() => api.getAttempts(runIds.after, { limit: 160 }), [runIds.after]);
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
  const total = success + controlN; // 공격 성공 + 대조
  const detP = m02?.p ?? null;
  const ci = m02 && m02.lo != null && m02.hi != null ? { lo: m02.lo, hi: m02.hi } : wilson(detected, m02?.n ?? 0);

  const beforeP = m02b?.p ?? null;
  const beforeCi = m02b && m02b.lo != null && m02b.hi != null ? { lo: m02b.lo, hi: m02b.hi } : null;

  const chip = (status: string) => {
    switch (status) {
      case '해결': case '해소': return 'c-al';
      case '잔존': return 'c-no';
      case '개선 예정': return 'c-lo';
      default: return 'c-na';
    }
  };
  const chipLabel = (status: string) => (status === '해결' ? '해소' : status);
  const loginNids = (benignLogin.data ?? []).find(
    (r) => r.metric_id === 'M14a_NIDS' && r.scope_key === 'BRUTE_FORCE'
  );
  const gapList = (gaps.data ?? []).map((g) =>
    g.id === 'Gap-login' && loginNids
      ? { ...g, status: (loginNids.x ?? 0) === 0 ? '해결' : '잔존' }
      : g
  );
  const resolved = gapList.filter((g) => g.status === '해결' || g.status === '해소').length;

  // 최근 공격은 동일 시나리오 5건이 연속 노출되지 않도록
  // 현재 확정 측정에서 SQLi / Path Traversal / Brute Force / SSRF의 최신 1건씩 표시한다.
  const recentScenarioNames = new Set(['SQL 인젝션', '경로 조작', '무차별 대입', 'SSRF']);
  const recentAttempts = (attempts.data ?? []).filter((a, index, all) => {
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

      <section aria-label="검증 흐름">
        <div className="ph ph-tight">
          <h2 className="flow-title">검증 흐름</h2>
          <span className="pm">{displayName(runAfter?.label ?? '')} · 칸을 누르면 해당 화면</span>
        </div>
        <div className="flow">
          <Link className="fc" to="/attacks"><span className="fn">01</span><span className="ft">공격 실행</span><span className="fv">{num(attackN)}건</span><span className="fs2">Caldera 자동 · 시나리오별 반복 측정</span></Link>
          <Link className="fc" to="/attacks"><span className="fn">02</span><span className="ft">공격 성공</span><span className="fv">{success} / {attackN}</span><span className="fs2">정답지 기준</span></Link>
          <Link className="fc" to="/detection"><span className="fn">03</span><span className="ft">탐지</span><span className="fv">{detected} / {m02?.n ?? attackN}</span><span className="fs2">개선 전 {m02b ? `${m02b.x} / ${m02b.n}` : NO_RECORD}</span></Link>
          <Link className="fc gap" to="/revalidate"><span className="fn">04</span><span className="ft">공백 발견</span><span className="fv">{gapList.length}건</span><span className="fs2">관제 3 · 측정 도구 1</span></Link>
          <Link className="fc" to="/revalidate"><span className="fn">05</span><span className="ft">재검증</span><span className="fv">{resolved}건 해소</span><span className="fs2">SQL 인젝션 놓침 {beforeMissed ?? NO_RECORD} → {missed}</span></Link>
        </div>
      </section>

      <div className="metrics">
        <div className="mc"><span className="ml">공격 시도</span><strong>{num(attackN)}</strong><small>성공 {success} (정답지 기준) · 대조 요청 {controlN} 별도</small></div>
        <div className="mc p"><span className="ml">탐지됨</span><strong>{num(detected)}</strong><small>관제 알림 연결 기준</small></div>
        <div className="mc"><span className="ml">놓친 공격</span><strong>{num(missed)}</strong><small>개선 전 측정 {beforeMissed ?? NO_RECORD} → {missed}</small></div>
        <div className="mc p"><span className="ml">탐지 시간 (MTTD)</span><strong>{msToSec(m08?.p50_ms)}</strong><small>중앙값 · 개선 전 측정 {msToSec(m08b?.p50_ms)} (p95 {msToSec(m08b?.p95_ms)})</small></div>
      </div>

      <div className="two">
        <section className="panel">
          <div className="ph"><h2>공격 결과 분포</h2><span className="pm">공격 {success} · 대조 요청 {controlN} · 건</span></div>
          <div className="dist" role="img" aria-label={`성공 ${success}건, 실패 대조 ${controlN}건, 판정 불가 0건, 차단 0건`}>
            <div className="dcol"><span className="dcount">{success}</span><div className="dtrack"><Bar heightPct={total ? (success / total) * 100 : 0} color="#b899eb" /></div><span className="dlabel">성공</span></div>
            <div className="dcol"><span className="dcount">{controlN}</span><div className="dtrack"><Bar heightPct={total ? (controlN / total) * 100 : 0} color="#a0bce8" /></div><span className="dlabel">실패 (대조)</span></div>
            <div className="dcol"><span className="dcount">0</span><div className="dtrack"><Bar heightPct={0} color="#ffffff66" /></div><span className="dlabel">판정 불가</span></div>
            <div className="dcol"><span className="dcount">0</span><div className="dtrack"><Bar heightPct={0} color="#ffffff66" /></div><span className="dlabel">차단</span></div>
          </div>
          <p className="foot">대조 요청은 실패하도록 만든 정상 요청이라 공격 표본에서 제외합니다.</p>
        </section>

        <section className="panel">
          <div className="ph"><h2>성공한 공격의 탐지율</h2><span className="pm">{m02?.n ?? attackN}건 중 {detected}건</span></div>
          <div className="donut">
            <Donut
              value={detP}
              color="#71dd8c"
              centerText={detP != null ? `${pct(detP)}%` : NO_RECORD}
              ariaLabel={`성공한 공격 ${m02?.n ?? attackN}건 중 ${detected}건 탐지, ${detP != null ? pct(detP) + '%' : NO_RECORD}`}
            />
            <dl className="legend">
              <div><dt><span className="ld dot-det"></span>탐지됨</dt><dd>{detected}건</dd></div>
              <div><dt><span className="ld dot-miss"></span>놓침</dt><dd>{missed}건</dd></div>
              <div><dt><span className="ld dot-unk"></span>판정 불가</dt><dd>0건</dd></div>
            </dl>
          </div>
          <p className="foot">
            95% 신뢰도 {ci ? `${pctRange(ci.lo, ci.hi)}%` : NO_RECORD}
            {' · '}개선 전 측정 (10/21) {beforeP != null ? `${pct(beforeP)}%` : NO_RECORD}
            {m02b ? ` (${m02b.n}건 중 ${m02b.x}건)` : ''}
            {beforeCi ? ` · 95% 신뢰도 ${pctRange(beforeCi.lo, beforeCi.hi)}%` : ''}
          </p>
        </section>
      </div>

      <div className="board">
        <div className="bh"><div><div className="ctx">공격 시도 {attackN}건</div><h2>공격 결과와 탐지 결과</h2></div><Link className="link" to="/attacks">시도별로 보기 →</Link></div>
        <div className="vc">
          <div className="vcol"><h3>공격 결과<small>정답지 기준 · Target Web</small></h3><dl>
            <div><dt>성공</dt><dd className="t-attack">{success}</dd></div>
            <div><dt>실패</dt><dd>0</dd></div>
            <div><dt>판정 불가</dt><dd>0</dd></div>
          </dl></div>
          <div className="vcol"><h3>탐지 결과<small>관제 기준 · 정답지 미참조</small></h3><dl>
            <div><dt>탐지됨</dt><dd className="t-det">{detected}</dd></div>
            <div><dt>놓침</dt><dd>{missed}</dd></div>
            <div><dt>늦은 탐지</dt><dd>0</dd></div>
          </dl></div>
        </div>
        <p className="bnote">두 결과는 서로 보지 않고 따로 계산합니다. 기대 요청 {((runAfter?.expected_attempts ?? 0) + (runAfter?.expected_controls ?? 0))}건 · 기록 검증 {runAfter?.integrity_status === 'VALID' ? '일치' : (runAfter?.integrity_status ?? NO_RECORD)}(공격 {attackN} · 대조 {controlN})으로 이 측정의 수치를 확정했습니다.</p>
      </div>

      <div className="gapbar">
        <b>탐지 공백 {gapList.length}건</b>
        {gapList.map((g) => <span key={g.id} className={`chip ${chip(g.status)}`}>{chipLabel(g.status)}</span>)}
        <span className="gapbar-note">SQL 인젝션 앱 로그 공백 해소 · 놓친 공격 {beforeMissed ?? NO_RECORD} → {missed}</span>
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
