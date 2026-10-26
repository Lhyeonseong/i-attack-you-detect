import { Layout } from '../components/Layout';
import { Meter } from '../components/primitives';
import { BadgeText } from '../components/Badge';
import { useDashboard } from '../components/DashboardContext';
import { useAsync } from '../lib/useAsync';
import { api } from '../api';
import { byMetricScope } from '../lib/select';
import { wilson, pct, pctRange, diffMain, NO_RECORD } from '../lib/ratio';
import type { SnapshotRow } from '../api/types';
import '../styles/revalidate.css';

const STATUS_BADGE: Record<string, string> = { '해결': 'b-ok', '확인 필요': 'b-dg', '개선 예정': 'b-at', '발견': 'b-nu' };

export default function Revalidate() {
  const { runIds, runBefore, runAfter, runs } = useDashboard();
  const snapA = useAsync(() => api.getSnapshot('', runIds.after), [runIds.after]);
  const snapB = useAsync(() => api.getSnapshot('', runIds.before), [runIds.before]);
  const benignWeb = useAsync(() => api.getSnapshot('', runIds.benignWeb), [runIds.benignWeb]);
  const benignLogin = useAsync(() => api.getSnapshot('', runIds.benignLogin), [runIds.benignLogin]);
  const compare = useAsync(() => api.getCompare(runIds.before, runIds.after), [runIds.before, runIds.after]);
  const attempts = useAsync(() => api.getAttempts(runIds.after), [runIds.after]);
  const gaps = useAsync(() => api.getGaps(), []);

  const def = snapA.data?.[0]?.definition_version ?? '';
  const m02a = byMetricScope<SnapshotRow>(snapA.data, 'M02', 'ALL');
  const m02b = byMetricScope<SnapshotRow>(snapB.data, 'M02', 'ALL');
  const benignSqliApp = (benignWeb.data ?? []).find(
    (r) => r.metric_id === 'M14a_APP_RULE' && r.scope_key === 'SQLI'
  );
  const loginNids = (benignLogin.data ?? []).find(
    (r) => r.metric_id === 'M14a_NIDS' && r.scope_key === 'BRUTE_FORCE'
  );
  const loginBackend = (benignLogin.data ?? []).find(
    (r) => r.metric_id === 'M14a_BACKEND_CORR' && r.scope_key === 'BRUTE_FORCE'
  );
  const sqliNids = (snapA.data ?? []).find(
    (r) => r.metric_id === 'M13_NIDS'
      && r.scope_kind === 'SCENARIO'
      && r.scope_key === 'SQLI'
  );
  const benignLoginRun = runs.find((r) => r.run_id === runIds.benignLogin);

  const controlAttempts = (attempts.data ?? []).filter(
    (a) => a.attempt_role === 'CONTROL'
  );
  const validControls = controlAttempts.filter(
    (a) => a.gt_outcome === 'FAILED' && a.verdict === 'FAILED_UNSEEN'
  );
  const controlStatusOk =
    controlAttempts.length > 0 && validControls.length === controlAttempts.length;

  // /compare 는 모든 metric×scope 를 반환 → 주지표(M03 놓침률 · SQLI 시나리오) 행을 집어낸다.
  const row = compare.data?.rows.find((r) => r.metric_id === 'M03' && r.scope_kind === 'SCENARIO' && r.scope_key === 'SQLI');

  const afterP = m02a?.p ?? null;
  const beforeP = m02b?.p ?? null;
  const afterCi = m02a && m02a.lo != null && m02a.hi != null ? { lo: m02a.lo, hi: m02a.hi } : null;
  const beforeMissed = m02b ? m02b.n - (m02b.x ?? 0) : null;
  const afterMissed = m02a ? m02a.n - (m02a.x ?? 0) : null;

  // SQLI 탐지 건수 / before·after 비율(Wilson 픽스처)
  const x1 = row?.x1 ?? 0, n1 = row?.n1 ?? 0, x2 = row?.x2 ?? 0, n2 = row?.n2 ?? 0;
  const sqliBeforeCi = n1 ? wilson(x1, n1) : null;
  const sqliAfterCi = n2 ? wilson(x2, n2) : null;
  const detectionFor = (rows: SnapshotRow[] | null, key: string) =>
    (rows ?? []).find((r) =>
      r.metric_id === 'M02' && r.scope_kind === 'SCENARIO' && r.scope_key === key
    );

  const scenarioComparisons = [
    { key: 'SQLI', name: 'SQL 인젝션', technique: 'T1190', focus: true },
    { key: 'PATH_TRAVERSAL', name: '경로 조작', technique: 'T1190', focus: false },
    { key: 'SSRF', name: 'SSRF', technique: 'T1190', focus: false },
    { key: 'BRUTE_FORCE', name: '무차별 대입', technique: 'T1110', focus: false },
  ].map((item) => ({
    ...item,
    before: detectionFor(snapB.data, item.key),
    after: detectionFor(snapA.data, item.key),
  }));

  const otherScenariosMaintained = scenarioComparisons
    .filter((item) => !item.focus)
    .every((item) => item.before && item.after && item.before.n > 0 && item.after.n > 0 && item.before.x === item.before.n && item.after.x === item.after.n);

  const sqliAfter = scenarioComparisons.find((item) => item.key === 'SQLI')?.after;
  const sqliImproved =
    !!sqliAfter && sqliAfter.n > 0 && (sqliAfter.x ?? 0) === sqliAfter.n;

  const benignSqliClean =
    !!benignSqliApp && benignSqliApp.n > 0 && (benignSqliApp.x ?? 0) === 0;

  const revalidationPassed =
    sqliImproved && benignSqliClean && otherScenariosMaintained;

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
        reval_run: benignLoginRun?.label ?? g.reval_run,
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
  const cnt = (s: string) => gapList.filter((g) => g.status === s).length;

  return (
    <Layout screenId="revalidate" title="공백 · 재검증" topNote="사전 등록 기준 ADR-S5-01">
      <div className="heading">
        <div className="eyebrow">개선 · 재검증</div>
        <h1>공백 · 재검증</h1>
        <p>측정에서 찾은 탐지 공백을 개선하고, 같은 공격으로 다시 측정해 효과와 부작용을 확인합니다.</p>
      </div>
      <div className="note">판정 기준은 재측정 전에 미리 고정했습니다. 같은 공격 시나리오 · 같은 정상 요청 데이터 · 같은 지표 정의로 비교합니다.</div>

      <div className="board">
        <div className="bh"><div><div className="ctx">SQL 인젝션 · 앱 로그 관제 · Gap #7</div><h2>SQL 인젝션 탐지 공백 해소</h2></div><BadgeText cls="b-ok">해소</BadgeText></div>
        <div className="hero">
          <div><div className="hero-l">놓친 공격</div><div className="hero-v">{beforeMissed ?? NO_RECORD} <span className="t-unk">→</span> <span className="t-det">{afterMissed ?? NO_RECORD}</span></div><div className="hero-s">SQL 인젝션 · 개선 전 {n1}회 / 개선 후 {n2}회</div></div>
          <div><div className="hero-l">성공한 공격의 탐지율</div><div className="hero-v">{beforeP != null ? `${pct(beforeP)}%` : NO_RECORD} <span className="t-unk">→</span> <span className="t-det">{afterP != null ? `${pct(afterP)}%` : NO_RECORD}</span></div><div className="hero-s">개선 전 {m02b ? `${m02b.n}건 중 ${m02b.x}건` : NO_RECORD} → 개선 후 {m02a ? `${m02a.n}건 중 ${m02a.x}건` : NO_RECORD} · 95% 신뢰도 {afterCi ? `${pctRange(afterCi.lo, afterCi.hi)}%` : NO_RECORD}</div></div>
        </div>
        <div className="flow"><span className="fs">발견</span><span className="fa">→</span><span className="fs">원인 분석</span><span className="fa">→</span><span className="fs">룰 개선</span><span className="fa">→</span><span className="fs">재검증</span><span className="fa">→</span><span className="fs">해소</span></div>
        <p className="bnote">측정으로 탐지 공백을 찾고, 원인을 분석해 탐지 룰을 개선한 뒤, 같은 공격으로 재검증했습니다. 놓치던 공격을 이제 관제가 탐지합니다. 개선 대상은 관제의 탐지이며, 시험 대상인 취약점은 그대로 두었습니다.</p>
      </div>

      <section className="panel scenario-compare">
        <div className="ph"><h2>시나리오별 탐지율 · 개선 전 / 후</h2><span className="pm">실측 · 성공한 공격 기준</span></div>
        <div className="scenario-list">
          {scenarioComparisons.map((item) => {
            const before = item.before;
            const after = item.after;
            const beforeRate = before && before.n > 0 ? (before.x ?? 0) / before.n : null;
            const afterRate = after && after.n > 0 ? (after.x ?? 0) / after.n : null;
            const maintained = beforeRate != null && afterRate != null && beforeRate === afterRate;
            return (
              <div className={`scenario-row ${item.focus ? 'focus' : ''}`} key={item.key}>
                <div className="scenario-name">
                  <b>{item.name}</b>
                  <span>{item.technique}{item.focus ? ' · 개선 대상' : ''}</span>
                </div>
                <div className="scenario-bars">
                  <div className="compare-line">
                    <span>개선 전</span>
                    <Meter widthPct={beforeRate != null ? beforeRate * 100 : 0} color="#b899eb" trackClass="sbar-track" fillClass="sbar-fill" />
                    <strong>{before ? `${before.x ?? 0}/${before.n}` : NO_RECORD}</strong>
                  </div>
                  <div className="compare-line">
                    <span>개선 후</span>
                    <Meter widthPct={afterRate != null ? afterRate * 100 : 0} color="#71dd8c" trackClass="sbar-track" fillClass="sbar-fill" />
                    <strong>{after ? `${after.x ?? 0}/${after.n}` : NO_RECORD}</strong>
                  </div>
                </div>
                <BadgeText cls={afterRate === 1 ? 'b-ok' : 'b-dg'}>
                  {item.focus ? (afterRate === 1 ? '개선 확인' : '확인 필요') : (maintained ? '유지 확인' : '변화 확인')}
                </BadgeText>
              </div>
            );
          })}
        </div>
        <p className="foot">SQL 인젝션 95% 신뢰도: 개선 전 {sqliBeforeCi ? `${pctRange(sqliBeforeCi.lo, sqliBeforeCi.hi)}%` : NO_RECORD} → 개선 후 {sqliAfterCi ? `${pctRange(sqliAfterCi.lo, sqliAfterCi.hi)}%` : NO_RECORD}. 다른 시나리오도 같은 방식으로 개선 전·후 실측값을 비교합니다.</p>
      </section>

      <div className="metrics">
        <div className="mc"><span className="ml">발견 이슈</span><strong>{gapList.length}</strong><small>발견 이력 전체</small></div>
        <div className="mc"><span className="ml">해결</span><strong className="t-det">{cnt('해결')}</strong><small>최신 재검증 기준</small></div>
        <div className="mc"><span className="ml">현재 확인 필요</span><strong>{cnt('확인 필요')}</strong><small>최신 실측 기준</small></div>
        <div className="mc"><span className="ml">추가 추적</span><strong>{cnt('개선 예정') + cnt('발견')}</strong><small>발견 이력·별도 확인 항목</small></div>
      </div>

      <div className="board">
        <div className="bh"><div><div className="ctx">발견 → 원인 → 개선 → 재검증</div><h2>공백 목록</h2></div></div>
        <div className="tw">
          <table>
            <thead><tr><th>공백</th><th>관제</th><th>발견 측정</th><th>개선</th><th>재검증 측정</th><th>결과</th></tr></thead>
            <tbody>
              {gapList.map((g, i) => (
                <tr key={g.id} className={i === 0 ? 'sel' : undefined}>
                  <td><span className="pc">{g.title}</span><span className="sc">{g.detail}</span></td>
                  <td>{g.control}</td>
                  <td>{g.found_run}{g.found_note ? <span className="sc">{g.found_note}</span> : null}</td>
                  <td>{g.fix}{g.fix_note ? <span className="sc">{g.fix_note}</span> : null}</td>
                  <td>
                    {g.id === 'Gap-login'
                      ? <>
                          {benignLoginRun?.label ?? NO_RECORD}
                          <span className="sc">
                            최종 FP {loginBackend ? `${loginBackend.x ?? 0} / ${loginBackend.n}` : NO_RECORD}
                            {loginNids ? ` · 원시 NIDS ${loginNids.x ?? 0} / ${loginNids.n}` : ''}
                          </span>
                        </>
                      : <>
                          {g.reval_run}
                          {g.reval_note ? <span className="sc">{g.reval_note}</span> : null}
                        </>}
                  </td>
                  <td><BadgeText cls={STATUS_BADGE[g.status] ?? 'b-nu'}>{g.status}</BadgeText></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="board">
        <div className="bh"><div><div className="ctx">선택한 공백 · SQL 인젝션 · 앱 로그</div><h2>재검증 결과</h2></div><BadgeText cls={revalidationPassed ? 'b-ok' : 'b-dg'}>{revalidationPassed ? '사전 기준 통과' : '확인 필요'}</BadgeText></div>
        <div className="vc">
          <div className="vcol"><h3>개선 효과<small>주지표 · 놓친 SQL 인젝션</small></h3><dl>
            <div><dt>개선 전</dt><dd className="t-attack">{beforeMissed ?? NO_RECORD} / {n1}</dd></div>
            <div><dt>개선 후</dt><dd className="t-det">{afterMissed ?? 0} / {n2}</dd></div>
            <div><dt>변화</dt><dd>{row ? diffMain(row.diff, row.lo, row.hi).split(' · ')[0] : NO_RECORD}</dd></div>
            <div><dt>95% 신뢰도</dt><dd>{row ? `${(row.lo * 100).toFixed(1).replace(/\.0$/, '')} ~ ${(row.hi * 100).toFixed(1)}%p` : NO_RECORD}</dd></div>
          </dl></div>
          <div className="vcol"><h3>부작용 점검<small>가드레일 3개</small></h3><dl>
            <div><dt>정상 요청 오탐</dt><dd>{benignSqliApp ? `${benignSqliApp.x ?? 0} / ${benignSqliApp.n}` : NO_RECORD} <BadgeText cls={benignSqliClean ? 'b-ok' : 'b-dg'}>{benignSqliClean ? '통과' : '확인'}</BadgeText></dd></div>
            <div><dt>다른 공격 탐지</dt><dd>{otherScenariosMaintained ? '개선 전·후 유지' : '변화 확인 필요'} <BadgeText cls={otherScenariosMaintained ? 'b-ok' : 'b-dg'}>{otherScenariosMaintained ? '통과' : '확인'}</BadgeText></dd></div>
          </dl></div>
        </div>
        <p className="bnote">비교 측정: 개선 전 {runBefore?.label ?? NO_RECORD} / 개선 후 {runAfter?.label ?? NO_RECORD} · 정의 {def || NO_RECORD}</p>
      </div>
    </Layout>
  );
}
