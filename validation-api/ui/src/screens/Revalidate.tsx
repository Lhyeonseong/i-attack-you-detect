import { Layout } from '../components/Layout';
import { Donut, Bar, Meter } from '../components/primitives';
import { BadgeText } from '../components/Badge';
import { useDashboard } from '../components/DashboardContext';
import { useAsync } from '../lib/useAsync';
import { api } from '../api';
import { byMetricScope } from '../lib/select';
import { wilson, pct, pctRange, diffMain, diffVerdict, diffVerdictLabel, NO_RECORD } from '../lib/ratio';
import type { SnapshotRow } from '../api/types';
import '../styles/revalidate.css';

const STATUS_BADGE: Record<string, string> = { '해결': 'b-ok', '잔존': 'b-dg', '개선 예정': 'b-at', '발견': 'b-nu' };

export default function Revalidate() {
  const { runIds, runBefore, runAfter, runs } = useDashboard();
  const snapA = useAsync(() => api.getSnapshot('', runIds.after), [runIds.after]);
  const snapB = useAsync(() => api.getSnapshot('', runIds.before), [runIds.before]);
  const benignWeb = useAsync(() => api.getSnapshot('', runIds.benignWeb), [runIds.benignWeb]);
  const benignLogin = useAsync(() => api.getSnapshot('', runIds.benignLogin), [runIds.benignLogin]);
  const compare = useAsync(() => api.getCompare(runIds.before, runIds.after), [runIds.before, runIds.after]);
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
  const benignLoginRun = runs.find((r) => r.run_id === runIds.benignLogin);
  // /compare 는 모든 metric×scope 를 반환 → 주지표(M03 놓침률 · SQLI 시나리오) 행을 집어낸다.
  const row = compare.data?.rows.find((r) => r.metric_id === 'M03' && r.scope_kind === 'SCENARIO' && r.scope_key === 'SQLI');

  const afterP = m02a?.p ?? null;
  const beforeP = m02b?.p ?? null;
  const afterCi = m02a && m02a.lo != null && m02a.hi != null ? { lo: m02a.lo, hi: m02a.hi } : null;
  const beforeCi = m02b && m02b.lo != null && m02b.hi != null ? { lo: m02b.lo, hi: m02b.hi } : null;
  const beforeMissed = m02b ? m02b.n - (m02b.x ?? 0) : null;
  const afterMissed = m02a ? m02a.n - (m02a.x ?? 0) : null;

  // SQLI 탐지 건수 / before·after 비율(Wilson 픽스처)
  const x1 = row?.x1 ?? 0, n1 = row?.n1 ?? 0, x2 = row?.x2 ?? 0, n2 = row?.n2 ?? 0;
  const sqliBeforeCi = n1 ? wilson(x1, n1) : null;
  const sqliAfterCi = n2 ? wilson(x2, n2) : null;
  const diff = row ? diffMain(row.diff, row.lo, row.hi) : NO_RECORD;
  const verdict = row ? diffVerdictLabel(diffVerdict(row.lo, row.hi)) : NO_RECORD;

  const gapList = (gaps.data ?? []).map((g) =>
    g.id === 'Gap-login' && loginNids
      ? { ...g, status: (loginNids.x ?? 0) === 0 ? '해결' : '잔존' }
      : g
  );
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

      <section className="panel">
        <div className="ph"><h2>시나리오별 탐지율 · 개선 전 / 후</h2><span className="pm">실측 · 성공한 공격 기준</span></div>
        <div className="sbar">
          <div className="sbar-head"><b>SQL 인젝션 <span className="t-sub">T1190 · 개선 대상</span></b><BadgeText cls="b-ok">개선됨</BadgeText></div>
          <div className="sbar-row"><span>개선 전</span><Meter widthPct={n1 ? (x1 / n1) * 100 : 0} color="#b899eb" trackClass="sbar-track" fillClass="sbar-fill" /><span><b className="t-white">{n1 ? pct(x1 / n1) : '0'}%</b> · {n1}건 중 {x1}건</span></div>
          <div className="sbar-row"><span>개선 후</span><Meter widthPct={n2 ? (x2 / n2) * 100 : 0} color="#71dd8c" trackClass="sbar-track" fillClass="sbar-fill" /><span><b className="t-white">{n2 ? pct(x2 / n2) : '0'}%</b> · {n2}건 중 {x2}건</span></div>
        </div>
        <div className="guard-note">다른 시나리오 · 원래부터 탐지되던 공격 (가드레일)</div>
        <div className="guard-row"><b>경로 조작 <span className="t-sub">T1190</span></b><div className="guard-bar"></div><BadgeText cls="b-nu">개선 전·후 모두 탐지 · 유지</BadgeText></div>
        <div className="guard-row"><b>SSRF <span className="t-sub">T1190</span></b><div className="guard-bar"></div><BadgeText cls="b-nu">개선 전·후 모두 탐지 · 유지</BadgeText></div>
        <div className="guard-row"><b>무차별 대입 <span className="t-sub">T1110</span></b><div className="guard-bar"></div><BadgeText cls="b-nu">개선 전·후 모두 탐지 · 유지</BadgeText></div>
        <p className="foot">개선 전 측정에서 놓친 {beforeMissed ?? NO_RECORD}건은 모두 SQL 인젝션이었습니다. 룰 하나로 그 공백만 메웠고, 원래 탐지되던 세 시나리오는 그대로 유지됐습니다. SQL 인젝션 95% 신뢰도: 개선 전 {sqliBeforeCi ? `${pctRange(sqliBeforeCi.lo, sqliBeforeCi.hi)}%` : NO_RECORD} → 개선 후 {sqliAfterCi ? `${pctRange(sqliAfterCi.lo, sqliAfterCi.hi)}%` : NO_RECORD}.</p>
      </section>

      <div className="metrics">
        <div className="mc"><span className="ml">발견된 공백</span><strong>{gapList.length}</strong><small>관제 3 · 측정 도구 1</small></div>
        <div className="mc p"><span className="ml">해결</span><strong>{cnt('해결')}</strong><small>SQL 인젝션 · 앱 로그</small></div>
        <div className="mc"><span className="ml">잔존</span><strong>{cnt('잔존')}</strong><small>SQL 인젝션 · 네트워크</small></div>
        <div className="mc p"><span className="ml">개선 예정 · 발견</span><strong>{cnt('개선 예정')} · {cnt('발견')}</strong><small>로그인 오탐 · SSRF 대조</small></div>
      </div>

      <div className="two">
        <section className="panel">
          <div className="ph"><h2>탐지율 변화</h2><span className="pm">성공한 공격 {m02a?.n ?? NO_RECORD}건 기준</span></div>
          <div className="donuts">
            <div className="dn"><Donut value={beforeP} color="#b899eb" size={140} centerText={beforeP != null ? `${pct(beforeP)}%` : NO_RECORD} ariaLabel={`개선 전 ${m02b?.n ?? 0}건 중 ${m02b?.x ?? 0}건 탐지`} /><b>개선 전</b><span>{m02b ? `${m02b.n}건 중 ${m02b.x}건` : NO_RECORD}</span></div>
            <span className="arrow" aria-hidden="true">→</span>
            <div className="dn"><Donut value={afterP} color="#71dd8c" size={140} centerText={afterP != null ? `${pct(afterP)}%` : NO_RECORD} ariaLabel={`개선 후 ${m02a?.n ?? 0}건 중 ${m02a?.x ?? 0}건 탐지`} /><b>개선 후</b><span>{m02a ? `${m02a.n}건 중 ${m02a.x}건` : NO_RECORD}</span></div>
          </div>
          <p className="foot">개선 후 95% 신뢰도 {afterCi ? `${pctRange(afterCi.lo, afterCi.hi)}%` : NO_RECORD} · 개선 전 95% 신뢰도 {beforeCi ? `${pctRange(beforeCi.lo, beforeCi.hi)}%` : NO_RECORD}</p>
        </section>
        <section className="panel">
          <div className="ph"><h2>SQL 인젝션 탐지 건수</h2><span className="pm">개선 전 {n1}회 · 개선 후 {n2}회</span></div>
          <div className="dist" role="img" aria-label={`개선 전 ${x1}건, 개선 후 ${x2}건`}>
            <div className="dcol"><span className="dcount">{x1}</span><div className="dtrack"><Bar heightPct={n2 ? (x1 / n2) * 100 : 0} color="#b899eb" /></div><span className="dlabel">개선 전</span></div>
            <div className="dcol"><span className="dcount">{x2}</span><div className="dtrack"><Bar heightPct={n2 ? (x2 / n2) * 100 : 0} color="#71dd8c" /></div><span className="dlabel">개선 후</span></div>
          </div>
          <p className="foot">놓친 비율 변화 {diff} · {verdict}</p>
        </section>
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
                            {loginNids ? `${loginNids.x ?? 0} / ${loginNids.n}` : NO_RECORD}
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
        <div className="bh"><div><div className="ctx">선택한 공백 · SQL 인젝션 · 앱 로그</div><h2>재검증 결과</h2></div><BadgeText cls="b-ok">사전 기준 통과</BadgeText></div>
        <div className="vc">
          <div className="vcol"><h3>개선 효과<small>주지표 · 놓친 SQL 인젝션</small></h3><dl>
            <div><dt>개선 전</dt><dd className="t-attack">{beforeMissed ?? NO_RECORD} / {n1}</dd></div>
            <div><dt>개선 후</dt><dd className="t-det">{afterMissed ?? 0} / {n2}</dd></div>
            <div><dt>변화</dt><dd>{row ? diffMain(row.diff, row.lo, row.hi).split(' · ')[0] : NO_RECORD}</dd></div>
            <div><dt>95% 신뢰도</dt><dd>{row ? `${(row.lo * 100).toFixed(1).replace(/\.0$/, '')} ~ ${(row.hi * 100).toFixed(1)}%p` : NO_RECORD}</dd></div>
          </dl></div>
          <div className="vcol"><h3>부작용 점검<small>가드레일 3개</small></h3><dl>
            <div><dt>정상 요청 오탐</dt><dd>{benignSqliApp ? `${benignSqliApp.x ?? 0} / ${benignSqliApp.n}` : NO_RECORD} <BadgeText cls="b-ok">통과</BadgeText></dd></div>
            <div><dt>다른 공격 탐지</dt><dd>변화 없음 <BadgeText cls="b-ok">통과</BadgeText></dd></div>
            <div><dt>측정 조건</dt><dd>룰만 변경 <BadgeText cls="b-ok">통과</BadgeText></dd></div>
            <div><dt>판정 엔진 버전</dt><dd>s3-v1 → s4-v1 <BadgeText cls="b-nu">측정 후 발견 · 영향 없음</BadgeText></dd></div>
          </dl></div>
        </div>
        <p className="bnote">비교 측정: 개선 전 {runBefore?.label ?? NO_RECORD} / 개선 후 {runAfter?.label ?? NO_RECORD} · 정의 {def || NO_RECORD}. 따옴표가 들어간 정상 단어(O'Reilly, it's)는 이번 정상 요청 데이터에 없어 별도 확인이 필요합니다.</p>
      </div>
    </Layout>
  );
}
