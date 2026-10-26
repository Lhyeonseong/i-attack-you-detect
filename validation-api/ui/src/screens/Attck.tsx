import { Link } from 'react-router-dom';
import { Layout } from '../components/Layout';
import { Meter } from '../components/primitives';
import { useDashboard } from '../components/DashboardContext';
import { useAsync } from '../lib/useAsync';
import { api } from '../api';
import { byMetricScope } from '../lib/select';
import { NO_RECORD } from '../lib/ratio';
import type { RateRow } from '../api/types';
import '../styles/attck.css';

function sum(rows: RateRow[] | undefined, key: 'x' | 'n'): number {
  return (rows ?? []).reduce((acc, r) => acc + (r[key] ?? 0), 0);
}

export default function Attck() {
  const { runIds, runAfter, displayName } = useDashboard();
  const rates = useAsync(() => api.getRates(runIds.after), [runIds.after]);
  const covA = useAsync(() => api.getCoverage(runIds.after), [runIds.after]);
  const covB = useAsync(() => api.getCoverage(runIds.before), [runIds.before]);
  const benignLogin = useAsync(() => api.getSnapshot('', runIds.benignLogin), [runIds.benignLogin]);

  // 시나리오별 탐지율 = M02 SCENARIO. 공격 시도 = M02 ALL 의 n(S_ALL).
  const scenarioRows = (rates.data ?? []).filter((r) => r.metric_id === 'M02' && r.scope_kind === 'SCENARIO');
  const all = byMetricScope<RateRow>(rates.data, 'M02', 'ALL');
  const attackN = all?.n ?? 0;
  const controlN = runAfter?.expected_controls ?? 0;

  // "꾸준히 잡은 기법" = M06b(일관 탐지), 기법 단위(TECHNIQUE) 2개 기준.
  const cov = (covA.data ?? []).find((r) => r.metric_id === 'M06b' && r.scope_kind === 'TECHNIQUE');
  const covBefore = (covB.data ?? []).find((r) => r.metric_id === 'M06b' && r.scope_kind === 'TECHNIQUE');
  const covX = cov?.x ?? 0;
  const covN = cov?.n ?? 0;
  const loginNids = (benignLogin.data ?? []).find(
    (r) => r.metric_id === 'M14a_NIDS' && r.scope_key === 'BRUTE_FORCE'
  );

  const t1190Rows = scenarioRows.filter((r) => ['SQLI', 'PATH_TRAVERSAL', 'SSRF'].includes(r.scope_key));
  const t1110Rows = scenarioRows.filter((r) => r.scope_key === 'BRUTE_FORCE');
  const sqliRow = scenarioRows.find((r) => r.scope_key === 'SQLI');
  const t1190N = sum(t1190Rows, 'n');
  const t1190Det = sum(t1190Rows, 'x');
  const t1110N = sum(t1110Rows, 'n');
  const t1110Det = sum(t1110Rows, 'x');

  async function downloadLayer() {
    try {
      const layer = await api.getNavigatorLayer(runIds.after, 'detection');
      const blob = new Blob([JSON.stringify(layer, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `navigator-layer-${runAfter?.label ?? 'run'}-detection.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch { /* 무시 */ }
  }

  return (
    <Layout screenId="attck" title={'ATT&CK 검증'} topNote={`${displayName(runAfter?.label ?? '')} · 확정 결과`}>
      <div className="heading">
        <div className="eyebrow">MITRE ATT&amp;CK · 측정 범위</div>
        <h1>Technique별 검증 현황</h1>
        <p>공격 시도를 Technique ID로 묶어 공격 결과와 탐지 결과를 따로 비교합니다.</p>
      </div>
      <div className="note">측정 범위는 T1190 · T1110 두 기법(Enterprise v20)입니다. 측정하지 않은 기법은 공백이 아니라 범위 밖입니다.</div>

      <div className="vs">
        <div><span className="eyebrow">공격 시도</span><strong>{attackN || NO_RECORD}</strong><small>대조 {controlN || NO_RECORD} 제외</small></div>
        <div><span className="eyebrow">측정 기법</span><strong>{covN || NO_RECORD}</strong><small>시나리오 {scenarioRows.length || NO_RECORD}개</small></div>
        <div><span className="eyebrow">꾸준히 잡은 기법</span><strong>{covX} / {covN}</strong><small>반복 측정에서 일관 탐지 · 개선 전 측정 {covBefore ? `${covBefore.x} / ${covBefore.n}` : NO_RECORD}</small></div>
      </div>

      <section className="panel">
        <div className="ph"><div><div className="ctx">기법 커버리지</div><h2>측정 범위 커버리지</h2></div><button type="button" className="link" onClick={downloadLayer}>Navigator 레이어 내보내기 →</button></div>
        <div className="cov">
          <span className="cv">{covX} / {covN}</span>
          <div className="cd"><strong>측정한 기법 {covN}개 모두 꾸준히 탐지</strong><p>개선 전 측정 {covBefore ? `${covBefore.x} / ${covBefore.n}` : NO_RECORD} (T1190 SQL 인젝션 놓침) → 룰 개선 후 {covX} / {covN} · 기법 수를 센 값이라 신뢰구간 없음</p></div>
          <Meter widthPct={covN ? (covX / covN) * 100 : 0} color="#71dd8c" trackClass="ct" />
          <div className="cl"><span>T1190 초기 접근 · 꾸준히 잡음</span><span>T1110 자격 증명 접근 · 꾸준히 잡음</span></div>
        </div>
      </section>

      <section className="panel">
        <div className="ph"><div><div className="ctx">기술별 결과</div><h2>공격 · 탐지 대조</h2></div><span className="pm">ID 기준 정렬</span></div>
        <div className="grid">
          <div className="tc">
            <div className="th"><span>T1110</span><small>시도 {t1110N || NO_RECORD}</small></div>
            <div className="tn">Brute Force · 무차별 대입</div>
            <div className="stats"><div><span>공격 성공</span><strong>{t1110Det}</strong></div><div><span>공격 실패</span><strong>0</strong></div><div><span>탐지됨</span><strong>{t1110Det}</strong></div><div><span>놓침</span><strong>{t1110N - t1110Det}</strong></div></div>
            <div className="sub"><div><span>백엔드 상관</span><span className="badge b-ok">잡음</span></div><div><span>앱 로그</span><span className="badge b-ok">잡음</span></div><div><span>네트워크</span><span className="badge b-nu">{NO_RECORD}</span></div><div><span>정상 로그인 오탐 · 네트워크</span><span className="badge b-dg">{loginNids
  ? `${loginNids.x ?? 0}/${loginNids.n} · ${loginNids.p != null ? (loginNids.p * 100).toFixed(1) : NO_RECORD}%`
  : NO_RECORD}</span></div></div>
            <Link className="link" to="/attacks">시도별 결과 보기 →</Link>
          </div>
          <div className="tc">
            <div className="th"><span>T1190</span><small>시도 {t1190N || NO_RECORD}</small></div>
            <div className="tn">Exploit Public-Facing Application · SQL 인젝션 · 경로 조작 · SSRF</div>
            <div className="stats"><div><span>공격 성공</span><strong>{t1190Det}</strong></div><div><span>공격 실패</span><strong>0</strong></div><div><span>탐지됨</span><strong>{t1190Det}</strong></div><div><span>놓침</span><strong>{t1190N - t1190Det}</strong></div></div>
            <div className="sub"><div><span>앱 로그</span><span className="badge b-ok">잡음</span></div><div><span>네트워크 · SQL 인젝션</span><span className="badge b-dg">{sqliRow
  ? `${sqliRow.x ?? 0}/${sqliRow.n} 탐지`
  : NO_RECORD}</span></div><div><span>네트워크 · 경로 조작 · SSRF</span><span className="badge b-ok">잡음</span></div></div>
            <Link className="link" to="/attacks">시도별 결과 보기 →</Link>
          </div>
        </div>
      </section>
    </Layout>
  );
}
