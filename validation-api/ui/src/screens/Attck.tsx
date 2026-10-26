import { Link } from 'react-router-dom';
import { Layout } from '../components/Layout';
import { Meter } from '../components/primitives';
import { useDashboard } from '../components/DashboardContext';
import { useAsync } from '../lib/useAsync';
import { api } from '../api';
import { byMetricScope } from '../lib/select';
import { NO_RECORD } from '../lib/ratio';
import type { RateRow, SnapshotRow } from '../api/types';
import '../styles/attck.css';

function sum(rows: RateRow[] | undefined, key: 'x' | 'n'): number {
  return (rows ?? []).reduce((acc, r) => acc + (r[key] ?? 0), 0);
}

export default function Attck() {
  const { runIds, runAfter, displayName } = useDashboard();
  const rates = useAsync(() => api.getRates(runIds.after), [runIds.after]);
  const snap = useAsync(() => api.getSnapshot('', runIds.after), [runIds.after]);
  const covA = useAsync(() => api.getCoverage(runIds.after), [runIds.after]);
  const covB = useAsync(() => api.getCoverage(runIds.before), [runIds.before]);
  const benignLogin = useAsync(() => api.getSnapshot('', runIds.benignLogin), [runIds.benignLogin]);

  // M01 = 공격 성공률, M02 = 탐지율. 두 값을 분리해 표시한다.
  const attackRows = (rates.data ?? []).filter(
    (r) => r.metric_id === 'M01' && r.scope_kind === 'SCENARIO'
  );
  const detectionRows = (rates.data ?? []).filter(
    (r) => r.metric_id === 'M02' && r.scope_kind === 'SCENARIO'
  );
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
  const loginBackend = (benignLogin.data ?? []).find(
    (r) => r.metric_id === 'M14a_BACKEND_CORR' && r.scope_key === 'BRUTE_FORCE'
  );

  const t1190AttackRows = attackRows.filter(
    (r) => ['SQLI', 'PATH_TRAVERSAL', 'SSRF'].includes(r.scope_key)
  );
  const t1110AttackRows = attackRows.filter((r) => r.scope_key === 'BRUTE_FORCE');

  const t1190DetectionRows = detectionRows.filter(
    (r) => ['SQLI', 'PATH_TRAVERSAL', 'SSRF'].includes(r.scope_key)
  );
  const t1110DetectionRows = detectionRows.filter((r) => r.scope_key === 'BRUTE_FORCE');

  const t1190N = sum(t1190AttackRows, 'n');
  const t1190Success = sum(t1190AttackRows, 'x');
  const t1190Det = sum(t1190DetectionRows, 'x');

  const t1110N = sum(t1110AttackRows, 'n');
  const t1110Success = sum(t1110AttackRows, 'x');
  const t1110Det = sum(t1110DetectionRows, 'x');

  const sensorFor = (metricId: string, key: string): SnapshotRow | undefined =>
    (snap.data ?? []).find(
      (r) => r.metric_id === metricId
        && r.scope_kind === 'SCENARIO'
        && r.scope_key === key
    );

  const sensorText = (row: SnapshotRow | undefined) =>
    !row || row.n <= 0 || row.status === 'NOT_APPLICABLE' || row.status === 'NO_RULE'
      ? NO_RECORD
      : `${row.x ?? 0}/${row.n}`;

  const sensorBadge = (row: SnapshotRow | undefined) =>
    row && row.n > 0 && row.status === 'OK' && (row.x ?? 0) === row.n ? 'b-ok' : 'b-nu';

  const coverageComplete = covN > 0 && covX === covN;

  const sensorGroup = (metricId: string, keys: string[]) => {
    const rows = keys
      .map((key) => sensorFor(metricId, key))
      .filter((r): r is SnapshotRow =>
        !!r && r.n > 0 && r.status !== 'NOT_APPLICABLE' && r.status !== 'NO_RULE'
      );

    if (rows.length === 0) return NO_RECORD;

    const x = rows.reduce((acc, r) => acc + (r.x ?? 0), 0);
    const n = rows.reduce((acc, r) => acc + r.n, 0);
    return `${x}/${n}`;
  };

  const sensorGroupBadge = (metricId: string, keys: string[]) => {
    const rows = keys
      .map((key) => sensorFor(metricId, key))
      .filter((r): r is SnapshotRow =>
        !!r && r.n > 0 && r.status !== 'NOT_APPLICABLE' && r.status !== 'NO_RULE'
      );
    return rows.length > 0 && rows.every((r) => r.status === 'OK' && (r.x ?? 0) === r.n)
      ? 'b-ok'
      : 'b-nu';
  };

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
        <div><span className="eyebrow">측정 기법</span><strong>{covN || NO_RECORD}</strong><small>시나리오 {attackRows.length || NO_RECORD}개</small></div>
        <div><span className="eyebrow">일관 탐지 기법</span><strong>{covX} / {covN}</strong><small>반복 측정 기준 · 개선 전 {covBefore ? `${covBefore.x} / ${covBefore.n}` : NO_RECORD}</small></div>
      </div>

      <section className="panel">
        <div className="ph"><div><div className="ctx">기법 커버리지</div><h2>측정 범위 커버리지</h2></div><button type="button" className="link" onClick={downloadLayer}>Navigator 레이어 내보내기 →</button></div>
        <div className="cov">
          <span className="cv">{covX} / {covN}</span>
          <div className="cd"><strong>{coverageComplete ? `측정한 기법 ${covN}개 모두 일관 탐지` : `일관 탐지 ${covX} / ${covN}`}</strong><p>개선 전 {covBefore ? `${covBefore.x} / ${covBefore.n}` : NO_RECORD} → 현재 {covX} / {covN} · 기법 단위 집계이므로 신뢰구간은 표시하지 않습니다.</p></div>
          <Meter widthPct={covN ? (covX / covN) * 100 : 0} color="#71dd8c" trackClass="ct" />
          <div className="cl"><span>T1190 · Exploit Public-Facing Application</span><span>T1110 · Brute Force</span></div>
        </div>
      </section>

      <section className="panel">
        <div className="ph"><div><div className="ctx">기술별 결과</div><h2>공격 · 탐지 대조</h2></div><span className="pm">ID 기준 정렬</span></div>
        <div className="grid">
          <div className="tc">
            <div className="th"><span>T1110</span><small>시도 {t1110N || NO_RECORD}</small></div>
            <div className="tn">Brute Force · 무차별 대입</div>
            <div className="stats"><div><span>공격 성공</span><strong>{t1110Success}</strong></div><div><span>공격 실패</span><strong>{t1110N - t1110Success}</strong></div><div><span>탐지됨</span><strong>{t1110Det}</strong></div><div><span>놓침</span><strong>{t1110N - t1110Det}</strong></div></div>
            <div className="sub">
              <div><span>백엔드 상관</span><span className={`badge ${sensorBadge(sensorFor('M13_BACKEND_CORR', 'BRUTE_FORCE'))}`}>{sensorText(sensorFor('M13_BACKEND_CORR', 'BRUTE_FORCE'))}</span></div>
              <div><span>앱 로그</span><span className={`badge ${sensorBadge(sensorFor('M13_APP_RULE', 'BRUTE_FORCE'))}`}>{sensorText(sensorFor('M13_APP_RULE', 'BRUTE_FORCE'))}</span></div>
              <div><span>네트워크</span><span className={`badge ${sensorBadge(sensorFor('M13_NIDS', 'BRUTE_FORCE'))}`}>{sensorText(sensorFor('M13_NIDS', 'BRUTE_FORCE'))}</span></div>
              <div><span>정상 로그인 · 최종 FP</span><span className={`badge ${loginBackend && (loginBackend.x ?? 0) === 0 ? 'b-ok' : 'b-dg'}`}>{loginBackend ? `${loginBackend.x ?? 0}/${loginBackend.n}` : NO_RECORD}</span></div>
              <div><span>정상 로그인 · 원시 NIDS</span><span className="badge b-nu">{loginNids ? `${loginNids.x ?? 0}/${loginNids.n}` : NO_RECORD}</span></div>
            </div>
            <Link className="link" to="/attacks">시도별 결과 보기 →</Link>
          </div>
          <div className="tc">
            <div className="th"><span>T1190</span><small>시도 {t1190N || NO_RECORD}</small></div>
            <div className="tn">Exploit Public-Facing Application · SQL 인젝션 · 경로 조작 · SSRF</div>
            <div className="stats"><div><span>공격 성공</span><strong>{t1190Success}</strong></div><div><span>공격 실패</span><strong>{t1190N - t1190Success}</strong></div><div><span>탐지됨</span><strong>{t1190Det}</strong></div><div><span>놓침</span><strong>{t1190N - t1190Det}</strong></div></div>
            <div className="sub">
              <div><span>앱 로그</span><span className={`badge ${sensorGroupBadge('M13_APP_RULE', ['SQLI', 'PATH_TRAVERSAL', 'SSRF'])}`}>{sensorGroup('M13_APP_RULE', ['SQLI', 'PATH_TRAVERSAL', 'SSRF'])}</span></div>
              <div><span>네트워크 · SQL 인젝션</span><span className={`badge ${sensorBadge(sensorFor('M13_NIDS', 'SQLI'))}`}>{sensorText(sensorFor('M13_NIDS', 'SQLI'))}</span></div>
              <div><span>네트워크 · 경로 조작 · SSRF</span><span className={`badge ${sensorGroupBadge('M13_NIDS', ['PATH_TRAVERSAL', 'SSRF'])}`}>{sensorGroup('M13_NIDS', ['PATH_TRAVERSAL', 'SSRF'])}</span></div>
            </div>
            <Link className="link" to="/attacks">시도별 결과 보기 →</Link>
          </div>
        </div>
      </section>
    </Layout>
  );
}
