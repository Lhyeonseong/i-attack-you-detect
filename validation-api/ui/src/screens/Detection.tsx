import { Link } from 'react-router-dom';
import { Layout } from '../components/Layout';
import { Donut } from '../components/primitives';
import { RatioBlock } from '../components/RatioBlock';
import { useDashboard } from '../components/DashboardContext';
import { useAsync } from '../lib/useAsync';
import { api } from '../api';
import { byMetricScope } from '../lib/select';
import { kst } from '../lib/format';
import { NO_RECORD, pct, pctRange, wilson } from '../lib/ratio';
import { scenarioMeta } from '../lib/labels';
import type { SnapshotRow } from '../api/types';
import '../styles/detection.css';

const CONTROL: Record<string, { label: string; cls: string; src: string }> = {
  app: { label: '앱 로그', cls: 'b-ap', src: 'wazuh-alerts-4.x' },
  nids: { label: '네트워크', cls: 'b-nw', src: 'suricata eve' },
  backend: { label: '백엔드 상관', cls: 'b-bc', src: '시퀀스 상관' },
};

// M14a·M14b 는 /metrics 에 없고 BENIGN run 의 /snapshot 에만 있다. scope_key = 시나리오(웹 SQLI/PT/SSRF, login BRUTE_FORCE).
function fp(rows: SnapshotRow[] | null, metricId: string, scopeKey: string): SnapshotRow | undefined {
  return rows?.find((r) => r.metric_id === metricId && r.scope_key === scopeKey);
}

export default function Detection() {
  const { runIds, runAfter, displayName, runs } = useDashboard();
  const snap = useAsync(() => api.getSnapshot('', runIds.after), [runIds.after]);
  const benignWeb = useAsync(() => api.getSnapshot('', runIds.benignWeb), [runIds.benignWeb]);
  const benignLogin = useAsync(() => api.getSnapshot('', runIds.benignLogin), [runIds.benignLogin]);
  const attempts = useAsync(() => api.getAttempts(runIds.after), [runIds.after]);
  const links = useAsync(() => api.getAlertLinks(runIds.after), [runIds.after]);

  const m02 = byMetricScope<SnapshotRow>(snap.data, 'M02', 'ALL');
  const successN = m02?.n ?? null;

  // M13은 통제 × 시나리오 행이다.
  // DB가 OK로 판정한 적용 대상 시나리오만 합산하고,
  // NO_RULE / NOT_APPLICABLE / NOT_COLLECTED / NO_DATA는 분모에서 제외한다.
  function m13(metricId: string) {
    const rows = (snap.data ?? []).filter(
      (r) => r.metric_id === metricId
        && r.scope_kind === 'SCENARIO'
        && r.status === 'OK'
    );
    if (rows.length === 0) return null;

    const n = rows.reduce((sum, r) => sum + r.n, 0);
    const x = rows.reduce((sum, r) => sum + (r.x ?? 0), 0);
    if (n <= 0) return null;

    const p = x / n;
    const ci = wilson(x, n);
    return { x, n, p, lo: ci?.lo ?? null, hi: ci?.hi ?? null };
  }

  const sensorMetrics = {
    app: m13('M13_APP_RULE'),
    nids: m13('M13_NIDS'),
    backend: m13('M13_BACKEND_CORR'),
  };

  // 웹 오탐은 대표 시나리오(SQLI, 각 320) · 로그인 오탐은 BRUTE_FORCE(300).
  const webApp = fp(benignWeb.data, 'M14a_APP_RULE', 'SQLI');
  const webNids = fp(benignWeb.data, 'M14a_NIDS', 'SQLI');
  const loginBackend = fp(benignLogin.data, 'M14a_BACKEND_CORR', 'BRUTE_FORCE');
  const loginNids = fp(benignLogin.data, 'M14a_NIDS', 'BRUTE_FORCE');
  const webBenignN = (benignWeb.data ?? [])
    .filter((r) => r.metric_id === 'M14a_APP_RULE' && r.scope_kind === 'SCENARIO' && r.n > 0)
    .reduce((sum, r) => sum + r.n, 0);
  const totalBenign = webBenignN + (loginBackend?.n ?? 0);
  const finalFp = loginBackend?.x ?? null;
  const rawLoginNidsFp = loginNids?.x ?? null;
  const benignLoginRun = runs.find((r) => r.run_id === runIds.benignLogin);

  const attemptById = new Map((attempts.data ?? []).map((a) => [a.attempt_id, a]));
  const alerts = links.data ?? [];

  const sensors = [
    { key: 'app' as const, name: '앱 로그 관제', sub: 'Wazuh 룰' },
    { key: 'nids' as const, name: '네트워크 관제', sub: 'Suricata 룰' },
    { key: 'backend' as const, name: '백엔드 상관', sub: '로그인 시퀀스' },
  ];

  return (
    <Layout screenId="detection" title="탐지 분석" topNote={`${displayName(runAfter?.label ?? '')} · 확정 결과`}>
      <div className="heading">
        <div className="eyebrow">관제 경보</div>
        <h1>탐지 이벤트 조사</h1>
        <p>공격 시도에 연결된 관제 경보를 관제별로 살펴봅니다. 경보 수준은 공격 성공이나 차단 여부를 뜻하지 않습니다.</p>
      </div>
      <div className="note">경보는 앱 로그 관제(Wazuh), 네트워크 관제(Suricata), 백엔드 상관 세 곳에서 옵니다. 원본 로그와 페이로드는 표시하지 않습니다.</div>

      <section className="panel">
        <div className="ph"><div><div className="ctx">성공한 공격 {successN != null ? `${successN}건` : NO_RECORD} 기준</div><h2>관제별 탐지율</h2></div><span className="pm">각 관제 적용 대상 기준 · 다른 관제와 겹칠 수 있음</span></div>
        <div className="dn3">
          {sensors.map((s) => {
            const m = sensorMetrics[s.key];
            const center = m ? `${pct(m.p)}%` : NO_RECORD;
            const range = m && m.lo != null && m.hi != null
              ? `${pctRange(m.lo, m.hi)}%`
              : NO_RECORD;
            return (
              <div className="dnc" key={s.name}>
                <Donut
                  value={m?.p ?? null}
                  color="#71dd8c"
                  size={112}
                  centerText={center}
                  ariaLabel={m ? `${s.name}의 탐지율, ${m.n}건 중 ${m.x}건, ${center}` : `${s.name}의 탐지율, ${NO_RECORD}`}
                />
                <dl>
                  <dt>{s.name}</dt>
                  <dd>{s.sub}</dd>
                  <dd>{m ? `${m.n}건 중 ${m.x}건` : NO_RECORD}</dd>
                  <dd>95% 신뢰도 {range}</dd>
                </dl>
              </div>
            );
          })}
        </div>
      </section>

      <section className="panel">
        <div className="ph"><div><div className="ctx">정상 트래픽 재검증 · {benignLoginRun?.label ?? NO_RECORD}</div><h2>오탐 검증</h2></div><span className="pm">원시 경보와 최종 상관 판정을 분리합니다</span></div>
        <p className="fplead">
          정상 요청 {totalBenign.toLocaleString('ko-KR')}건 기준 최종 오탐은
          <b className={finalFp === 0 ? 't-det' : 't-danger'}> {finalFp != null ? `${finalFp}건` : NO_RECORD}</b>입니다.
          {rawLoginNidsFp != null ? ` 원시 네트워크 경보 ${rawLoginNidsFp}건은 관측 기록으로 유지합니다.` : ''}
        </p>
        <div className="tw"><table className="vt">
          <thead><tr><th>정상 요청</th><th>앱 로그 관제 / 백엔드 상관</th><th>네트워크 관제</th></tr></thead>
          <tbody>
            <tr>
              <td><b>웹 요청</b><small>상품 검색 · 파일 다운로드 · 미리보기 각 {webApp?.n ?? NO_RECORD}건</small></td>
              <td>{webApp ? <RatioBlock label="웹 요청 앱 로그 오탐" x={webApp.x} n={webApp.n} lo={webApp.lo} hi={webApp.hi} status={webApp.status === 'OK' ? 'VALID' : webApp.status} /> : NO_RECORD}</td>
              <td>{webNids ? <RatioBlock label="웹 요청 네트워크 오탐" x={webNids.x} n={webNids.n} lo={webNids.lo} hi={webNids.hi} status={webNids.status === 'OK' ? 'VALID' : webNids.status} /> : NO_RECORD}</td>
            </tr>
            <tr>
              <td><b>로그인</b><small>정상 로그인 {loginBackend?.n ?? NO_RECORD}건</small></td>
              <td>{loginBackend ? <RatioBlock label="로그인 백엔드 오탐" x={loginBackend.x} n={loginBackend.n} lo={loginBackend.lo} hi={loginBackend.hi} status={loginBackend.status === 'OK' ? 'VALID' : loginBackend.status} /> : NO_RECORD}</td>
              <td>{loginNids ? <RatioBlock label="로그인 네트워크 오탐" x={loginNids.x} n={loginNids.n} lo={loginNids.lo} hi={loginNids.hi} status={loginNids.status === 'OK' ? 'VALID' : loginNids.status} /> : NO_RECORD}</td>
            </tr>
          </tbody>
        </table></div>
        <p className="fpcellsub">
          네트워크 로그인 행은 원시 NIDS 경보입니다. 최종 오탐 판정은 로그인 시퀀스를 확인하는 백엔드 상관 결과를 기준으로 합니다.
        </p>
      </section>

      <section className="panel">
        <div className="ph"><div><div className="ctx">{displayName(runAfter?.label ?? '')}</div><h2>연결된 경보</h2></div><span className="pm">연결 경보 {alerts.length}건 · 탐지된 시도 {m02?.x ?? NO_RECORD}건</span></div>
        <div className="frow"><label htmlFor="q">검색</label><input id="q" className="inp" type="search" placeholder="rid · Operation ID · Technique · Rule ID" /><select className="selc" aria-label="관제"><option>모든 관제</option><option>앱 로그</option><option>네트워크</option><option>백엔드 상관</option></select></div>
        <div className="tw">
          <table>
            <thead><tr><th>시각</th><th>설명</th><th>rid / Operation</th><th>Technique</th><th>Rule · 수준</th><th>관제</th><th></th></tr></thead>
            <tbody>
              {alerts.map((l, i) => {
                const at = attemptById.get(l.attempt_id);
                const meta2 = at ? scenarioMeta(at) : null;
                const ctl = CONTROL[l.control] ?? { label: l.control, cls: 'b-nu', src: '' };
                return (
                  <tr key={i}>
                    <td>{kst(l.alert_time)}</td>
                    <td><span className="pc">{meta2 ? `${meta2.name} 시도` : NO_RECORD}</span><span className="sc">{ctl.src}</span></td>
                    <td><span className="pc">{l.rid}</span><span className="sc">{at?.op_id ?? NO_RECORD}</span></td>
                    <td>{at?.technique_id ?? NO_RECORD}</td>
                    <td><span className="pc rule">{l.rule_id}</span><span className="sc">{l.match_path}</span></td>
                    <td><span className={`badge ${ctl.cls}`}>{ctl.label}</span></td>
                    <td><Link className="link" to={`/attempts/${l.attempt_id}`}>상세 보기 →</Link></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <div className="pag"><span>페이지별 최대 50건</span><div className="pagbtns"><button type="button" className="sb">이전</button><button type="button" className="sb">다음</button></div></div>
      </section>
    </Layout>
  );
}
