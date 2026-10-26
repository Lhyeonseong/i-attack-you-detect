import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Layout } from '../components/Layout';
import { Badge } from '../components/Badge';
import { EventMarker } from '../components/primitives';
import { useDashboard } from '../components/DashboardContext';
import { useAsync } from '../lib/useAsync';
import { api } from '../api';
import { byMetricScope } from '../lib/select';
import { kst } from '../lib/format';
import { NO_RECORD } from '../lib/ratio';
import { scenarioMeta, gtBadge, detectionBadge, verdictBadge } from '../lib/labels';
import type { SnapshotRow } from '../api/types';
import '../styles/attacks.css';

type Tab = 'list' | 'network' | 'flow';

export default function Attacks() {
  const { runIds, runAfter, runBefore, displayName } = useDashboard();
  const [tab, setTab] = useState<Tab>('list');
  const attempts = useAsync(() => api.getAttempts(runIds.after), [runIds.after]);
  const snap = useAsync(() => api.getSnapshot('', runIds.after), [runIds.after]);
  const links = useAsync(() => api.getAlertLinks(runIds.after), [runIds.after]);
  const imds = useAsync(() => api.getImdsRequests(runIds.after), [runIds.after]);

  const m01 = byMetricScope<SnapshotRow>(snap.data, 'M01', 'ALL');
  const m02 = byMetricScope<SnapshotRow>(snap.data, 'M02', 'ALL');
  const attackN = m01?.n ?? 0;
  const controlN = runAfter?.expected_controls ?? 0;
  const detected = m02?.x ?? 0;
  const rows = attempts.data ?? [];
  const alerts = links.data ?? [];
  const appAlerts = alerts.filter((l) => l.control === 'app').length;
  const nidsAlerts = alerts.filter((l) => l.control === 'nids').length;
  const backendDetected = (snap.data ?? [])
    .filter((r) => r.metric_id === 'M13_BACKEND_CORR' && r.scope_kind === 'SCENARIO' && r.status === 'OK')
    .reduce((sum, r) => sum + (r.x ?? 0), 0);

  const timelineTimes = [
    ...rows.flatMap((a) => [a.attack_time, a.decided_at]),
    ...alerts.map((l) => l.alert_time),
  ]
    .map((t) => new Date(t).getTime())
    .filter((t) => Number.isFinite(t));

  const timelineMin = timelineTimes.length ? Math.min(...timelineTimes) : 0;
  const timelineMax = timelineTimes.length ? Math.max(...timelineTimes) : 0;
  const timelineSpan = Math.max(timelineMax - timelineMin, 1);

  const pct = (iso: string) => {
    const t = new Date(iso).getTime();
    if (!Number.isFinite(t) || !timelineTimes.length) return 0;
    return 5 + ((t - timelineMin) / timelineSpan) * 90;
  };

  const appAlertRows = alerts.filter((l) => l.control === 'app');
  const nidsAlertRows = alerts.filter((l) => l.control === 'nids');

  const tabBtn = (id: Tab, label: string) => (
    <button type="button" className="tab" role="tab" aria-selected={tab === id} onClick={() => setTab(id)}>{label}</button>
  );

  return (
    <Layout screenId="attacks" title="공격 결과" topNote={`${displayName(runAfter?.label ?? '')} · 확정 결과`}>
      <div className="heading">
        <div className="eyebrow">시도 단위 검증</div>
        <h1>공격 결과</h1>
        <p>공격 시도의 정답지 결과, 탐지, 판정을 같은 데이터로 살펴봅니다. 공격 성공과 탐지 여부는 각각 확인하세요.</p>
      </div>
      <div className="note">시도 범위: 선택한 측정의 공격 시도와 대조 요청. Attack Flow에서 Operation별 Caldera 실행 순서를 함께 봅니다.</div>

      <div className="panel">
        <div className="frow">
          <label htmlFor="run">측정</label>
          <select id="run" className="inp" defaultValue={runAfter?.label}>
            <option value={runAfter?.label ?? ""}>{runAfter ? `${runAfter.label} · ${runAfter.run_id.slice(0, 8)} · ${kst(runAfter.ended_at).split(" ")[0]}` : NO_RECORD}</option>
            <option value={runBefore?.label ?? ""}>{runBefore ? `${runBefore.label} · ${runBefore.run_id.slice(0, 8)} · ${kst(runBefore.ended_at).split(" ")[0]}` : NO_RECORD}</option>
          </select>
          <button type="button" className="pb">적용</button>
          <button type="button" className="sb">필터 초기화</button>
          <button type="button" className="sb">새로고침</button>
        </div>
        <div className="fgrid">
          <div><label htmlFor="f1">관찰 시작</label><input id="f1" className="inp" type="datetime-local" /></div>
          <div><label htmlFor="f2">관찰 종료</label><input id="f2" className="inp" type="datetime-local" /></div>
          <div><label htmlFor="f3">Technique</label><select id="f3" className="selc"><option>전체</option><option>T1190</option><option>T1110</option></select></div>
          <div><label htmlFor="f4">판정</label><select id="f4" className="selc"><option>전체</option><option>성공 · 탐지</option><option>성공 · 놓침</option><option>실패 · 탐지</option><option>실패 · 안 보임</option><option>판정 불가</option></select></div>
          <div><label htmlFor="f5">rid · Operation 검색</label><input id="f5" className="inp" type="search" placeholder="rid 또는 Operation ID" /></div>
        </div>
        <div className="note inline">시간·Technique·판정 필터는 선택한 측정 안에서 적용됩니다. 시간은 공격 시각 기준 KST 입니다.</div>
      </div>

      <div className="tabs" role="tablist" aria-label="보기">
        {tabBtn('list', '시도 목록')}
        {tabBtn('network', 'Network')}
        {tabBtn('flow', 'Attack Flow')}
      </div>

      <div className="cards2">
        <div className="cc"><b>공격 시도 {attackN}건</b><p>대조 요청 {controlN} 별도 · 기대 요청 {((runAfter?.expected_attempts ?? 0) + (runAfter?.expected_controls ?? 0))}건 · 기록 검증 {runAfter?.integrity_status === 'VALID' ? '일치' : (runAfter?.integrity_status ?? NO_RECORD)} · 마지막 측정 {kst(runAfter?.ended_at)}</p></div>
        <div className="cc"><b>탐지된 시도 <span className="t-det">{detected}건</span></b><p>연결 경보 {alerts.length}건 · 앱 로그 · 네트워크 · 백엔드 상관 · 관찰 30초 기준</p><Link className="link" to="/detection">탐지 분석에서 보기</Link></div>
      </div>

      {tab === 'list' && (
        <div className="panel">
          <div className="tw">
            <table>
              <thead><tr><th>관찰 시각</th><th>Operation / 시도</th><th>공격 내용</th><th>Technique</th><th>공격 결과</th><th>탐지 결과</th><th>판정</th><th></th></tr></thead>
              <tbody>
                {rows.map((a) => {
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
                      <td><Link className="selb" to={`/attempts/${a.attempt_id}`}>선택</Link></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <div className="pag"><span>1–{rows.length} / {attackN + controlN}</span><div className="pagbtns"><button type="button" className="sb">이전</button><button type="button" className="sb">다음</button></div></div>
        </div>
      )}

      {tab === 'network' && (
        <div className="panel">
          <div className="subhead">요청 경로</div>
          <div className="subsub">공격 요청이 지나가는 구성과 각 지점을 보는 관제</div>
          <div className="topo" role="img" aria-label={`Caldera agent에서 Target Web으로 공격 시도 ${attackN}건과 대조 요청 ${controlN}건, Target Web에서 Mock IMDS로 SSRF 요청`}>
            <div className="node"><b>Caldera agent</b>호스트 sandcat · 127.0.0.1:8080<br />공격 시도 {attackN} · 대조 요청 {controlN}</div>
            <div className="arr"></div>
            <div className="node target-node">
              <b>Target Web</b>
              <span className="attack-endpoint">SQLi · /api/products/search</span>
              <span className="attack-endpoint">Path Traversal · /api/files/download</span>
              <span className="attack-endpoint">Brute Force · /api/auth/login</span>
              <span className="attack-endpoint">SSRF · 취약 URL 요청 엔드포인트</span>
            </div>
            <div className="arr ssrf-arr"><span>SSRF 경로</span></div>
            <div className="node"><b>Mock IMDS</b>내부 링크-로컬 서비스 · 169.254.169.254<br />SSRF 내부 서비스 도달 {imds.data ? `${imds.data.request_count}건` : NO_RECORD}</div>
          </div>
          <div className="sens">
            <div className="node"><b>앱 로그 관제 · Wazuh</b>Target Web 앱 로그 · 연결 경보 {appAlerts}건</div>
            <div className="node"><b>네트워크 관제 · Suricata</b>app0 · atk0 · imds0 캡처 · 연결 경보 {nidsAlerts}건</div>
            <div className="node"><b>백엔드 상관</b>로그인 시퀀스 · 탐지 {backendDetected}건</div>
          </div>
        </div>
      )}

      {tab === 'flow' && (
        <div className="panel">
          <div className="subhead">측정 {runAfter?.run_id.slice(0, 8) ?? NO_RECORD} · 공격 시도 {attackN}건</div>
          <div className="subsub">같은 시간축에 Caldera 실행 → 정답지 기록 → 관제 알림을 놓습니다</div>
          <div className="lane"><span>Caldera 실행</span><div className="tr">{rows.map((a) => <EventMarker key={`attack-${a.attempt_id}`} leftPct={pct(a.attack_time)} color="#b899eb" />)}</div></div>
          <div className="lane"><span>정답지 기록</span><div className="tr">{rows.map((a) => <EventMarker key={`verdict-${a.attempt_id}`} leftPct={pct(a.decided_at)} color="#a0bce8" />)}</div></div>
          <div className="lane"><span>앱 로그 관제</span><div className="tr">{appAlertRows.map((l, i) => <EventMarker key={`app-${l.attempt_id}-${l.rule_id}-${i}`} leftPct={pct(l.alert_time)} color="#71dd8c" />)}</div></div>
          <div className="lane"><span>네트워크 관제</span><div className="tr">{nidsAlertRows.map((l, i) => <EventMarker key={`nids-${l.attempt_id}-${l.rule_id}-${i}`} leftPct={pct(l.alert_time)} color="#71dd8c" />)}</div></div>
        </div>
      )}
    </Layout>
  );
}
