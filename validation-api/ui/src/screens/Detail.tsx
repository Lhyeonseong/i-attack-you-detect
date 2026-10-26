import { Link, useParams } from 'react-router-dom';
import { Layout } from '../components/Layout';
import { Badge, BadgeText } from '../components/Badge';
import { useDashboard } from '../components/DashboardContext';
import { useAsync } from '../lib/useAsync';
import { api } from '../api';
import { byMetricScope } from '../lib/select';
import { kst } from '../lib/format';
import { msToSec, NO_RECORD } from '../lib/ratio';
import { scenarioMeta, gtBadge, detectionBadge, verdictBadge } from '../lib/labels';
import type { SnapshotRow } from '../api/types';
import '../styles/detail.css';

const SOURCE_LABEL: Record<string, string> = {
  app_rule: '앱 로그 관제 (Wazuh)',
  nids: '네트워크 관제 (Suricata)',
  backend: '백엔드 상관',
  none: '—',
};
const CONTROL_LABEL: Record<string, string> = {
  app: '앱 로그 (Wazuh)',
  nids: '네트워크 (Suricata)',
  backend: '백엔드 상관',
};

export default function Detail() {
  const { id } = useParams();
  const { runIds, runAfter, displayName } = useDashboard();
  const attempts = useAsync(() => api.getAttempts(runIds.after), [runIds.after]);
  const links = useAsync(() => api.getAlertLinks(runIds.after), [runIds.after]);
  const snapAfter = useAsync(() => api.getSnapshot('', runIds.after), [runIds.after]);
  const snapBefore = useAsync(() => api.getSnapshot('', runIds.before), [runIds.before]);

  const sqliAfter = byMetricScope<SnapshotRow>(snapAfter.data, 'M02', 'SQLI');
  const sqliBefore = byMetricScope<SnapshotRow>(snapBefore.data, 'M02', 'SQLI');
  const sqliMissedAfter = sqliAfter ? sqliAfter.n - (sqliAfter.x ?? 0) : null;
  const sqliMissedBefore = sqliBefore ? sqliBefore.n - (sqliBefore.x ?? 0) : null;

  const a = (attempts.data ?? []).find((x) => x.attempt_id === id) ?? (attempts.data ?? [])[0];
  const alerts = (links.data ?? []).filter((l) => a && l.attempt_id === a.attempt_id);

  if (!a) {
    return (
      <Layout screenId="detail" title="공격 검증 상세" topNote={`${displayName(runAfter?.label ?? '')} · 확정 결과`} provenance={false}>
        <Link className="back" to="/attacks">← 공격 결과 목록</Link>
        <p className="t-muted">해당 시도를 찾을 수 없습니다.</p>
      </Layout>
    );
  }

  const m = scenarioMeta(a);
  const firstAlert = alerts[0]?.alert_time ?? null;
  const isSqli = a.scenario === 'SQLI';

  return (
    <Layout screenId="detail" title="공격 검증 상세" topNote={`${displayName(runAfter?.label ?? '')} · 확정 결과`}>
      <Link className="back" to="/attacks">← 공격 결과 목록</Link>
      <div className="heading">
        <div className="eyebrow">시도 단위 검증</div>
        <h1>공격 검증 상세</h1>
        <p>Target의 정답지 결과와 관제의 탐지 증거를 분리해 확인합니다.</p>
      </div>

      <div className="banner">
        <div><div className="eyebrow">시도 ID</div><h2>rid {a.rid}</h2><p>{a.ability_id} · {kst(a.attack_time)}</p></div>
        <div className="pair">
          <div><small>공격 결과</small><Badge model={gtBadge(a)} /></div>
          <div><small>탐지 결과</small><Badge model={detectionBadge(a)} /></div>
          <div><small>판정</small><Badge model={verdictBadge(a)} /></div>
        </div>
      </div>

      <div className="two">
        <section className="panel">
          <div className="ph"><div><div className="ctx">공격 요청</div><h2>실행 · 정답지 정보</h2></div></div>
          <dl className="dl">
            <div><dt>Operation ID</dt><dd>{a.op_id}</dd></div>
            <div><dt>Ability</dt><dd>{a.ability_id}</dd></div>
            <div><dt>Technique</dt><dd>{a.technique_id}</dd></div>
            <div><dt>정답지 결과</dt><dd>{a.gt_outcome === 'SUCCEEDED' ? '성공' : '실패'} · {m.name}</dd></div>
            <div><dt>공격자 판정 (Caldera)</dt><dd>{a.attacker_match ? <BadgeText cls="b-ok">성공 · 정답지와 일치</BadgeText> : <BadgeText cls="b-dg">불일치</BadgeText>}</dd></div>
          </dl>
        </section>
        <section className="panel">
          <div className="ph"><div><div className="ctx">관제 결과</div><h2>탐지 판정</h2></div></div>
          <dl className="dl">
            <div><dt>탐지 주체</dt><dd>{SOURCE_LABEL[a.correlation_source] ?? NO_RECORD}</dd></div>
            <div><dt>연결 근거</dt><dd>{alerts[0] ? `${alerts[0].match_path} 일치 · 신뢰도 ${alerts[0].confidence ?? NO_RECORD}` : NO_RECORD}</dd></div>
            <div><dt>공격 시각</dt><dd>{kst(a.attack_time)}</dd></div>
            <div><dt>첫 알림 시각</dt><dd>{kst(firstAlert)}</dd></div>
            <div><dt>탐지 시간</dt><dd>{a.mttd_ms != null ? `${msToSec(a.mttd_ms)} · 관찰 30초 이내` : NO_RECORD}</dd></div>
          </dl>
          <div className="inline">관찰 30초 안에 연결된 알림이 있어 탐지로 확정했습니다. 30초 이후 도착한 알림은 늦은 탐지로 따로 기록합니다.</div>
        </section>
      </div>

      <section className="panel">
        <div className="ph"><div><div className="ctx">관제별 증거</div><h2>연결된 알림</h2></div><Link className="link" to="/detection">탐지 분석에서 보기 →</Link></div>
        <div className="tw">
          <table>
            <thead><tr><th>관제</th><th>룰 · 수준</th><th>알림 시각</th><th>연결 근거</th><th>결과</th></tr></thead>
            <tbody>
              {alerts.length > 0 ? alerts.map((l, i) => (
                <tr key={i}>
                  <td><span className="pc">{CONTROL_LABEL[l.control] ?? l.control}</span></td>
                  <td>{l.rule_id}</td>
                  <td>{kst(l.alert_time)}</td>
                  <td>{l.match_path} · {l.confidence ?? NO_RECORD}</td>
                  <td><BadgeText cls="b-ok">탐지</BadgeText></td>
                </tr>
              )) : (
                <tr><td colSpan={5} className="t-muted">연결된 알림이 없습니다.</td></tr>
              )}
              {isSqli && (
                <tr>
                  <td><span className="pc">네트워크 (Suricata)</span></td><td>—</td><td>—</td><td>—</td>
                  <td><BadgeText cls="b-dg">알림 없음 · Gap #7</BadgeText></td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <div className="inline">원본 로그와 페이로드는 표시하지 않습니다. 룰 번호·시각·연결 근거만 확인합니다.</div>
      </section>

      {isSqli && (
        <div className="reval">
          <div><b>개선 전 측정에서 놓쳤던 공격 유형입니다</b>SQL 인젝션 놓침 {sqliMissedBefore ?? NO_RECORD} → {sqliMissedAfter ?? NO_RECORD} · 룰 100211 추가 후 재검증</div>
          <Link className="pb" to="/revalidate">재검증 결과 보기 →</Link>
        </div>
      )}
    </Layout>
  );
}
