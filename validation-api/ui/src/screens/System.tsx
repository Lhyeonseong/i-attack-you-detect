import { Link } from 'react-router-dom';
import { Layout } from '../components/Layout';
import { useDashboard } from '../components/DashboardContext';
import { useAsync } from '../lib/useAsync';
import { api } from '../api';
import { byScope } from '../lib/select';
import { kst, short8 } from '../lib/format';
import { NO_RECORD } from '../lib/ratio';
import type { AttackerRow, RateRow, SnapshotRow } from '../api/types';
import '../styles/system.css';

const services = [
  { name: '측정 DB · PostgreSQL', pill: 'up', pillText: '연결됨', desc: 'validation 스키마 · 읽기 전용 계정 · 실시간 확인', sub: '버전 16.15' },
  { name: '공격 실행 · Caldera', pill: 'uk', pillText: '측정 당시', desc: 'Operation 실행 · agent 1개', sub: '버전 5.2.0' },
  { name: '대상 · Target Web', pill: 'uk', pillText: '측정 당시', desc: '정답지 기록 · 취약 엔드포인트 4개', sub: 'Spring Boot 4.1.1' },
  { name: '앱 로그 관제 · Wazuh', pill: 'uk', pillText: '측정 당시', desc: 'manager · indexer · agent 004', sub: '버전 4.14.9' },
  { name: '네트워크 관제 · Suricata', pill: 'uk', pillText: '측정 당시', desc: 'app0 · atk0 · imds0 인터페이스', sub: '버전 8.0.7' },
  { name: '메타데이터 서비스 · Mock IMDS', pill: 'uk', pillText: '측정 당시', desc: 'SSRF 대상 · 169.254.169.254', sub: '내부 전용 네트워크' },
];

export default function System() {
  const { runIds, runAfter } = useDashboard();
  const snap = useAsync(() => api.getSnapshot('', runIds.after), [runIds.after]);
  const snapBefore = useAsync(() => api.getSnapshot('', runIds.before), [runIds.before]);
  const rates = useAsync(() => api.getRates(runIds.after), [runIds.after]);
  const h2 = useAsync(() => api.getH2(runIds.after), [runIds.after]);
  const attacker = useAsync(() => api.getAttacker(runIds.after), [runIds.after]);

  const snapLen = snap.data ? `${snap.data.length}행` : NO_RECORD;
  const def = snap.data?.[0]?.definition_version ?? '';
  const atk = byScope<AttackerRow>(attacker.data, 'ALL');
  const rid = h2.data?.rid_header_x;
  const m02After = (snap.data ?? []).find(
    (r: SnapshotRow) => r.metric_id === 'M02' && r.scope_kind === 'ALL'
  );
  const m02Before = (snapBefore.data ?? []).find(
    (r: SnapshotRow) => r.metric_id === 'M02' && r.scope_kind === 'ALL'
  );
  const beforeMissed = m02Before ? m02Before.n - (m02Before.x ?? 0) : null;
  const afterMissed = m02After ? m02After.n - (m02After.x ?? 0) : null;

  const attackScenarioRows = (rates.data ?? []).filter(
    (r: RateRow) => r.metric_id === 'M01' && r.scope_kind === 'SCENARIO'
  );
  const successfulScenarioN = attackScenarioRows.filter(
    (r: RateRow) => r.n > 0 && r.x === r.n
  ).length;
  const scenarioN = attackScenarioRows.length;

  return (
    <Layout screenId="system" title="시스템 상태" topNote="읽기 전용 연결">
      <div className="heading">
        <div className="eyebrow">연결 및 수집</div>
        <h1>시스템 상태</h1>
        <p>측정 DB 연결 상태, 마지막 측정의 구성과 결과 수집 상태를 보여줍니다.</p>
      </div>
      <div className="note">실시간으로 확인하는 것은 측정 DB 연결뿐입니다. Caldera · Target Web · Wazuh · Suricata · Mock IMDS는 마지막 측정 당시 구성이며, 이 화면이 현재 정상 상태를 보증하지 않습니다.</div>

      <section className="panel">
        <div className="ph"><div><div className="ctx">검증 구성요소</div><h2>서비스 연결</h2></div><span className="pm">측정 {short8(runAfter?.run_id)} 출처 기록</span></div>
        <div className="pg">
          {services.map((s) => (
            <div className="pc" key={s.name}>
              <div className="phd"><strong>{s.name}</strong><span className={`pill ${s.pill}`}>{s.pillText}</span></div>
              <p>{s.desc}</p><small>{s.sub}</small>
            </div>
          ))}
        </div>
      </section>

      <div className="two">
        <section className="panel">
          <div className="ph"><div><div className="ctx">결과 수집</div><h2>마지막 결과 수집</h2></div></div>
          <dl className="dl">
            <div><dt>측정 상태</dt><dd><span className="pill up">확정</span></dd></div>
            <div><dt>기록 검증</dt><dd><span className="pill up">{runAfter?.integrity_status === 'VALID' ? '일치' : (runAfter?.integrity_status ?? NO_RECORD)}</span></dd></div>
            <div><dt>마지막 완료</dt><dd>{kst(runAfter?.ended_at)}</dd></div>
            <div><dt>수집 방식</dt><dd>측정 종료 시 일괄 적재</dd></div>
            <div><dt>요청 기록</dt><dd>기대 160 · 적재 160 · 앱 로그 관측 160</dd></div>
            <div><dt>확정 결과 (스냅샷)</dt><dd>{snapLen} · 정의 {def || NO_RECORD}</dd></div>
            <div><dt>측정 ID</dt><dd>{runAfter?.label ?? NO_RECORD} · {short8(runAfter?.run_id)}</dd></div>
          </dl>
        </section>
        <section className="panel">
          <div className="ph"><div><div className="ctx">측정 신뢰</div><h2>측정 정확도</h2></div><span className="pill up">정상</span></div>
          <dl className="dl">
            <div><dt>공격자 판정 = 정답지</dt><dd>{scenarioN ? `${successfulScenarioN} / ${scenarioN} 유형` : NO_RECORD} · {atk ? `${atk.n}건 중 ${atk.x}건` : NO_RECORD}</dd></div>
            <div><dt>성공을 부풀린 경우</dt><dd>{atk ? `${atk.overestimate}건` : NO_RECORD}</dd></div>
            <div><dt>연결 근거 rid · 헤더</dt><dd>{rid != null ? rid : NO_RECORD} / {h2.data?.n ?? NO_RECORD} · 목표 90% 이상</dd></div>
            <div><dt>판정 불가</dt><dd>{atk ? `${atk.uncertain}건` : NO_RECORD}</dd></div>
            <div><dt>대조 요청 성공 오판 (SSRF)</dt><dd><span className="pill dn">별도 공백</span></dd></div>
          </dl>
        </section>
      </div>

      <section className="panel">
        <div className="ph"><div><div className="ctx">구성 변경 · 개선 전 측정 (10/21) → 개선 후 측정 (10/22)</div><h2>탐지 룰 구성 변경</h2></div><Link className="link" to="/revalidate">개선 효과 보기 →</Link></div>
        <dl className="dl">
          <div><dt>변경 내용</dt><dd>SQL 인젝션 탐지 룰 100211 추가 (기존 100210 유지)</dd></div>
          <div><dt>커밋</dt><dd>{short8(runAfter?.git_commit)}</dd></div>
          <div><dt>탐지 룰 지문</dt><dd>Wazuh 룰만 변경 · Suricata · 앱 · Caldera 동일</dd></div>
          <div><dt>판정 엔진</dt><dd>s3-v1 → s4-v1 · 측정 후 발견 · SQL 인젝션 결과 영향 없음</dd></div>
          <div><dt>결과</dt><dd><span className="pill up">놓친 공격 {beforeMissed ?? NO_RECORD} → {afterMissed ?? NO_RECORD}</span></dd></div>
        </dl>
      </section>
    </Layout>
  );
}
