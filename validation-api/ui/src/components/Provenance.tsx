import { useDashboard } from './DashboardContext';
import { short8, short12, kst } from '../lib/format';
import type { RunDetail } from '../api/types';

function prov(run: RunDetail | null, item: string): string | undefined {
  return run?.provenance.find((p) => p.item === item)?.value;
}

/**
 * R-g 출처 줄. 측정 라벨 · 측정 ID 앞8자 · commit · rules_digest 앞12자 ·
 * engine_version · definition_version · snapshot_rule_version · 캡처시각(KST).
 * 용어(R-i): "Run" 대신 "측정".
 */
export function Provenance() {
  const { runAfter } = useDashboard();
  if (!runAfter) return null;
  const items: Array<[string, string]> = [
    ['측정', runAfter.label],
    ['측정 ID', short8(runAfter.run_id)],
    ['commit', runAfter.git_commit],
    ['rules_digest', short12(prov(runAfter, 'rules_digest'))],
    ['engine', prov(runAfter, 'engine_version') ?? '해당 없음'],
    ['def', prov(runAfter, 'definition_version') ?? (runAfter.definition_versions[0] ?? '해당 없음')],
    ['snapshot_rule', prov(runAfter, 'snapshot_rule_version') ?? '해당 없음'],
    ['캡처(KST)', kst(prov(runAfter, 'captured_at') ?? runAfter.ended_at)],
  ];
  return (
    <p className="rg-foot" data-testid="provenance">
      {items.map(([k, v], i) => (
        <span className="rg-item" key={k}>
          {i > 0 ? ' · ' : ''}{k} {v}
        </span>
      ))}
    </p>
  );
}
