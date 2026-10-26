import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { api, KNOWN_RUN_IDS } from '../api';
import type { Meta, RunDetail, RunSummary, DisplayNames } from '../api/types';

interface DashboardData {
  meta: Meta | null;
  runs: RunSummary[];
  runAfter: RunDetail | null;
  runBefore: RunDetail | null;
  displayNames: DisplayNames;
  runIds: typeof KNOWN_RUN_IDS;
  loading: boolean;
  error: string | null;
  displayName: (label: string) => string;
}

const Ctx = createContext<DashboardData | null>(null);

export function DashboardProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<Omit<DashboardData, 'displayName'>>({
    meta: null, runs: [], runAfter: null, runBefore: null, displayNames: {},
    runIds: KNOWN_RUN_IDS, loading: true, error: null,
  });

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const meta = await api.getMeta();
        const runs = await api.getRuns();
        // 운영에서는 label 로 run 을 식별. 개발 mock 은 KNOWN_RUN_IDS 보유.
        const byLabel = (label: string) => runs.find((r) => r.label === label)?.run_id ?? '';
        const latestValidAttackId = runs
          .filter((r) =>
            r.kind === 'ATTACK' &&
            r.status === 'CLOSED' &&
            r.integrity_status === 'VALID'
          )
          .sort((a, b) => Date.parse(b.ended_at) - Date.parse(a.ended_at))[0]?.run_id ?? '';
        const afterId = KNOWN_RUN_IDS.after || latestValidAttackId;
        const beforeId = KNOWN_RUN_IDS.before || byLabel('S4-STACK-6-BASELINE');
        const benignWebId = KNOWN_RUN_IDS.benignWeb || byLabel('S5-SQLI-AFTER-BENIGN-WEB');
        const latestBenignLoginId = runs
          .filter((r) =>
            r.kind === 'BENIGN' &&
            r.status === 'CLOSED' &&
            r.label.startsWith('S4-5-BENIGN-LOGIN')
          )
          .sort((a, b) => Date.parse(b.ended_at) - Date.parse(a.ended_at))[0]?.run_id ?? '';
        const benignLoginId = KNOWN_RUN_IDS.benignLogin || latestBenignLoginId;
        const [runAfter, runBefore, displayNames] = await Promise.all([
          afterId ? api.getRun(afterId) : Promise.resolve(null),
          beforeId ? api.getRun(beforeId) : Promise.resolve(null),
          api.getDisplayNames().catch(() => ({})),
        ]);
        if (!alive) return;
        setState({
          meta, runs, runAfter, runBefore, displayNames,
          runIds: { after: afterId, before: beforeId, benignWeb: benignWebId, benignLogin: benignLoginId },
          loading: false, error: null,
        });
      } catch (err) {
        if (!alive) return;
        setState((s) => ({ ...s, loading: false, error: err instanceof Error ? err.message : String(err) }));
      }
    })();
    return () => { alive = false; };
  }, []);

  const value: DashboardData = {
    ...state,
    displayName: (label: string) => state.displayNames[label] ?? label,
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useDashboard(): DashboardData {
  const v = useContext(Ctx);
  if (!v) throw new Error('useDashboard must be used within DashboardProvider');
  return v;
}
